"""
Регресійні тести для CLI (mstar_analyzer/analyze.py).

--output/--json приймають ШЛЯХ, а не лише ім'я файлу (напр.
"reports/flash.txt") — до виправлення відкриття файлу в неіснуючій
директорії падало FileNotFoundError ще до першого рядка звіту.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from mstar_analyzer.analyze import main


def _run_cli(argv: list[str]) -> int:
    old_argv = sys.argv
    sys.argv = ["mstar-analyzer", *argv]
    try:
        return main()
    finally:
        sys.argv = old_argv


class ReportsDirAutoCreateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.firmware = Path(self.tmp.name) / "flash.bin"
        # Розмір не критичний для цього тесту (перевіряємо лише
        # створення директорій/файлів, не вміст аналізу) — але даємо
        # трохи більше нуля байтів, щоб пайплайн не вважав файл порожнім.
        self.firmware.write_bytes(b"\x00" * 600)

    def test_output_creates_nested_reports_dir(self):
        output_path = Path(self.tmp.name) / "reports" / "nested" / "flash.txt"
        self.assertFalse(output_path.parent.exists())

        rc = _run_cli([str(self.firmware), "-o", str(output_path)])

        self.assertEqual(rc, 0)
        self.assertTrue(output_path.exists())
        self.assertIn("MStar Firmware Analyzer", output_path.read_text(encoding="utf-8"))

    def test_json_creates_nested_reports_dir(self):
        json_path = Path(self.tmp.name) / "reports" / "flash.json"
        self.assertFalse(json_path.parent.exists())

        rc = _run_cli([str(self.firmware), "-j", str(json_path)])

        self.assertEqual(rc, 0)
        self.assertTrue(json_path.exists())

    def test_output_and_json_together_in_different_new_dirs(self):
        output_path = Path(self.tmp.name) / "reports" / "text" / "flash.txt"
        json_path = Path(self.tmp.name) / "reports" / "data" / "flash.json"

        rc = _run_cli([str(self.firmware), "-o", str(output_path), "-j", str(json_path)])

        self.assertEqual(rc, 0)
        self.assertTrue(output_path.exists())
        self.assertTrue(json_path.exists())

    def test_existing_output_dir_still_works(self):
        # Регресія: авто-створення не повинно ламатись/скаржитись, якщо
        # директорія вже існує.
        output_path = Path(self.tmp.name) / "flash.txt"

        rc = _run_cli([str(self.firmware), "-o", str(output_path)])

        self.assertEqual(rc, 0)
        self.assertTrue(output_path.exists())


class CompareWithTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.firmware = Path(self.tmp.name) / "flash.bin"
        self.firmware.write_bytes(
            b"\x00" * 50
            + b"MDrv_GE_SetBlt\x00Wait MIU0...\x00K5AP_BD_MST297B_D01A\x00"
            + b"\x00" * 500
        )

    def test_nonexistent_compare_file_errors_before_running(self):
        # parser.error() кидає SystemExit(2), а не повертає значення зі
        # звичайного return — на відміну від решти тестів тут.
        with self.assertRaises(SystemExit) as ctx:
            _run_cli([str(self.firmware), "--compare-with", str(Path(self.tmp.name) / "missing.json")])
        self.assertEqual(ctx.exception.code, 2)

    def test_compare_with_valid_prior_report_succeeds(self):
        report_path = Path(self.tmp.name) / "prior.json"
        rc1 = _run_cli([str(self.firmware), "-j", str(report_path)])
        self.assertEqual(rc1, 0)
        self.assertTrue(report_path.exists())

        rc2 = _run_cli([str(self.firmware), "--compare-with", str(report_path)])
        self.assertEqual(rc2, 0)

    def test_compare_with_report_missing_fingerprint_key_does_not_crash(self):
        old_report = Path(self.tmp.name) / "old.json"
        old_report.write_text('{"schema_version": 1}', encoding="utf-8")

        rc = _run_cli([str(self.firmware), "--compare-with", str(old_report)])
        self.assertEqual(rc, 0)  # деградує без падіння, лише пропускає порівняння

    def test_compare_with_corrupted_json_does_not_crash(self):
        broken = Path(self.tmp.name) / "broken.json"
        broken.write_text("not valid json{{{", encoding="utf-8")

        rc = _run_cli([str(self.firmware), "--compare-with", str(broken)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
