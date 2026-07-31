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


if __name__ == "__main__":
    unittest.main()
