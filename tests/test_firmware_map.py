"""
Регресійні тести для firmware_map.py.

test_real_cluster_collapses_to_one_entry відтворює побайтово точно той
самий LZMA-заголовок, який на реальній прошивці Romsat TR-9110HD давав
кластер трьох "окремих" знахідок на 0x43028/0x43029/0x4302A — усі три
описують один і той самий заголовок, зсунутий на 1-2 байти. Дедуплікація
має звести їх до однієї.
"""

from __future__ import annotations

import struct
import unittest

from mstar_analyzer.firmware_map import FirmwareMap, MapEntry, _dedupe_lzma_findings, build_firmware_map
from mstar_analyzer.signatures import LzmaHeuristicScanner, ZlibHeuristicScanner


class DedupeLzmaFindingsTests(unittest.TestCase):

    def test_real_cluster_collapses_to_one_entry(self):
        # props=0x6C -> lc=0 lp=2 pb=2 (як у реальному дампі)
        props = 0x6C
        header = bytes([props]) + struct.pack("<I", 0x800000) + struct.pack("<Q", 0x2000000)

        # Кілька додаткових нульових байтів одразу за заголовком +
        # ненульовий "потік" далі — саме ця комбінація і відтворює
        # overlapping-кластер (заголовок частково "проходить" ще й на
        # +1, +2 байти зсуву).
        tail = b"\x00" * 4 + bytes((i % 251) + 1 for i in range(300))
        blob = b"\x00" * 500 + header + tail

        raw = LzmaHeuristicScanner().scan(blob)
        cluster = [f for f in raw if 495 <= f.offset <= 520]

        self.assertGreaterEqual(
            len(cluster), 2,
            "test setup did not reproduce the overlapping cluster",
        )

        entries = [
            MapEntry(offset=f.offset, kind=f.name, confidence=f.confidence, detail=f.detail)
            for f in cluster
        ]

        deduped = _dedupe_lzma_findings(entries)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].offset, 500)
        self.assertIn("overlapping match", deduped[0].detail)

    def test_distant_findings_are_not_merged(self):
        entries = [
            MapEntry(offset=0x1000, kind="lzma-alone-header", confidence="medium"),
            MapEntry(offset=0x5000, kind="lzma-alone-header", confidence="low"),
        ]
        deduped = _dedupe_lzma_findings(entries)
        self.assertEqual(len(deduped), 2)

    def test_best_confidence_wins_within_cluster(self):
        entries = [
            MapEntry(offset=0x100, kind="lzma-alone-header", confidence="low"),
            MapEntry(offset=0x105, kind="lzma-alone-header", confidence="medium"),
            MapEntry(offset=0x108, kind="lzma-alone-header", confidence="low"),
        ]
        deduped = _dedupe_lzma_findings(entries)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].confidence, "medium")

    def test_zlib_cluster_also_collapses(self):
        """
        ZlibHeuristicScanner (доданий разом із цим тестом) підключений
        до build_firmware_map() через той самий _dedupe_lzma_findings,
        що й LZMA — реальний zlib-потік одразу за заголовком сам є
        стисненими (тобто фактично випадковими) байтами, тому дає той
        самий клас overlapping-спрацювань.
        """
        import zlib

        blob = zlib.compress(b"payload " * 200, 9)
        raw = ZlibHeuristicScanner().scan(blob)

        self.assertGreaterEqual(
            len(raw), 1, "test setup did not produce any zlib findings",
        )

        entries = [
            MapEntry(offset=f.offset, kind=f.name, confidence=f.confidence, detail=f.detail)
            for f in raw
        ]
        deduped = _dedupe_lzma_findings(entries)

        # Незалежно від того, скільки overlapping-спрацювань дав сирий
        # скан, реальний потік один — і його заголовок починається з 0.
        self.assertEqual(deduped[0].offset, 0)
        self.assertEqual(deduped[0].kind, "zlib")


class AsTableExcludeKindsTests(unittest.TestCase):
    """
    as_table(exclude_kinds=...) — analyze.py::_run() використовує це,
    щоб не друкувати непідтверджені Stage 2 extraction-кандидати
    (zlib/gzip/xz/...) у ранній "Firmware map" таблиці: той самий
    candidate пізніше з'являється в секції "Findings" ВЖЕ з реальним
    extraction-статусом (confirmed/rejected), там ця інформація
    точніша. За замовчуванням (без аргументу) поведінка не змінюється.
    """

    def _sample_map(self) -> FirmwareMap:
        return FirmwareMap(
            size=1000,
            entropy_points=[],
            entries=[
                MapEntry(offset=10, kind="zlib", confidence="medium", detail="cinfo=7"),
                MapEntry(offset=20, kind="marker: MStar", confidence="high", detail=""),
                MapEntry(offset=30, kind="gzip", confidence="high", detail=""),
            ],
        )

    def test_default_call_is_unchanged(self):
        fw = self._sample_map()
        table = fw.as_table()
        self.assertIn("zlib", table)
        self.assertIn("gzip", table)
        self.assertIn("marker: MStar", table)

    def test_excluded_kinds_are_omitted(self):
        fw = self._sample_map()
        table = fw.as_table(exclude_kinds=frozenset({"zlib", "gzip"}))
        self.assertNotIn("zlib", table)
        self.assertNotIn("gzip", table)
        self.assertIn("marker: MStar", table)


class ZlibFullFileScanTests(unittest.TestCase):
    """
    ZlibHeuristicScanner раніше запускався лише в межах high-entropy
    регіонів (build_firmware_map()), як і LzmaHeuristicScanner. Після
    посилення (BTYPE/LEN~NLEN + bounded probe, signatures.py) він
    тепер сканує ВЕСЬ файл — ключова причина: малий стиснений блок,
    оточений низькоентропійним вмістом, розмиває СЕРЕДНЮ ентропію
    вікна, що його містить, нижче порогу навіть якщо сам блок один в
    один структурно валідний zlib-потік. Entropy-gating для такого
    випадку не просто зайвий — він і був джерелом пропущеної знахідки.
    """

    def test_small_zlib_block_in_low_entropy_padding_is_found(self):
        """
        Той самий сценарій, що емпірично показав проблему: невеликий
        (71-байтний) стиснений config-блок всередині стандартного
        вікна ентропійного сканування (1024 байти), оточений
        незапрограмованою flash-пам'яттю (0xFF). До цієї зміни
        відповідне вікно НЕ перетинало поріг ентропії (0.741 замість
        7.0) і ZlibHeuristicScanner до нього взагалі не діставався.
        """
        import zlib

        payload = b'{"version":"1.2.3","model":"TR-9110HD","config":{"a":1,"b":2}}' * 5
        compressed = zlib.compress(payload, 9)

        data = b"\xff" * 953 + compressed + b"\xff" * (1024 - 953 - len(compressed))

        fw = build_firmware_map(data)

        zlib_entries = [e for e in fw.entries if e.kind == "zlib"]
        self.assertEqual(len(zlib_entries), 1, fw.entries)
        self.assertEqual(zlib_entries[0].offset, 953)

    def test_zero_false_positives_on_structured_low_entropy_data(self):
        """
        Повнофайловий скан не повинен давати шуму на структурованих
        (не випадкових) низькоентропійних даних — ASCII-текст,
        padding, псевдо-код, рядкові таблиці. Перевірено окремо перед
        внесенням цієї зміни; тест фіксує це як регресію.
        """
        samples = [
            (b"the quick brown fox jumps over the lazy dog " * 50000)[:1_000_000],
            b"\xff" * 1_000_000,
            b"\x00" * 1_000_000,
            bytes((i % 64) for i in range(1_000_000)),
        ]

        for data in samples:
            with self.subTest(sample=data[:20]):
                fw = build_firmware_map(data)
                zlib_entries = [e for e in fw.entries if e.kind == "zlib"]
                self.assertEqual(zlib_entries, [])


if __name__ == "__main__":
    unittest.main()
