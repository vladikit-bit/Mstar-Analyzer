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

from mstar_analyzer.firmware_map import MapEntry, _dedupe_lzma_findings
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


if __name__ == "__main__":
    unittest.main()
