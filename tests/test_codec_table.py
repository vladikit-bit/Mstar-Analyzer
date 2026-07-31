"""
Регресійні тести для analyzers/codec_table.py.

Реальний рядок нижче (REAL_CODEC_TABLE_STRING) — точна копія рядка з
firmware-звіту користувача (0x0028D000 у report.txt): суцільна
конкатенація FourCC-кодів без роздільників.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.analyzers.codec_table import analyze_codec_table
from mstar_analyzer.strings import StringFinding

REAL_CODEC_TABLE_STRING = "DIVXdivxDX50H263H264DIV3MJPGmjpgXVIDxvidFMP4D"


def _finding(text: str, offset: int = 0) -> StringFinding:
    return StringFinding(offset=offset, text=text)


class RealFirmwareStringTests(unittest.TestCase):

    def test_real_string_decodes_eleven_codecs(self):
        profile = analyze_codec_table([_finding(REAL_CODEC_TABLE_STRING, offset=0x0028D000)])
        self.assertIsNotNone(profile)
        (table,) = profile.tables
        self.assertEqual(table.offset, 0x0028D000)
        self.assertEqual(
            table.codecs,
            ["DIVX", "divx", "DX50", "H263", "H264", "DIV3", "MJPG", "mjpg", "XVID", "xvid", "FMP4"],
        )

    def test_real_string_trailing_partial_byte_reported_not_dropped_silently(self):
        profile = analyze_codec_table([_finding(REAL_CODEC_TABLE_STRING)])
        (table,) = profile.tables
        self.assertEqual(table.leftover, "D")

    def test_case_variants_get_the_same_label(self):
        profile = analyze_codec_table([_finding(REAL_CODEC_TABLE_STRING)])
        (table,) = profile.tables
        self.assertEqual(table.label_for("DIVX"), table.label_for("divx"))


class PrecisionGuardTests(unittest.TestCase):
    """Не кожен 4-байтний блок або випадкова згадка кодека — це 'таблиця'."""

    def test_random_gibberish_does_not_trigger(self):
        profile = analyze_codec_table([_finding("qwertyuiopasdfghjklzxcvbnmqwerty")])
        self.assertIsNone(profile)

    def test_single_incidental_mention_in_prose_does_not_trigger(self):
        profile = analyze_codec_table([_finding("this stream uses H264 encoding for video")])
        self.assertIsNone(profile)

    def test_below_minimum_recognized_count_does_not_trigger(self):
        # Лише 2 розпізнані коди (< MIN_RECOGNIZED=3) серед іншого сміття.
        profile = analyze_codec_table([_finding("H264MJPGqwerasdfzxcv")])
        self.assertIsNone(profile)

    def test_too_short_string_does_not_trigger(self):
        profile = analyze_codec_table([_finding("H264")])
        self.assertIsNone(profile)

    def test_empty_strings_list_returns_none(self):
        self.assertIsNone(analyze_codec_table([]))


class MultipleTablesTests(unittest.TestCase):

    def test_two_separate_tables_in_different_strings_both_captured(self):
        strings = [
            _finding("DIVXXVIDH264MJPG", offset=0x100),
            _finding("H263DIV3FMP4DX50", offset=0x200),
        ]
        profile = analyze_codec_table(strings)
        self.assertEqual(len(profile.tables), 2)
        self.assertIn("H264", profile.all_codecs)
        self.assertIn("DX50", profile.all_codecs)


if __name__ == "__main__":
    unittest.main()
