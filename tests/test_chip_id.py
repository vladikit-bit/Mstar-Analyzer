"""
Регресійні тести для analyzers/chip_id.py.

REAL_BOARD_STRING нижче — точна копія рядка з firmware-звіту
користувача (MBoot "Board" variable): "K5AP_BD_MST297B_D01A".
"""

from __future__ import annotations

import unittest

from mstar_analyzer.analyzers.chip_id import analyze_chip_id
from mstar_analyzer.strings import StringFinding

REAL_BOARD_STRING = "K5AP_BD_MST297B_D01A"


def _finding(text: str, offset: int = 0) -> StringFinding:
    return StringFinding(offset=offset, text=text)


class RealEvidenceTests(unittest.TestCase):

    def test_real_board_string_extracts_confirmed_soc_model(self):
        result = analyze_chip_id([_finding(REAL_BOARD_STRING)])
        self.assertIsNotNone(result)
        self.assertEqual(result.confirmed_models, {"MST297B"})

    def test_real_board_string_captured_as_board_identifier(self):
        result = analyze_chip_id([_finding(REAL_BOARD_STRING)])
        self.assertIn(REAL_BOARD_STRING, result.board_identifiers)

    def test_mst_prefix_marked_confirmed(self):
        result = analyze_chip_id([_finding(REAL_BOARD_STRING)])
        (match,) = result.models
        self.assertEqual(match.prefix, "MST")
        self.assertTrue(match.confirmed)


class BoundaryCorrectnessTests(unittest.TestCase):
    """
    \\b не вважає '_' межею слова (underscore — \\w-символ), тому
    наївний \\b-варіант regex не матчив би НАВІТЬ реальний доказ вище
    (обидва краї "MST297B" у "..._MST297B_..." межують з underscore).
    Ці тести фіксують і позитивний, і негативний бік цього фіксу.
    """

    def test_prefix_embedded_in_longer_word_does_not_match(self):
        # "xMST297By" — MST297B тут частина довшого ідентифікатора, а не окремий токен.
        result = analyze_chip_id([_finding("xMST297By is not a chip model")])
        self.assertIsNone(result)

    def test_digits_without_prefix_do_not_match(self):
        result = analyze_chip_id([_finding("version 1234 build number")])
        self.assertIsNone(result)

    def test_prefix_without_digits_does_not_match(self):
        result = analyze_chip_id([_finding("MST protocol handler init")])
        self.assertIsNone(result)

    def test_underscore_separated_is_a_valid_boundary(self):
        result = analyze_chip_id([_finding("prefix_MST123_suffix")])
        self.assertIsNotNone(result)
        self.assertIn("MST123", result.confirmed_models)


class ConfidenceTieringTests(unittest.TestCase):

    def test_mst_is_confirmed_prefix(self):
        result = analyze_chip_id([_finding("chip MST123A detected")])
        (match,) = result.models
        self.assertTrue(match.confirmed)

    def test_mso_is_unconfirmed_prefix(self):
        result = analyze_chip_id([_finding("platform=MSO9686 rev A")])
        (match,) = result.models
        self.assertFalse(match.confirmed)
        self.assertEqual(result.unconfirmed_models, {"MSO9686"})
        self.assertEqual(result.confirmed_models, set())


class DedupAndAggregationTests(unittest.TestCase):

    def test_same_model_across_strings_not_duplicated(self):
        result = analyze_chip_id([
            _finding(REAL_BOARD_STRING),
            _finding("MST297B mentioned again elsewhere"),
        ])
        self.assertEqual(len(result.models), 1)

    def test_distinct_models_both_captured(self):
        result = analyze_chip_id([
            _finding(REAL_BOARD_STRING),
            _finding("secondary chip MST296 present"),
        ])
        self.assertEqual(result.confirmed_models, {"MST296", "MST297B"})

    def test_empty_strings_list_returns_none(self):
        self.assertIsNone(analyze_chip_id([]))

    def test_short_string_below_minimum_length_ignored(self):
        self.assertIsNone(analyze_chip_id([_finding("MST1")]))


if __name__ == "__main__":
    unittest.main()
