from __future__ import annotations

import unittest

from mstar_analyzer.entropy import classify_region, shannon_entropy


class ShannonEntropyTests(unittest.TestCase):

    def test_empty_data_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_repeated_byte_is_zero_entropy(self):
        self.assertEqual(shannon_entropy(b"\x00" * 1000), 0.0)

    def test_uniform_byte_values_are_near_maximum(self):
        data = bytes(range(256)) * 10
        self.assertGreater(shannon_entropy(data), 7.9)


class ClassifyRegionTests(unittest.TestCase):

    def test_thresholds(self):
        self.assertEqual(classify_region(0.5), "empty/padding")
        self.assertEqual(classify_region(2.0), "structured/text/tables")
        self.assertEqual(classify_region(5.0), "code")
        self.assertEqual(classify_region(7.5), "compressed/encrypted")


if __name__ == "__main__":
    unittest.main()
