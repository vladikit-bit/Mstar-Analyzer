import gzip
import unittest

from mstar_analyzer.extractors import GZipExtractor


class TestGZipExtractor(unittest.TestCase):

    def test_gzip_valid(self):
        payload = b"Hello World!" * 100
        blob = gzip.compress(payload)

        r = GZipExtractor().extract(blob, 0)

        self.assertEqual(r.method, "gzip")
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)
        self.assertEqual(r.consumed, len(blob))

    def test_gzip_empty(self):
        blob = gzip.compress(b"")

        r = GZipExtractor().extract(blob, 0)

        self.assertTrue(r.success)
        self.assertEqual(r.data, b"")
        self.assertEqual(r.output_size, 0)

    def test_gzip_truncated(self):
        blob = gzip.compress(b"A" * 500)
        blob = blob[:-5]

        r = GZipExtractor().extract(blob, 0)

        self.assertFalse(r.success)

    def test_gzip_random(self):
        blob = b"\x1f\x8b\x08" + b"\xff" * 100

        r = GZipExtractor().extract(blob, 0)

        self.assertFalse(r.success)
        self.assertIsNone(r.data)

    def test_gzip_max_output(self):
        payload = b"A" * 50000
        blob = gzip.compress(payload)

        r = GZipExtractor().extract(
            blob,
            0,
            max_output=100,
        )

        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)
        self.assertIn("output exceeded", r.error)

    def test_gzip_offset(self):
        payload = b"DATA" * 100
        blob = gzip.compress(payload)

        file = b"\x00" * 123 + blob

        r = GZipExtractor().extract(file, 123)

        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)

    def test_gzip_consumed(self):
        payload = b"ABC" * 100
        blob = gzip.compress(payload)

        file = blob + b"TRAILER"

        r = GZipExtractor().extract(file, 0)

        self.assertTrue(r.success)
        self.assertEqual(r.consumed, len(blob))

    def test_gzip_multimember(self):
        blob = gzip.compress(b"A")
        blob += gzip.compress(b"B")

        r = GZipExtractor().extract(blob, 0)

        self.assertTrue(r.success)

        print("\nmultimember data:", r.data)
        print("multimember consumed:", r.consumed)

    def test_gzip_error_contains_message(self):
        blob = b"\x1f\x8b\x08" + b"\xff" * 100

        r = GZipExtractor().extract(blob, 0)

        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)


if __name__ == "__main__":
    unittest.main()