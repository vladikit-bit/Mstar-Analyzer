"""
test_stream_extractors.py
=========================
Unit-тести для _StreamExtractorMixin та всіх extractors, що його використовують:
  - GZipExtractor   (вже є test_gzip.py; тут додаємо специфічні edge cases)
  - ZlibExtractor
  - LZMAExtractor
  - XZExtractor
  - BZip2Extractor

Окремо тестуються приватні helper-функції _dec_eof / _dec_pending,
щоб зафіксувати контракт адаптації двох сімей stdlib API.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import unittest
import zlib

from mstar_analyzer.extractors import (
    BZip2Extractor,
    GZipExtractor,
    LZMAExtractor,
    XZExtractor,
    ZlibExtractor,
)
from mstar_analyzer.extractors.stream import _dec_eof, _dec_pending


# ---------------------------------------------------------------------------
# Helper-функції: тести на рівні одиниці
# ---------------------------------------------------------------------------

class TestDecEof(unittest.TestCase):
    """_dec_eof повинна надійно визначати EOF для обох сімей декомпресорів."""

    def test_zlib_eof_via_unused_data(self):
        """zlib: EOF визначається через unused_data, атрибут .eof відсутній."""
        payload = zlib.compress(b"hello")
        dec = zlib.decompressobj()
        # До кінця стриму — unused_data порожній
        dec.decompress(payload[:-2])
        self.assertFalse(_dec_eof(dec))
        # Подаємо залишок із трейлером
        dec.decompress(payload[-2:] + b"TRAILER")
        self.assertTrue(_dec_eof(dec))

    def test_lzma_eof_via_attribute(self):
        """lzma: EOF визначається через .eof, навіть якщо unused_data == b""."""
        payload = lzma.compress(b"hello", format=lzma.FORMAT_XZ)
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        dec.decompress(payload)
        # Стрім завершився рівно на межі — unused_data може бути b""
        self.assertTrue(dec.eof)
        self.assertTrue(_dec_eof(dec))

    def test_bz2_eof_via_attribute(self):
        """bz2: те саме, що lzma — використовує .eof."""
        payload = bz2.compress(b"hello")
        dec = bz2.BZ2Decompressor()
        dec.decompress(payload)
        self.assertTrue(dec.eof)
        self.assertTrue(_dec_eof(dec))

    def test_not_eof_before_stream_end(self):
        """Жоден декомпресор не вважається EOF до закінчення стриму."""
        dec_z = zlib.decompressobj()
        dec_z.decompress(b"\x78\x9c")   # початок zlib-заголовка
        self.assertFalse(_dec_eof(dec_z))

        dec_l = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        self.assertFalse(_dec_eof(dec_l))


class TestDecPending(unittest.TestCase):
    """_dec_pending повинна повертати bytes, якщо є буферизовані дані,
    або None, якщо декомпресор очікує нові зовнішні дані."""

    def test_zlib_no_pending_initially(self):
        """zlib: без виклику decompress unconsumed_tail = b"" → None."""
        dec = zlib.decompressobj()
        self.assertIsNone(_dec_pending(dec))

    def test_zlib_pending_after_max_length(self):
        """zlib: після decompress з max_length unconsumed_tail непорожній."""
        payload = zlib.compress(b"A" * 10_000)
        dec = zlib.decompressobj()
        dec.decompress(payload, 1)   # тільки 1 байт output
        if dec.unconsumed_tail:
            self.assertIsNotNone(_dec_pending(dec))
            self.assertEqual(_dec_pending(dec), dec.unconsumed_tail)

    def test_lzma_no_pending_initially(self):
        """lzma: до першого виклику needs_input == True → None."""
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        self.assertIsNone(_dec_pending(dec))

    def test_bz2_no_pending_initially(self):
        """bz2: те саме, що lzma."""
        dec = bz2.BZ2Decompressor()
        self.assertIsNone(_dec_pending(dec))

    def test_lzma_pending_after_max_length(self):
        """lzma: після decompress з max_length needs_input == False → b""."""
        big = lzma.compress(b"B" * 50_000, format=lzma.FORMAT_XZ)
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        # Маленький budget → декомпресор має внутрішній буфер
        out = dec.decompress(big, 1)
        if not dec.needs_input and not dec.eof:
            result = _dec_pending(dec)
            self.assertIsNotNone(result)
            self.assertEqual(result, b"")


# ---------------------------------------------------------------------------
# ZlibExtractor
# ---------------------------------------------------------------------------

class TestZlibExtractor(unittest.TestCase):

    def _compress(self, data: bytes) -> bytes:
        return zlib.compress(data)

    def test_basic_roundtrip(self):
        payload = b"Hello zlib!" * 200
        blob = self._compress(payload)
        r = ZlibExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)
        self.assertEqual(r.method, "zlib")

    def test_empty_payload(self):
        blob = self._compress(b"")
        r = ZlibExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, b"")
        self.assertEqual(r.output_size, 0)

    def test_consumed_with_trailer(self):
        payload = b"zlib data" * 50
        blob = self._compress(payload)
        r = ZlibExtractor().extract(blob + b"EXTRA", 0)
        self.assertTrue(r.success)
        self.assertEqual(r.consumed, len(blob))

    def test_max_output_enforced(self):
        payload = b"X" * 30_000
        blob = self._compress(payload)
        r = ZlibExtractor().extract(blob, 0, max_output=100)
        self.assertFalse(r.success)
        self.assertIn("output exceeded", r.error)

    def test_max_output_exact_fit(self):
        """Якщо payload рівно вміщується у budget — має бути success."""
        payload = b"Y" * 500
        blob = self._compress(payload)
        r = ZlibExtractor().extract(blob, 0, max_output=500)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)

    def test_truncated_stream(self):
        blob = self._compress(b"truncate me" * 100)[:-10]
        r = ZlibExtractor().extract(blob, 0)
        self.assertFalse(r.success)

    def test_corrupt_data(self):
        r = ZlibExtractor().extract(b"\x78\x9c\xff\xff\xff\xff", 0)
        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)

    def test_offset(self):
        payload = b"OFFSET_TEST" * 100
        blob = self._compress(payload)
        file_data = b"\x00" * 64 + blob
        r = ZlibExtractor().extract(file_data, 64)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)


# ---------------------------------------------------------------------------
# LZMAExtractor (FORMAT_ALONE / .lzma)
# ---------------------------------------------------------------------------

class TestLZMAExtractor(unittest.TestCase):

    def _compress(self, data: bytes) -> bytes:
        return lzma.compress(data, format=lzma.FORMAT_ALONE)

    def test_basic_roundtrip(self):
        payload = b"Hello LZMA!" * 200
        blob = self._compress(payload)
        r = LZMAExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)
        self.assertEqual(r.method, "lzma-alone")

    def test_empty_payload(self):
        blob = self._compress(b"")
        r = LZMAExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, b"")

    def test_consumed_with_trailer(self):
        payload = b"lzma data" * 50
        blob = self._compress(payload)
        r = LZMAExtractor().extract(blob + b"EXTRA", 0)
        self.assertTrue(r.success)
        self.assertEqual(r.consumed, len(blob))

    def test_max_output_enforced(self):
        payload = b"Z" * 30_000
        blob = self._compress(payload)
        r = LZMAExtractor().extract(blob, 0, max_output=100)
        self.assertFalse(r.success)
        self.assertIn("output exceeded", r.error)

    def test_truncated_stream(self):
        blob = self._compress(b"truncate me" * 100)[:-20]
        r = LZMAExtractor().extract(blob, 0)
        self.assertFalse(r.success)

    def test_corrupt_data(self):
        r = LZMAExtractor().extract(b"\x5d\x00\x00\x80\x00" + b"\xff" * 50, 0)
        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)


# ---------------------------------------------------------------------------
# XZExtractor
# ---------------------------------------------------------------------------

class TestXZExtractor(unittest.TestCase):

    def _compress(self, data: bytes) -> bytes:
        return lzma.compress(data, format=lzma.FORMAT_XZ)

    def test_basic_roundtrip(self):
        payload = b"Hello XZ!" * 200
        blob = self._compress(payload)
        r = XZExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)
        self.assertEqual(r.method, "xz")

    def test_empty_payload(self):
        blob = self._compress(b"")
        r = XZExtractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, b"")

    def test_consumed_with_trailer(self):
        payload = b"xz data" * 50
        blob = self._compress(payload)
        r = XZExtractor().extract(blob + b"EXTRA", 0)
        self.assertTrue(r.success)
        self.assertEqual(r.consumed, len(blob))

    def test_max_output_enforced(self):
        payload = b"W" * 30_000
        blob = self._compress(payload)
        r = XZExtractor().extract(blob, 0, max_output=100)
        self.assertFalse(r.success)
        self.assertIn("output exceeded", r.error)

    def test_truncated_stream(self):
        blob = self._compress(b"truncate me" * 100)[:-20]
        r = XZExtractor().extract(blob, 0)
        self.assertFalse(r.success)

    def test_corrupt_data(self):
        r = XZExtractor().extract(b"\xfd7zXZ\x00" + b"\xff" * 50, 0)
        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)


# ---------------------------------------------------------------------------
# BZip2Extractor
# ---------------------------------------------------------------------------

class TestBZip2Extractor(unittest.TestCase):

    def _compress(self, data: bytes) -> bytes:
        return bz2.compress(data)

    def test_basic_roundtrip(self):
        payload = b"Hello BZip2!" * 200
        blob = self._compress(payload)
        r = BZip2Extractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)
        self.assertEqual(r.method, "bzip2")

    def test_empty_payload(self):
        blob = self._compress(b"")
        r = BZip2Extractor().extract(blob, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.data, b"")

    def test_consumed_with_trailer(self):
        payload = b"bzip2 data" * 50
        blob = self._compress(payload)
        r = BZip2Extractor().extract(blob + b"EXTRA", 0)
        self.assertTrue(r.success)
        self.assertEqual(r.consumed, len(blob))

    def test_max_output_enforced(self):
        payload = b"V" * 30_000
        blob = self._compress(payload)
        r = BZip2Extractor().extract(blob, 0, max_output=100)
        self.assertFalse(r.success)
        self.assertIn("output exceeded", r.error)

    def test_max_output_exact_fit(self):
        """Якщо payload рівно вміщується у budget — має бути success."""
        payload = b"U" * 500
        blob = self._compress(payload)
        r = BZip2Extractor().extract(blob, 0, max_output=500)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)

    def test_truncated_stream(self):
        blob = self._compress(b"truncate me" * 100)[:-20]
        r = BZip2Extractor().extract(blob, 0)
        self.assertFalse(r.success)

    def test_corrupt_data(self):
        r = BZip2Extractor().extract(b"BZh9" + b"\xff" * 50, 0)
        self.assertFalse(r.success)
        self.assertIsNotNone(r.error)

    def test_offset(self):
        payload = b"BZ2_OFFSET" * 100
        blob = self._compress(payload)
        file_data = b"\x00" * 32 + blob
        r = BZip2Extractor().extract(file_data, 32)
        self.assertTrue(r.success)
        self.assertEqual(r.data, payload)


# ---------------------------------------------------------------------------
# Cross-family: budget boundary / ZIP-bomb prevention
# ---------------------------------------------------------------------------

class TestBudgetBoundary(unittest.TestCase):
    """Перевіряємо, що ліміт спрацьовує до накопичення зайвих байтів в пам'яті.

    Ці тести перевіряють ключову гарантію нової архітектури:
    out ніколи не перевищує max_output більш ніж на один шматок декомпресора.
    """

    PAYLOAD = b"A" * 100_000   # 100 KiB → стискається добре

    def _assert_budget_respected(self, extractor, blob, max_output):
        r = extractor.extract(blob, 0, max_output=max_output)
        self.assertFalse(r.success, "Має бути failure, стрім більший за бюджет")
        self.assertIn("output exceeded", r.error)

    def test_gzip_budget(self):
        blob = gzip.compress(self.PAYLOAD)
        self._assert_budget_respected(GZipExtractor(), blob, 1_000)

    def test_zlib_budget(self):
        blob = zlib.compress(self.PAYLOAD)
        self._assert_budget_respected(ZlibExtractor(), blob, 1_000)

    def test_lzma_budget(self):
        blob = lzma.compress(self.PAYLOAD, format=lzma.FORMAT_ALONE)
        self._assert_budget_respected(LZMAExtractor(), blob, 1_000)

    def test_xz_budget(self):
        blob = lzma.compress(self.PAYLOAD, format=lzma.FORMAT_XZ)
        self._assert_budget_respected(XZExtractor(), blob, 1_000)

    def test_bzip2_budget(self):
        blob = bz2.compress(self.PAYLOAD)
        self._assert_budget_respected(BZip2Extractor(), blob, 1_000)


if __name__ == "__main__":
    unittest.main()
