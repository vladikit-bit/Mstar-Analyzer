"""
Регресійні тести для extractors/lz4.py (LZ4 Frame format) та
його підключення до пайплайну (signatures.py/factory.py/classify.py/
analyze.py).
"""

from __future__ import annotations

import os
import random
import unittest

from mstar_analyzer.analyze import analyze_node
from mstar_analyzer.extractors.factory import DEFAULT_FACTORY
from mstar_analyzer.extractors.lz4 import LZ4Extractor, MAGIC
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.signatures import Finding, MagicScanner

try:
    import lz4.frame as _reference_lz4_frame
    HAVE_LZ4 = True
except ImportError:
    HAVE_LZ4 = False


@unittest.skipUnless(HAVE_LZ4, "pip install lz4 — needed only as a reference compressor for these tests")
class LZ4ExtractorRoundTripTests(unittest.TestCase):

    def setUp(self):
        self.extractor = LZ4Extractor()

    def _roundtrip(self, payload: bytes, **frame_kwargs) -> None:
        compressed = _reference_lz4_frame.compress(payload, **frame_kwargs)
        result = self.extractor.extract(compressed, 0)
        self.assertTrue(result.success, result.error)
        self.assertEqual(result.data, payload)
        self.assertEqual(result.consumed, len(compressed))
        self.assertEqual(result.output_size, len(payload))

    def test_small_single_block_payload(self):
        self._roundtrip(b"hello firmware world")

    def test_multi_block_linked(self):
        payload = b"The quick brown fox jumps over the lazy dog. " * 3000
        self._roundtrip(payload, block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB, block_linked=True)

    def test_multi_block_independent(self):
        payload = b"The quick brown fox jumps over the lazy dog. " * 3000
        self._roundtrip(payload, block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB, block_linked=False)

    def test_with_content_checksum(self):
        self._roundtrip(b"payload " * 500, content_checksum=True)

    def test_with_block_checksum(self):
        self._roundtrip(
            b"payload " * 5000,
            block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB,
            block_checksum=True,
        )

    def test_with_stored_content_size(self):
        self._roundtrip(b"payload " * 500, store_size=True)

    def test_empty_payload(self):
        self._roundtrip(b"")

    def test_random_binary_payload(self):
        self._roundtrip(random.Random(5).randbytes(20000), block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB)

    def test_all_flag_combinations(self):
        rng = random.Random(7)
        failures = []
        for block_linked in (True, False):
            for content_checksum in (True, False):
                for block_checksum in (True, False):
                    for store_size in (True, False):
                        length = rng.randint(0, 100_000)
                        payload = rng.randbytes(length) if rng.random() < 0.5 else (
                            b"lorem ipsum dolor sit amet " * (length // 28 + 1)
                        )[:length]
                        compressed = _reference_lz4_frame.compress(
                            payload,
                            block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB,
                            block_linked=block_linked,
                            content_checksum=content_checksum,
                            block_checksum=block_checksum,
                            store_size=store_size,
                        )
                        result = self.extractor.extract(compressed, 0)
                        ok = (
                            result.success
                            and result.data == payload
                            and result.consumed == len(compressed)
                        )
                        if not ok:
                            failures.append(
                                f"linked={block_linked} content_ck={content_checksum} "
                                f"block_ck={block_checksum} store_size={store_size} "
                                f"len={length} -> success={result.success} error={result.error}"
                            )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_extraction_at_nonzero_offset(self):
        payload = b"kernel image bytes " * 200
        compressed = _reference_lz4_frame.compress(payload)
        data = b"\xFF" * 137 + compressed
        result = self.extractor.extract(data, 137)
        self.assertTrue(result.success, result.error)
        self.assertEqual(result.data, payload)


@unittest.skipUnless(HAVE_LZ4, "pip install lz4 — needed only as a reference compressor for these tests")
class LZ4ExtractorErrorHandlingTests(unittest.TestCase):

    def setUp(self):
        self.extractor = LZ4Extractor()
        payload = b"test payload data " * 500
        self.good = _reference_lz4_frame.compress(payload, block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB)

    def test_bad_magic_rejected(self):
        result = self.extractor.extract(b"\x00\x00\x00\x00" + self.good[4:], 0)
        self.assertFalse(result.success)

    def test_truncated_frame_never_crashes(self):
        for trunc_len in list(range(0, 30)) + [len(self.good) // 2, len(self.good) - 1, len(self.good) - 4]:
            with self.subTest(trunc_len=trunc_len):
                result = self.extractor.extract(self.good[:trunc_len], 0)
                self.assertFalse(result.success)

    def test_corrupted_bytes_never_raise_uncaught(self):
        rng = random.Random(3)
        for _ in range(100):
            corrupted = bytearray(self.good)
            pos = rng.randint(len(MAGIC), len(corrupted) - 1)
            corrupted[pos] ^= rng.randint(1, 255)
            # Не повинно кидати виняток — success True чи False, обидва прийнятні
            # (checksums не верифікуються, тож деякі пошкодження й досі
            # "успішно" розпакуються в неправильні дані — задокументовано).
            self.extractor.extract(bytes(corrupted), 0)

    def test_max_output_cap_respected(self):
        payload = os.urandom(50_000)  # некомпресивний -> великий стиснений розмір теж
        compressed = _reference_lz4_frame.compress(payload, block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB)
        result = self.extractor.extract(compressed, 0, max_output=1000)
        self.assertFalse(result.success)
        self.assertIn("exceeded", result.error)


class LZ4PipelineWiringTests(unittest.TestCase):
    """Магія детекції + фабрика + класифікація — без залежності від пакету lz4."""

    def test_magic_scanner_detects_lz4_frame_header(self):
        data = b"\xFF" * 50 + MAGIC + b"\x00" * 20
        found = MagicScanner().scan(data)
        self.assertTrue(any(f.offset == 50 and f.name == "lz4" for f in found))

    def test_factory_resolves_lz4_finding_to_lz4_extractor(self):
        finding = Finding(offset=0, name="lz4", confidence="high")
        extractor = DEFAULT_FACTORY.for_finding(finding)
        self.assertIsNotNone(extractor)
        self.assertEqual(extractor.method, "lz4")

    @unittest.skipUnless(HAVE_LZ4, "pip install lz4 — needed only as a reference compressor for these tests")
    def test_full_pipeline_end_to_end(self):
        payload = b"MStar firmware LZ4 stream content " * 3000
        compressed = _reference_lz4_frame.compress(payload, block_size=_reference_lz4_frame.BLOCKSIZE_MAX64KB)

        data = os.urandom(500) + compressed + os.urandom(500)
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1, root.children)
        child = root.children[0]
        self.assertEqual(child.data, payload)
        self.assertEqual(child.format, "LZ4")
        self.assertEqual(child.compression, "LZ4")
        self.assertIn("[LZ4]", root.pretty())


if __name__ == "__main__":
    unittest.main()
