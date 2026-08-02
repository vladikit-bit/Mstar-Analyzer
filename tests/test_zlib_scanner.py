"""
Регресійні тести для ZlibHeuristicScanner (signatures.py) і його
підключення до решти пайплайну.

Контекст: ZlibExtractor (extractors/zlib.py) існував і був повністю
покритий тестами (tests/test_stream_extractors.py) задовго до появи
цього сканера — але жоден Scanner не породжував Finding(name="zlib"),
і ExtractorFactory його теж не знала. "Мотор" був готовий, "запалення"
були відсутнім: жоден сирий zlib/deflate потік ніколи не потрапляв у
Stage 5 як candidate. Ці тести фіксують сканер САМ ПО СОБІ і те, що
весь ланцюжок (Stage 2 -> factory -> Stage 5 -> classify_node) тепер
з'єднаний наскрізно.
"""

from __future__ import annotations

import random
import unittest
import zlib

from mstar_analyzer.analyze import analyze_node
from mstar_analyzer.extractors.factory import DEFAULT_FACTORY
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.signatures import Finding, ZlibHeuristicScanner, _VALID_ZLIB_HEADERS


class ZlibValidHeaderEnumerationTests(unittest.TestCase):
    """
    ZlibHeuristicScanner шукає через iter_find() по переліченому набору
    валідних (CMF,FLG) пар (_VALID_ZLIB_HEADERS), а не циклом по
    кожному байту — цей тест фіксує саме той факт, на якому тримається
    швидкість: набір валідних заголовків малий і незмінний.
    """

    def test_exactly_32_valid_headers(self):
        # 8 валідних CMF (CINFO 0..7, CM=8) x 4 валідних FLEVEL
        # (FDICT=0, FCHECK підбирається однозначно під кожен) = 32.
        self.assertEqual(len(_VALID_ZLIB_HEADERS), 32)

    def test_every_enumerated_header_passes_checksum(self):
        for header in _VALID_ZLIB_HEADERS:
            cmf, flg = header
            self.assertEqual((cmf * 256 + flg) % 31, 0)
            self.assertEqual(cmf & 0x0F, 8)

    def test_well_known_zlib_compress_headers_are_included(self):
        # 0x78 0x9C — найпоширеніший заголовок, який реально видає
        # zlib.compress() на рівні 6 (типовий дефолт).
        self.assertIn(bytes((0x78, 0x9C)), _VALID_ZLIB_HEADERS)


class ZlibHeuristicScannerTests(unittest.TestCase):

    def setUp(self):
        self.scanner = ZlibHeuristicScanner()

    def test_finds_real_zlib_stream_at_correct_offset(self):
        payload = b"Hello firmware zlib stream! " * 50
        blob = zlib.compress(payload)
        data = b"\xFF" * 100 + blob + b"\xFF" * 100

        found = self.scanner.scan(data)

        self.assertTrue(
            any(f.offset == 100 and f.name == "zlib" for f in found),
            f"expected a 'zlib' Finding at offset 100, got {found}",
        )

    def test_all_standard_compression_levels_are_detected(self):
        # 0x78 0x01 / 0x78 0x5E / 0x78 0x9C / 0x78 0xDA — заголовки,
        # які реально видає zlib.compress() на рівнях 0-1 / 2-5 / 6 /
        # 7-9 відповідно. Усі мають пройти checksum-перевірку.
        for level in (1, 3, 6, 9):
            with self.subTest(level=level):
                blob = zlib.compress(b"payload data " * 40, level)
                found = self.scanner.scan(blob)
                self.assertTrue(any(f.offset == 0 for f in found))

    def test_rejects_non_deflate_compression_method(self):
        # CM=7 замість 8 (deflate) — валідний checksum, але не той метод.
        cmf = 0x77  # CINFO=7, CM=7
        for flg in range(256):
            if (cmf * 256 + flg) % 31 == 0:
                header = bytes([cmf, flg]) + b"\x11\x22\x33\x44"
                self.assertEqual(self.scanner.scan(header), [])
                return
        self.fail("no matching FLG found for test setup")

    def test_rejects_oversized_window(self):
        # CINFO=8 (вікно 64 KiB) — за межами того, що реально
        # трапляється (CM=8 обмежений CINFO<=7 специфікацією zlib).
        cmf = 0x88  # CINFO=8, CM=8
        for flg in range(256):
            if (cmf * 256 + flg) % 31 == 0:
                header = bytes([cmf, flg]) + b"\x11\x22\x33\x44"
                self.assertEqual(self.scanner.scan(header), [])
                return
        self.fail("no matching FLG found for test setup")

    def test_rejects_fdict_headers(self):
        # FDICT-біт (0x20 у FLG) виставлено — свідомо не підтримуємо.
        cmf = 0x78
        for flg in range(256):
            if (flg >> 5) & 1 and (cmf * 256 + flg) % 31 == 0:
                header = bytes([cmf, flg]) + b"\x11\x22\x33\x44\x55\x66"
                self.assertEqual(self.scanner.scan(header), [])
                return
        self.fail("no FDICT-set FLG found for test setup")

    def test_rejects_header_followed_by_zero_padding(self):
        # Валідний checksum, але одразу за заголовком — суцільні нулі
        # (типовий незапрограмований flash-заповнювач, а не реальний
        # стиснений потік).
        cmf, flg = 0x78, 0x9C
        self.assertEqual((cmf * 256 + flg) % 31, 0)
        header_then_zeros = bytes([cmf, flg]) + b"\x00" * 20
        self.assertEqual(self.scanner.scan(header_then_zeros), [])

    def test_false_positive_rate_on_random_data_is_bounded(self):
        # Детермінований PRNG (не os.urandom) — тест відтворюваний.
        # Теоретична очікувана частота: ~32 валідних (CMF,FLG) пари з
        # 65536 можливих на кожну позицію, тобто ~1 знахідка на ~2048
        # байт. Перевіряємо порядок величини, а не точне число.
        noise = random.Random(42).randbytes(200_000)
        found = self.scanner.scan(noise)
        expected = len(noise) / 2048
        self.assertLess(len(found), expected * 3)

    def test_scan_stays_fast_on_large_high_entropy_input(self):
        """
        Регресія на продуктивність: scan() шукає через iter_find() по
        32 переліченим заголовкам (_VALID_ZLIB_HEADERS), а не циклом
        по кожному байту. На 8 МБ псевдовипадкових даних (найгірший
        випадок для high-entropy вікна) оптимізована версія — ~0.12с;
        попередня посимвольна Python-реалізація — ~0.7с. Межу 0.4с
        свідомо взято так, щоб пропускати оптимізовану версію з запасом
        і ловити випадкове повернення до старого алгоритму.
        """

        import time

        data = random.Random(1).randbytes(8_000_000)

        t0 = time.perf_counter()
        self.scanner.scan(data)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 0.4, f"scan() took {elapsed:.3f}s — looks like the O(n) per-byte fallback")


class ZlibFactoryRegistrationTests(unittest.TestCase):

    def test_factory_resolves_zlib_finding_to_zlib_extractor(self):
        finding = Finding(offset=0, name="zlib", confidence="medium")
        extractor = DEFAULT_FACTORY.for_finding(finding)
        self.assertIsNotNone(extractor)
        self.assertEqual(extractor.method, "zlib")


class ZlibEndToEndPipelineTests(unittest.TestCase):
    """
    Наскрізна перевірка через analyze_node() — те саме, чого раніше не
    відбувалось узагалі: жоден Scanner не породжував Finding(name="zlib"),
    тож ExtractorFactory ніколи не отримувала для неї candidate,
    незалежно від того, наскільки коректним був сам ZlibExtractor.
    """

    def test_raw_zlib_stream_is_detected_extracted_and_classified(self):
        payload = b"eCos zlib payload data " * 500  # достатньо для high-entropy вікна
        blob = zlib.compress(payload, 9)

        data = random.Random(7).randbytes(300) + blob + random.Random(9).randbytes(300)

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1)
        child = root.children[0]

        self.assertEqual(child.data, payload)
        self.assertEqual(child.format, "zlib")
        self.assertEqual(child.compression, "zlib")
        self.assertIn("[zlib]", root.pretty())


if __name__ == "__main__":
    unittest.main()
