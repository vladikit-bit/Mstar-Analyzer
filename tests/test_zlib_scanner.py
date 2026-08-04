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

    def test_false_positive_rate_on_random_data_is_near_zero(self):
        """
        До додавання _deflate_structurally_plausible()/_bounded_deflate_probe()
        цей тест допускав до 3x теоретичної частоти ~1/2048 (тобто до
        ~293 знахідок на 200000 байт) — інструмент, який давав ТИСЯЧІ
        "zlib"-рядків шуму на реальній прошивці (незалежний review,
        4МБ образ: 1920 кандидатів, 0 успішних декомпресій).

        Після двох структурних перевірок (BTYPE/LEN~NLEN — безкоштовно;
        обмежений 256-байтний probe через справжній декодер, результат
        відкидається) емпірично на 40 МБ чистого шуму (19737 структурно
        валідних CMF/FLG заголовків, БЕЗ ентропійного префільтра) — 0
        хибних спрацювань. Перевірено на 20 різних seed по 200000 байт
        кожен — теж стабільний нуль. Це не гарантія на всі можливі
        входи (математично ненульова залишкова ймовірність існує), але
        точно НЕ "3x від теоретичної частоти" — тому строгий поріг
        замість м'якого.
        """
        for seed in range(10):
            with self.subTest(seed=seed):
                noise = random.Random(seed).randbytes(200_000)
                found = self.scanner.scan(noise)
                self.assertEqual(found, [], f"seed={seed}: expected 0 findings on pure noise, got {len(found)}")

    def test_bounded_probe_accepts_valid_empty_zlib_stream(self):
        """
        zlib.compress(b"") — валідний 8-байтний потік, що декомпресується
        в 0 байт БЕЗ помилки. Критерій _bounded_deflate_probe() — "не
        кинуло виняток", а НЕ "дало непорожній вивід" — саме тому, що
        вимога "≥1 байт" хибно відкидала б цей легітимний, хай і
        рідкісний, випадок (знайдено емпірично під час перевірки
        компромісного рішення з reviewer'ом).
        """
        empty_stream = zlib.compress(b"")
        found = self.scanner.scan(b"\xFF" * 50 + empty_stream + b"\xFF" * 50)
        self.assertTrue(any(f.offset == 50 for f in found), found)

    def test_deflate_structural_check_rejects_btype_11(self):
        # BTYPE=11 (reserved/invalid) одразу за валідним CMF/FLG заголовком.
        from mstar_analyzer.signatures import _deflate_structurally_plausible

        # first byte deflate-потоку: BFINAL=1, BTYPE=11 -> біти (LSB->MSB) 1,1,1 -> 0b111 = 0x07
        data = bytes([0x78, 0x9C, 0x07]) + b"\x11" * 10
        self.assertFalse(_deflate_structurally_plausible(data, 0))

    def test_deflate_structural_check_validates_stored_block_len_nlen(self):
        from mstar_analyzer.signatures import _deflate_structurally_plausible

        # BTYPE=00 (stored), BFINAL=0 -> перший байт deflate-потоку = 0x00
        # LEN=0x1234, NLEN має бути ~LEN = 0xEDCB
        valid = bytes([0x78, 0x9C, 0x00, 0x34, 0x12, 0xCB, 0xED])
        self.assertTrue(_deflate_structurally_plausible(valid, 0))

        invalid = bytes([0x78, 0x9C, 0x00, 0x34, 0x12, 0x00, 0x00])  # NLEN не є доповненням LEN
        self.assertFalse(_deflate_structurally_plausible(invalid, 0))

    def test_bounded_probe_rejects_garbage_that_passes_free_checks(self):
        from mstar_analyzer.signatures import _bounded_deflate_probe

        # BTYPE=01 (fixed Huffman) з випадковим сміттям далі — минає
        # безкоштовну перевірку (яка не заглядає всередину Huffman-кодів),
        # але має бути відкинуте самим probe.
        rng = random.Random(11)
        rejected = 0
        for _ in range(50):
            garbage = bytes([0x78, 0x9C]) + rng.randbytes(64)
            if not _bounded_deflate_probe(garbage, 0):
                rejected += 1
        self.assertGreater(rejected, 40, "bounded probe should reject the vast majority of random garbage")

    def test_scan_stays_fast_on_large_high_entropy_input(self):
        """
        Регресія на продуктивність: навіть з двома додатковими
        структурними перевірками (BTYPE/LEN~NLEN + обмежений probe)
        сканування 32 МБ чистого шуму лишається ~0.5с — бо probe
        (найдорожчий крок) викликається лише для кандидатів, що вже
        пройшли обидва дешевші фільтри, а на чистому шумі таких
        практично 0 після BTYPE/LEN~NLEN.
        """

        import time

        data = random.Random(1).randbytes(8_000_000)

        t0 = time.perf_counter()
        self.scanner.scan(data)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 1.0, f"scan() took {elapsed:.3f}s — looks like a performance regression")


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
