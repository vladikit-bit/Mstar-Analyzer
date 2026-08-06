"""
Регресійні тести для оптимізації LzmaHeuristicScanner (signatures.py):
_PROPS_LOOKUP — precomputed lookup table замість виклику
_decode_properties() з арифметикою (%, //) на кожній позиції буфера.

Контекст: на відміну від zlib (2-байтний магіко-подібний заголовок,
32 валідних значення з 65536 — iter_find() дає ~6x) і JFFS2 (2-байтний
magic, iter_find() дає ~100x), у LZMA-alone заголовка немає короткого
розрідженого патерну: 75/256 (~29%) байтових значень props самі по
собі валідні, тож "рідкісні збіги" підхід сюди не переноситься
(перевірено окремо: пошук символьним класом через `re` над 32 МБ уже
займає ~4с ДО перевірки dict_size/usize — гірше, ніж просто цикл).
Натомість оптимізація суто в усуненні накладних витрат Python-виклику
функції на кожній ітерації: заміряно 5.44с -> 2.93с (лише props-
перевірка) на 32 МБ.
"""

from __future__ import annotations

import lzma
import os
import time
import unittest

from mstar_analyzer.signatures import _PROPS_LOOKUP, LzmaHeuristicScanner, _decode_properties


class PropsLookupCorrectnessTests(unittest.TestCase):
    """
    _PROPS_LOOKUP мусить бути побайтово ідентичною _decode_properties() —
    інакше оптимізація змінила б те, що приймається/відхиляється, а не
    лише швидкість.
    """

    def test_lookup_matches_function_for_every_byte_value(self):
        for p in range(256):
            with self.subTest(props=p):
                self.assertEqual(_PROPS_LOOKUP[p], _decode_properties(p))

    def test_lookup_length_is_256(self):
        self.assertEqual(len(_PROPS_LOOKUP), 256)


class LzmaHeuristicScannerCorrectnessTests(unittest.TestCase):
    """
    Переконуємось, що оптимізація не змінила поведінку самого сканера
    (не лише lookup-таблиці окремо).
    """

    def test_detects_real_lzma_alone_stream(self):
        payload = b"MStar firmware bootloader data " * 3000
        compressed = lzma.compress(
            payload,
            format=lzma.FORMAT_ALONE,
            filters=[{"id": lzma.FILTER_LZMA1, "preset": 6}],
        )
        data = b"\xFF" * 500 + compressed + b"\xFF" * 500

        found = LzmaHeuristicScanner().scan(data)

        matches = [f for f in found if f.offset == 500]
        self.assertEqual(len(matches), 1, found)
        self.assertEqual(matches[0].name, "lzma-alone-header")

    def test_detects_stream_at_multiple_lzma1_presets(self):
        # Різні preset-и дають різні lc/lp/pb (не завжди дефолтні 3/0/2).
        for preset in (0, 1, 6, 9):
            with self.subTest(preset=preset):
                payload = b"payload data " * 500
                compressed = lzma.compress(
                    payload,
                    format=lzma.FORMAT_ALONE,
                    filters=[{"id": lzma.FILTER_LZMA1, "preset": preset}],
                )
                found = LzmaHeuristicScanner().scan(compressed)
                self.assertTrue(any(f.offset == 0 for f in found), f"preset={preset}: not found")

    def test_no_findings_on_too_short_buffer(self):
        self.assertEqual(LzmaHeuristicScanner().scan(b"\x00" * 5), [])


class LzmaHeuristicScannerPerformanceTests(unittest.TestCase):

    def test_scan_stays_fast_on_large_high_entropy_input(self):
        """
        Регресія на продуктивність: до оптимізації 32 МБ чистого шуму
        сканувались ~6.3с (переважно — Python-виклик _decode_properties()
        на кожній із 32М позицій); після — ~3.2с. Межу 5с узято з запасом,
        щоб не бути крихкою на повільнішому CI, але вона все одно
        достатньо нижче старого часу, щоб зловити регресію до
        function-call-based версії.
        """
        data = os.urandom(16_000_000)

        t0 = time.perf_counter()
        LzmaHeuristicScanner().scan(data)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 3.5, f"scan() took {elapsed:.3f}s on 16MB — looks like a performance regression")


if __name__ == "__main__":
    unittest.main()
