"""
Регресійні тести для lz4_block.py — чистого Python декодера LZ4
"block format" (без жодної runtime-залежності).

Оскільки stdlib не має модуля lz4, а сам цей модуль реалізує лише
ДЕКОМПРЕСІЮ (не компресію), єдиний спосіб перевірити коректність —
round-trip проти незалежного референсного компресора: пакет `lz4` з
PyPI (тестова, НЕ runtime-залежність — див. pyproject.toml). Якщо
пакет не встановлено, ці тести коректно пропускаються, а не падають.
"""

from __future__ import annotations

import random
import unittest

from mstar_analyzer.lz4_block import Lz4BlockError, decompress_block

try:
    import lz4.block as _reference_lz4_block
    HAVE_LZ4 = True
except ImportError:
    HAVE_LZ4 = False


@unittest.skipUnless(HAVE_LZ4, "pip install lz4 — needed only as a reference compressor for these tests")
class RoundTripTests(unittest.TestCase):
    """Стиснути референсним компресором, розпакувати нашим декодером."""

    def _roundtrip(self, payload: bytes) -> None:
        compressed = _reference_lz4_block.compress(payload, store_size=False)
        result = decompress_block(compressed)
        self.assertEqual(result, payload)

    def test_empty(self):
        self._roundtrip(b"")

    def test_single_byte(self):
        self._roundtrip(b"a")

    def test_short_text(self):
        self._roundtrip(b"hello world")

    def test_long_rle_friendly_run(self):
        # offset=1 self-referential copy — найчастіше джерело помилок
        # у ручних LZ77-подібних реалізаціях (перекриваюче копіювання).
        self._roundtrip(b"a" * 500)

    def test_repeating_short_pattern(self):
        self._roundtrip(b"abc" * 400)

    def test_long_literal_run_needs_length_extension(self):
        # >15 літералів поспіль -> код довжини 15 + байти розширення.
        self._roundtrip(b"The quick brown fox jumps over the lazy dog. " * 300)

    def test_varied_bytes_all_values(self):
        self._roundtrip(bytes(range(256)) * 50)

    def test_uncompressible_random_data_forces_all_literals(self):
        self._roundtrip(random.Random(1).randbytes(4000))

    def test_fuzz_various_shapes_and_sizes(self):
        rng = random.Random(42)
        failures = []

        for i in range(300):
            kind = rng.choice(["random", "repetitive", "text", "mixed"])
            length = rng.randint(0, 4000)

            if kind == "random":
                payload = rng.randbytes(length)
            elif kind == "repetitive":
                unit = rng.randbytes(rng.randint(1, 20))
                payload = (unit * (length // max(1, len(unit)) + 1))[:length]
            elif kind == "text":
                payload = (b"the quick brown fox jumps over the lazy dog " * (length // 40 + 1))[:length]
            else:
                chunks = []
                total = 0
                while total < length:
                    if rng.random() < 0.5:
                        c = rng.randbytes(rng.randint(1, 50))
                    else:
                        c = bytes([rng.randint(0, 255)]) * rng.randint(1, 100)
                    chunks.append(c)
                    total += len(c)
                payload = b"".join(chunks)[:length]

            compressed = _reference_lz4_block.compress(payload, store_size=False)
            try:
                result = decompress_block(compressed)
            except Exception as exc:
                failures.append(f"case {i} ({kind}, len={length}): raised {exc!r}")
                continue
            if result != payload:
                failures.append(f"case {i} ({kind}, len={length}): mismatch")

        self.assertEqual(failures, [], "\n".join(failures))


@unittest.skipUnless(HAVE_LZ4, "pip install lz4 — needed only as a reference compressor for these tests")
class SharedOutputBufferTests(unittest.TestCase):
    """
    output= — needed by extractors/lz4.py for LZ4 Frame "linked block"
    mode, where a later block's matches may reference back into an
    earlier block's already-decompressed data. Confirms decompress_block
    appends onto (and can read back-references from) a pre-populated
    buffer instead of always starting fresh.
    """

    def test_second_call_can_reference_first_calls_output(self):
        history = b"once upon a time in a firmware far far away, "
        buf = bytearray(history)

        # payload сам є частиною своєї ж "історії", щоб компресор мав
        # шанс і справді закодувати back-reference довжиною понад
        # межу простого RLE (не критично для коректності тесту — сам
        # decompress_block() коректний незалежно від того, ЩО саме
        # обрав компресор).
        second_payload = b"a firmware far far away is where our story begins."
        compressed = _reference_lz4_block.compress(second_payload, store_size=False)

        piece = decompress_block(compressed, output=buf)

        self.assertEqual(piece, second_payload)
        self.assertEqual(bytes(buf), history + second_payload)

    def test_output_buffer_is_mutated_in_place(self):
        buf = bytearray(b"prefix-")
        compressed = _reference_lz4_block.compress(b"suffix-data", store_size=False)
        decompress_block(compressed, output=buf)
        self.assertEqual(bytes(buf), b"prefix-suffix-data")


class ErrorHandlingTests(unittest.TestCase):
    """Пошкоджені/обрізані дані мають кидати Lz4BlockError, не щось інше."""

    def test_truncated_literal_run_raises(self):
        # token каже "14 літералів", але даних більше немає взагалі.
        with self.assertRaises(Lz4BlockError):
            decompress_block(bytes([0xE0]))

    def test_truncated_match_offset_raises(self):
        # token з literal_len=0, match_len_code=0 -> 0 літералів, вхід
        # НЕ вичерпаний (лишається 1 байт) -> це НЕ фінальна sequence,
        # тож очікує повний 2-байтний offset, а є лише 1 зайвий байт.
        # (Сам по собі token-байт 0x00 в кінці валідний і означає
        # "порожня фінальна sequence" — це не той випадок.)
        with self.assertRaises(Lz4BlockError):
            decompress_block(bytes([0x00, 0xAB]))

    def test_zero_offset_raises(self):
        # token: literal_len=0, match_len_code=0; offset=0 (невалідний).
        with self.assertRaises(Lz4BlockError):
            decompress_block(bytes([0x00, 0x00, 0x00]))

    def test_offset_before_start_of_output_raises(self):
        # offset=5, але вивід ще порожній -> посилання "до початку".
        with self.assertRaises(Lz4BlockError):
            decompress_block(bytes([0x00, 0x05, 0x00]))

    def test_empty_input_is_empty_output(self):
        self.assertEqual(decompress_block(b""), b"")


if __name__ == "__main__":
    unittest.main()
