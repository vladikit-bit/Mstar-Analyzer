"""
Регресійні тести для strings.py — переважно is_signal_quality().

Кожен "noise" кейс тут — це РЕАЛЬНИЙ false positive, підтверджений на
справжній прошивці (Romsat TR-9110HD / MStar) під час розробки, а не
вигаданий приклад. Якщо цей тест колись почне падати — значить хтось
(можливо, майбутня версія Claude) послабив фільтр і одна з цих
конкретних, вже раз виправлених проблем повернулася.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.strings import (
    MIN_LENGTH,
    extract_ascii_strings,
    is_signal_quality,
)


class IsSignalQualityTests(unittest.TestCase):

    # Кожен запис тут — реальний рядок, побачений у справжньому виводі
    # аналізатора під час цієї сесії розробки.
    CONFIRMED_NOISE = [
        "(GERD",       # Graphics Engine false positive (5 символів)
        "-eB=",        # Endian (big) false positive (4 символи)
        "F-ebdG",      # Endian false positive (6 символів)
        "-eBEn",       # Endian false positive (5 символів)
        "geLF",        # Graphics Engine false positive (4 символи, до MIN_SIGNAL_LENGTH)
        "mIu>",        # Memory controller false positive (4 символи)
        "GE`s%[qS",    # Graphics Engine false positive — 8 символів (пройшов
                       # старий поріг довжини!), макс. прогін літер лише 2.
    ]

    CONFIRMED_REAL_EVIDENCE = [
        "MDrv_GE_SetStrBltSckType",
        "driver GE init ok",
        "MIU0 Init Done",
        "Wait MIU10...",
        "mipsisa32-elf-gcc -mips16 -EL -D ECOS_OS",
        "value for `lua_getinfo' is not a function",
    ]

    def test_confirmed_noise_is_rejected(self):
        for text in self.CONFIRMED_NOISE:
            with self.subTest(text=text):
                self.assertFalse(
                    is_signal_quality(text),
                    f"{text!r} previously confirmed as noise — should stay rejected",
                )

    def test_confirmed_real_evidence_is_accepted(self):
        for text in self.CONFIRMED_REAL_EVIDENCE:
            with self.subTest(text=text):
                self.assertTrue(
                    is_signal_quality(text),
                    f"{text!r} is real evidence from an actual firmware run — must not be rejected",
                )


class ExtractAsciiStringsTests(unittest.TestCase):

    def test_respects_min_length(self):
        data = b"\x00" + b"AB" + b"\x00" + b"ABCD" + b"\x00"
        found = [s.text for s in extract_ascii_strings(data, min_length=MIN_LENGTH)]
        self.assertNotIn("AB", found)
        self.assertIn("ABCD", found)

    def test_requires_at_least_two_letters(self):
        # Чисто цифровий/символьний "рядок" не повинен потрапляти —
        # це не текст, а радше числова структура/таблиця.
        data = b"\x00" + b"1234" + b"\x00" + b"AB12" + b"\x00"
        found = [s.text for s in extract_ascii_strings(data)]
        self.assertNotIn("1234", found)
        self.assertIn("AB12", found)

    def test_end_of_file_string_uses_same_rule_as_middle(self):
        # Раніше кінець файлу мав слабшу вимогу (>=1 літера) за середину
        # файлу (>=2 літери) — неузгодженість, яку виправили.
        data = b"\x00" + b"A123"  # лише 1 літера, рядок аж до кінця файлу
        found = [s.text for s in extract_ascii_strings(data)]
        self.assertNotIn("A123", found)

    def test_offsets_are_correct(self):
        data = b"\x00\x00" + b"HelloWorld"
        found = extract_ascii_strings(data)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].offset, 2)
        self.assertEqual(found[0].text, "HelloWorld")


if __name__ == "__main__":
    unittest.main()
