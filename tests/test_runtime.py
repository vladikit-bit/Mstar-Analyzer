"""
Регресійні тести для analyzers/runtime.py.

Обидва основні кейси тут — реальні, підтверджені false positives:
- "thumb" бare substring збігався з "thumbnail.jpg" (є в прошивці —
  YouTube picture decoder) і давав хибний ARM на MIPS-бінарнику.
- "ppc" бare substring збігався з "RegisterAppCallback"
  ("...App{ppc}allback" у нижньому регістрі) і давав хибний PowerPC.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.strings import StringFinding
from mstar_analyzer.analyzers.runtime import analyze_runtime


def _finding(text: str, offset: int = 0) -> StringFinding:
    return StringFinding(offset=offset, text=text)


class ArchitectureFalsePositiveTests(unittest.TestCase):

    def test_thumbnail_does_not_imply_arm(self):
        strings = [
            _finding("ERROR youtube pic decoder init fail, couldn't decode thumbnails"),
            _finding("thumbnail.jpg"),
            _finding("mipsisa32-elf-gcc -mips16 -EL -D ECOS_OS"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.architecture, "MIPS")

    def test_registerappcallback_does_not_imply_powerpc(self):
        strings = [
            _finding("virtual void mapi_pvr_v4::RegisterAppCallback(PVR_Event_CB*)"),
            _finding("void mapi_pvr_event_handler1::RegisterAppCallback(PVR_Event_CB*)"),
            _finding("mipsisa32-elf-gcc -mips16 -EL -D ECOS_OS"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.architecture, "MIPS")

    def test_registerappcallback_alone_does_not_imply_powerpc(self):
        # Без жодного toolchain-рядка теж не повинно давати PowerPC —
        # це перевіряє саме strict-boundary фікс для "ppc" незалежно
        # від toolchain-lock механізму.
        strings = [
            _finding("virtual void mapi_pvr_v4::RegisterAppCallback(PVR_Event_CB*)"),
        ]
        info = analyze_runtime(strings)
        if info is not None:
            self.assertNotEqual(info.architecture, "PowerPC")

    def test_genuine_powerpc_string_still_detected(self):
        # ppc як окремий токен (не всередині іншого слова) має й далі
        # спрацьовувати — фікс не повинен був вимкнути детекцію взагалі.
        strings = [
            _finding("target arch: powerpc-linux-gnu toolchain build info"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.architecture, "PowerPC")


if __name__ == "__main__":
    unittest.main()
