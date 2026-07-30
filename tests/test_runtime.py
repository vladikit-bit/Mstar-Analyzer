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


class EcosPackageInventoryTests(unittest.TestCase):
    """
    libc_package_versions (плаский набір "2.0.60") існував і раніше, але
    приховував, з ЯКИХ САМЕ пакетів SDK він зібраний — різні пакети
    одного релізу технічно можуть розходитись за версією. ecos_packages
    (ім'я пакета -> набір версій) — саме той інвентар, а не лише число.
    """

    def test_multiple_packages_captured_with_names(self):
        strings = [
            _finding("/home/tao.yang/ecos_os/stb_ecospro/packages/io/serial/v2_0_60/src/common/serial.c"),
            _finding("/home/tao.yang/ecos_os/stb_ecospro/packages/services/memalloc/common/v2_0_60/src/malloc.cxx"),
            _finding("/home/tao.yang/ecos_os/stb_ecospro/packages/fs/fat/v2_0_60/src/fatfs_supp.c"),
            _finding("/home/tao.yang/ecos_os/stb_ecospro/packages/io/fileio/v2_0_60/src/misc.cxx"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(
            info.ecos_packages,
            {
                "io/serial": {"2.0.60"},
                "services/memalloc/common": {"2.0.60"},
                "fs/fat": {"2.0.60"},
                "io/fileio": {"2.0.60"},
            },
        )
        # Стара плоска форма й далі має заповнюватись — зворотна сумісність.
        self.assertEqual(info.libc_package_versions, {"2.0.60"})

    def test_package_with_disagreeing_versions(self):
        strings = [
            _finding("/ecos_os/stb_ecospro/packages/io/serial/v2_0_60/src/serial.c"),
            _finding("/ecos_os/stb_ecospro/packages/io/serial/v2_0_61/src/serial.c"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.ecos_packages["io/serial"], {"2.0.60", "2.0.61"})

    def test_vN_N_N_without_packages_prefix_not_captured_as_named_package(self):
        # ECOS_PACKAGE_NAME_RE навмисно строгіший за ECOS_PACKAGE_VERSION_RE
        # (вимагає літеральне "packages/") — інакше легко зачепити чужий
        # "vN_N_N"-каталог без стосунку до eCos package tree.
        strings = [
            _finding("ecos_os some/random/v2_0_60/path/not_a_real_package_tree"),
        ]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.ecos_packages, {})
        # Стара (менш строга) форма й далі це ловить — поведінка не регресувала.
        self.assertEqual(info.libc_package_versions, {"2.0.60"})

    def test_no_ecos_strings_gives_empty_dict(self):
        strings = [_finding("mipsisa32-elf-gcc -mips16 -EL -D ECOS_OS")]
        info = analyze_runtime(strings)
        self.assertIsNotNone(info)
        self.assertEqual(info.ecos_packages, {})


if __name__ == "__main__":
    unittest.main()
