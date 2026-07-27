"""
Регресійні тести для MBoot Env Block parser.

Покривають:
  - Детектор: пошук блоку у flash.bin та відсутність хибних спрацьовувань
  - Парсер: version string, env variables, preamble
  - Confidence: правила призначення high/medium/low
  - Edge cases: truncated block, multiple blocks
"""

from __future__ import annotations

import unittest

from mstar_analyzer.analyzers.mboot_env import (
    MBootVariable,
    MBootEnvBlockInfo,
    _find_preamble_start,
    _extract_version_string,
    _skip_ff_padding,
    _extract_env_variables,
    parse_mboot_env_block,
    compute_confidence,
)
from mstar_analyzer.detectors.objects import detect_mboot_env_block, EmbeddedObject
from mstar_analyzer.object_analyzer import analyze_mboot_env_block


# ---------------------------------------------------------------------------
# Helper: побудувати штучний MBoot block з параметрами
# ---------------------------------------------------------------------------


def _build_mboot_block(
    preamble_size: int = 64,
    version: str = "MBOT-1106.0.10.test.20260101000000",
    variables: dict[str, str] | None = None,
    total_block_size: int = 1024,
) -> bytes:
    """
    Зібрати синтетичний MBoot Env Block.

    Структура:
      [0xFF padding до total_block_size - preamble_size - version_size - env_size]
      [preamble — ненульові байти]
      [version string + 0xFF terminator]
      [0xFF padding]
      [env variables \\n-розділені + \\0 terminator]
      [0xFF padding]
    """
    if variables is None:
        variables = {"Board": "TEST_BD", "MBoot_IN": "SPI_FLASH"}

    preamble = bytes(range(1, preamble_size + 1))  # ненульові байти

    version_bytes = version.encode("ascii")
    version_part = version_bytes + b"\xff"

    env_lines = "".join(f"{k}={v} \n" for k, v in variables.items())
    env_part = env_lines.encode("ascii") + b"\x00"

    # Перевіряємо, чи все влазить
    content_size = len(preamble) + len(version_part) + len(env_part)
    if total_block_size < content_size + 2:
        total_block_size = content_size + 2

    # Padding з 0xFF навколо preamble (зліва) та після env (справа)
    padding_before = b"\xff" * (total_block_size - content_size - 1)
    padding_after = b"\xff" * 1

    block = padding_before + preamble + version_part + env_part + padding_after
    return block


# ============================================================================
# Тести парсер-хелперів
# ============================================================================


class TestFindPreambleStart(unittest.TestCase):
    """_find_preamble_start — пошук межі preamble."""

    def test_finds_boundary_after_ff_padding(self):
        block = _build_mboot_block(preamble_size=64)
        # Знайти MBOT- в блоці
        mbot_pos = block.find(b"MBOT-")
        preamble_start = _find_preamble_start(block, mbot_pos)
        # Preamble має бути відокремлена від 0xFF padding
        self.assertGreater(preamble_start, 0)
        self.assertLess(preamble_start, mbot_pos)
        # Байт перед preamble має бути 0xFF
        self.assertEqual(block[preamble_start - 1], 0xFF)

    def test_no_ff_before_marker(self):
        """Якщо перед MBOT- немає 0xFF — preamble починається з 0."""
        data = b"some preambleMBOT-version\xffenv\x00"
        preamble_start = _find_preamble_start(data, 13)
        # Немає 0xFF перед ненульовими даними — preamble=offset MBOT-
        self.assertEqual(preamble_start, 13)

    def test_marker_at_start_of_data(self):
        """MBOT- на самому початку — preamble size=0."""
        data = b"MBOT-version\xffkey=val\x00"
        preamble_start = _find_preamble_start(data, 0)
        self.assertEqual(preamble_start, 0)


class TestExtractVersionString(unittest.TestCase):
    """_extract_version_string — парсинг version string з \\xff terminator."""

    def test_extracts_full_version(self):
        data = b"MBOT-1106.0.10.test.20260101\xff"
        version, end = _extract_version_string(data, 0)
        self.assertEqual(version, "MBOT-1106.0.10.test.20260101")
        self.assertEqual(end, 28)  # offset першого \xff (len "MBOT-1106.0.10.test.20260101")

    def test_extracts_short_version(self):
        data = b"MBOT-1.0\xff"
        version, end = _extract_version_string(data, 0)
        self.assertEqual(version, "MBOT-1.0")
        self.assertEqual(end, 8)  # len "MBOT-1.0"

    def test_no_ff_terminator(self):
        """Якщо немає \xff — читає до кінця даних."""
        data = b"MBOT-1.0"
        version, end = _extract_version_string(data, 0)
        self.assertEqual(version, "MBOT-1.0")
        self.assertEqual(end, len(data))


class TestExtractEnvVariables(unittest.TestCase):
    """_extract_env_variables — розбір key=value пар."""

    def test_extracts_multiple_variables(self):
        data = b"Board=TEST_BD \nMBoot_IN=SPI_FLASH \nSecurity=Non-TEE \n\x00"
        variables, block_end = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 3)
        self.assertEqual(variables[0].name, "Board")
        self.assertEqual(variables[0].value, "TEST_BD")
        self.assertEqual(variables[1].name, "MBoot_IN")
        self.assertEqual(variables[1].value, "SPI_FLASH")
        self.assertEqual(variables[2].name, "Security")
        self.assertEqual(variables[2].value, "Non-TEE")
        # block_end — offset першого \x00 після змінних
        self.assertEqual(block_end, len(data) - 1)

    def test_strips_trailing_spaces(self):
        data = b"Board=TEST_BD   \n\x00"
        variables, _ = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 1)
        self.assertEqual(variables[0].value, "TEST_BD")  # spaces stripped

    def test_empty_lines_skipped(self):
        data = b"Board=TEST \n\nMBoot_IN=SPI \n\x00"
        variables, _ = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 2)

    def test_unknown_keys_captured(self):
        data = b"CustomKey=CustomValue \nPanel=AUO_T215 \n\x00"
        variables, _ = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 2)
        self.assertEqual(variables[0].name, "CustomKey")
        self.assertEqual(variables[1].name, "Panel")

    def test_offsets_and_lengths(self):
        data = b"Board=TEST \n\x00"
        variables, _ = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 1)
        self.assertEqual(variables[0].offset, 0)
        self.assertEqual(variables[0].length, 12)  # "Board=TEST \n"

    def test_offsets_with_base(self):
        data = b"Board=TEST \n\x00"
        variables, _ = _extract_env_variables(data, 0, len(data), 0x100)
        self.assertEqual(variables[0].offset, 0x100)

    def test_block_end_terminated_by_ff(self):
        """block_end — це offset першого 0xFF або 0x00 після змінних."""
        data = b"Board=TEST \n\xff\xff"
        variables, block_end = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 1)
        self.assertEqual(block_end, 12)  # "Board=TEST \n" — 12 байт

    def test_block_end_at_limit(self):
        """Якщо змінні йдуть до кінця даних — block_end = limit."""
        data = b"Board=TEST \n"
        variables, block_end = _extract_env_variables(data, 0, len(data), 0)
        self.assertEqual(len(variables), 1)
        self.assertEqual(block_end, len(data))


# ============================================================================
# Тести повного парсингу (parse_mboot_env_block)
# ============================================================================


class TestParseMbootEnvBlock(unittest.TestCase):
    """parse_mboot_env_block — інтеграційний тест парсера."""

    def test_full_block(self):
        block = _build_mboot_block(
            preamble_size=64,
            version="MBOT-1106.0.10.test.20260101000000",
            variables={"Board": "TEST_BD", "MBoot_IN": "SPI_FLASH", "Security": "Non-TEE"},
            total_block_size=1024,
        )
        mbot_pos = block.find(b"MBOT-")
        info = parse_mboot_env_block(block, mbot_pos)

        self.assertEqual(info.version_string, "MBOT-1106.0.10.test.20260101000000")
        self.assertGreater(info.preamble_size, 0)
        self.assertEqual(len(info.variables), 3)
        # block_end має бути після всіх змінних, але перед 0xFF padding
        self.assertGreater(info.block_end, mbot_pos)
        self.assertLess(info.block_end, len(block))

    def test_no_variables(self):
        block = _build_mboot_block(
            preamble_size=64,
            variables={},
            total_block_size=256,
        )
        mbot_pos = block.find(b"MBOT-")
        info = parse_mboot_env_block(block, mbot_pos)
        self.assertEqual(len(info.variables), 0)


# ============================================================================
# Тести confidence
# ============================================================================


class TestComputeConfidence(unittest.TestCase):
    """compute_confidence — правила призначення confidence."""

    def test_high_many_vars_with_preamble(self):
        info = MBootEnvBlockInfo(variables=[MBootVariable("a", "1", 0, 5)] * 3)
        self.assertEqual(compute_confidence(info, preamble_found=True), "high")

    def test_high_one_var_with_preamble(self):
        info = MBootEnvBlockInfo(variables=[MBootVariable("a", "1", 0, 5)])
        self.assertEqual(compute_confidence(info, preamble_found=True), "high")

    def test_medium_no_vars_with_preamble(self):
        info = MBootEnvBlockInfo(variables=[])
        self.assertEqual(compute_confidence(info, preamble_found=True), "medium")

    def test_medium_no_preamble_with_vars(self):
        info = MBootEnvBlockInfo(variables=[MBootVariable("a", "1", 0, 5)])
        self.assertEqual(compute_confidence(info, preamble_found=False), "medium")

    def test_low_only_marker(self):
        info = MBootEnvBlockInfo(variables=[])
        self.assertEqual(compute_confidence(info, preamble_found=False), "low")


# ============================================================================
# Тести детектора
# ============================================================================


class TestDetectMbootEnvBlock(unittest.TestCase):
    """detect_mboot_env_block — пошук кандидатів."""

    def test_detects_single_block(self):
        block = _build_mboot_block(total_block_size=1024)
        objects = detect_mboot_env_block(block)
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].kind, "MBootEnvBlock")
        self.assertEqual(objects[0].description, "MBoot environment block")
        # offset — це offset маркера MBOT- (не preamble_start)
        self.assertEqual(objects[0].offset, block.find(b"MBOT-"))
        # size та confidence встановлює analyzer, детектор не заповнює
        self.assertIsNone(objects[0].size)
        self.assertEqual(objects[0].confidence, "low")

    def test_no_false_positive_without_marker(self):
        data = b"\x00" * 1024 + b"Some random text\x00" * 32
        objects = detect_mboot_env_block(data)
        self.assertEqual(len(objects), 0)

    def test_no_false_positive_random_binary(self):
        import os
        data = os.urandom(4096)
        # Випадкові байти можуть містити "MBOT-" — але це дуже малоймовірно
        # і якщо станеться, confidence буде low
        objects = detect_mboot_env_block(data)
        # Головне: не викидає виняток
        self.assertIsInstance(objects, list)

    def test_detects_multiple_blocks(self):
        block1 = _build_mboot_block(version="MBOT-1.0", variables={"A": "1"}, total_block_size=256)
        block2 = _build_mboot_block(version="MBOT-2.0", variables={"B": "2"}, total_block_size=256)
        data = block1 + block2
        objects = detect_mboot_env_block(data)
        self.assertEqual(len(objects), 2)


# ============================================================================
# Тести аналізатора (analyze_mboot_env_block через EmbeddedObject)
# ============================================================================


class TestAnalyzeMbootEnvBlock(unittest.TestCase):
    """analyze_mboot_env_block — заповнення EmbeddedObject.metadata."""

    def test_metadata_populated(self):
        block = _build_mboot_block(
            preamble_size=64,
            version="MBOT-1106.0.10.test",
            variables={"Board": "TEST_BD", "MBoot_IN": "SPI_FLASH"},
            total_block_size=1024,
        )
        objects = detect_mboot_env_block(block)
        self.assertEqual(len(objects), 1)

        obj = objects[0]
        analyze_mboot_env_block(obj, block)

        self.assertEqual(obj.metadata["mboot_version"], "MBOT-1106.0.10.test")
        self.assertGreater(obj.metadata["mboot_preamble_size"], 0)
        self.assertEqual(obj.metadata["mboot_variable_count"], 2)

        vars_list = obj.metadata["mboot_variables"]
        self.assertEqual(len(vars_list), 2)
        self.assertEqual(vars_list[0]["name"], "Board")
        self.assertEqual(vars_list[0]["value"], "TEST_BD")
        self.assertEqual(vars_list[1]["name"], "MBoot_IN")
        self.assertEqual(vars_list[1]["value"], "SPI_FLASH")

    def test_size_computed_from_block_end_and_preamble(self):
        """obj.size = block_end - preamble_offset (анализатор власне обчислює розмір)."""
        block = _build_mboot_block(
            preamble_size=64,
            version="MBOT-1106.0.10.test",
            variables={"Board": "TEST_BD", "MBoot_IN": "SPI_FLASH"},
            total_block_size=1024,
        )
        objects = detect_mboot_env_block(block)
        obj = objects[0]
        analyze_mboot_env_block(obj, block)

        self.assertIsNotNone(obj.size)
        self.assertGreater(obj.size, 0)
        # size має охоплювати preamble + version + env
        self.assertGreater(obj.size, 64)  # принаймні preamble_size

    def test_confidence_high_for_well_formed_block(self):
        block = _build_mboot_block(
            preamble_size=64,
            variables={"Board": "TEST_BD", "MBoot_IN": "SPI_FLASH", "Security": "Non-TEE"},
            total_block_size=1024,
        )
        objects = detect_mboot_env_block(block)
        obj = objects[0]
        analyze_mboot_env_block(obj, block)
        self.assertEqual(obj.confidence, "high")

    def test_truncated_block_handled(self):
        """Block truncated near MBOT- marker — not crashing."""
        data = b"MBOT-1.0"  # very short
        objects = detect_mboot_env_block(data)
        # Marker too close to end — detector should skip
        self.assertEqual(len(objects), 0)


# ============================================================================
# Інтеграційний тест на реальній прошивці flash.bin
# ============================================================================


class TestFlashBinIntegration(unittest.TestCase):
    """Перевірка на реальних даних з flash.bin."""

    @classmethod
    def setUpClass(cls):
        try:
            with open("firmware/flash.bin", "rb") as f:
                cls.data = f.read()
        except FileNotFoundError:
            raise unittest.SkipTest("firmware/flash.bin not found")

    def test_detects_mboot_block_in_flash(self):
        objects = detect_mboot_env_block(self.data)
        self.assertGreaterEqual(len(objects), 1, "Expected at least one MBoot block in flash.bin")

    def test_block_offset_near_0xB000(self):
        objects = detect_mboot_env_block(self.data)
        obj = objects[0]
        # obj.offset — це offset маркера MBOT- (не preamble_start).
        # Маркер розташований після preamble, тому його позиція
        # трохи більша за preamble_start.
        self.assertLessEqual(obj.offset, 0xB100)
        self.assertGreaterEqual(obj.offset, 0xA000)

    def test_version_string_extracted(self):
        objects = detect_mboot_env_block(self.data)
        obj = objects[0]
        analyze_mboot_env_block(obj, self.data)
        self.assertTrue(obj.metadata["mboot_version"].startswith("MBOT-"))

    def test_known_variables_present(self):
        objects = detect_mboot_env_block(self.data)
        obj = objects[0]
        analyze_mboot_env_block(obj, self.data)
        var_names = {v["name"] for v in obj.metadata["mboot_variables"]}
        self.assertIn("Board", var_names)
        self.assertIn("MBoot_IN", var_names)

    def test_confidence_high(self):
        objects = detect_mboot_env_block(self.data)
        obj = objects[0]
        analyze_mboot_env_block(obj, self.data)
        self.assertEqual(obj.confidence, "high")
