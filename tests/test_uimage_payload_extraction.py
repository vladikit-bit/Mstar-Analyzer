"""
Регресійні тести для підключення uImage payload до дерева вузлів
(analyze.py::analyze_node()).

Контекст: object_analyzer.analyze_uimage() повністю розбирає заголовок
uImage (OS/arch/type/compression, обидва CRC, валідований розмір), але
detectors/objects.py навмисно лише детектує ("this module DOES NOT
extract anything") — і до цього патчу payload НІКОЛИ не ставав вузлом
дерева:

  * якщо ih_comp вказував на формат, чий magic сам по собі впізнається
    (gzip/xz/lzma-alone/bzip2/zlib), payload розпаковувався лише
    ЗБІГОМ — через незалежний повнофайловий скан MagicScanner/
    LzmaHeuristicScanner/ZlibHeuristicScanner, без жодного зв'язку з
    тим, що це вміст саме uImage-контейнера.
  * якщо ih_comp=0 (без стиснення) або вказував на формат, якого
    інструмент не вміє розпаковувати (lzo/lz4/zstd), payload був
    ПОВНІСТЮ невидимий: жодного вузла, жодних strings, жодного
    подальшого аналізу — лише плаский metadata dict на батьківському
    вузлі.

Ці тести фіксують обидва випадки: старий (уже працював, тепер
перевіряємо відсутність дублювання) і новий (раніше не працював
узагалі).
"""

from __future__ import annotations

import struct
import unittest
import zlib

from mstar_analyzer.analyze import analyze_node
from mstar_analyzer.firmware_tree import FirmwareNode


def _make_uimage(comp_type: int, payload: bytes, name: bytes = b"Linux-5.10") -> bytes:
    """Будує валідний (обидва CRC) uImage-контейнер навколо payload."""

    ih_size = len(payload)
    ih_dcrc = zlib.crc32(payload) & 0xFFFFFFFF
    name_padded = name + b"\x00" * (32 - len(name))

    header = struct.pack(
        ">7I4B",
        0x27051956,  # ih_magic
        0,  # ih_hcrc (заповнюється нижче)
        0,  # ih_time
        ih_size,
        0x80008000,  # ih_load
        0x80008000,  # ih_ep
        ih_dcrc,
        5,  # ih_os = Linux
        5,  # ih_arch = MIPS
        2,  # ih_type = Kernel Image
        comp_type,
    ) + name_padded

    header = bytearray(header)
    hcrc = zlib.crc32(bytes(header[:4]) + b"\x00\x00\x00\x00" + bytes(header[8:])) & 0xFFFFFFFF
    header[4:8] = struct.pack(">I", hcrc)

    return bytes(header) + payload


class UimageAlreadyCoveredPayloadTests(unittest.TestCase):
    """
    Коли ih_comp вказує на формат, чий magic MagicScanner і так
    впізнає незалежно (gzip тут), payload раніше показувався як
    анонімний вузол просто під root — без жодного зв'язку з тим, що
    це вміст саме uImage-контейнера. collect_extract_candidates()
    тепер свідомо виключає offset payload зі свого власного
    (батьківського) списку кандидатів (exclude_ranges), тож
    розпакування відбувається виключно через контекстно-обізнаний
    шлях нижче — один вузол "uImage payload (gzip)", а всередині
    нього (рекурсивно) — власне розпакований "gzip stream", а не два
    незалежні, непов'язані між собою вузли з однаковим вмістом.
    """

    def test_gzip_payload_nests_under_uimage_context_without_duplication(self):
        import gzip

        payload = b"Linux kernel bytes here " * 2000
        blob = gzip.compress(payload)

        uimg = _make_uimage(1, blob)  # ih_comp=1 -> gzip
        data = b"\xFF" * 500 + uimg + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        # Рівно один вузол на верхньому рівні — не анонімний "gzip",
        # а контекстно-обізнаний "uImage payload (gzip)".
        self.assertEqual(len(root.children), 1, root.children)
        uimage_child = root.children[0]
        self.assertIn("uImage payload", uimage_child.name)
        self.assertIn("gzip", uimage_child.name)
        self.assertEqual(uimage_child.data, blob)  # усе ще стиснені байти

        # Розпакований вміст — рекурсивно, ОДИН РАЗ, під ним.
        self.assertEqual(len(uimage_child.children), 1)
        self.assertEqual(uimage_child.children[0].data, payload)


class UimagePreviouslyInvisiblePayloadTests(unittest.TestCase):
    """
    Раніше повністю невидимі випадки — тепер мають стати справжніми
    дочірніми вузлами.
    """

    def test_uncompressed_payload_becomes_a_child(self):
        payload = b"RAW_KERNEL_BYTES_NO_COMPRESSION_" * 100

        uimg = _make_uimage(0, payload)  # ih_comp=0 -> None
        data = b"\xFF" * 500 + uimg + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1, root.children)
        child = root.children[0]
        self.assertEqual(child.data, payload)
        self.assertEqual(child.offset, 500 + 64)
        self.assertIn("uImage payload", child.name)
        self.assertIn("None", child.name)

    def test_unsupported_compression_still_becomes_a_child(self):
        # ih_comp=5 (lz4) — жоден Extractor у проєкті цього не вміє
        # розпакувати, але сирий регіон усе одно має стати доступним
        # для подальшого дослідження (замість повного зникнення).
        import random

        payload = random.Random(3).randbytes(2000)

        uimg = _make_uimage(5, payload)
        data = b"\xFF" * 500 + uimg + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1, root.children)
        child = root.children[0]
        self.assertEqual(child.data, payload)
        self.assertIn("lz4", child.name)

    def test_uncompressed_payload_still_recurses_for_further_analysis(self):
        """
        Тепер, коли payload — справжній вузол дерева, він так само
        рекурсивно аналізується: якщо всередині "нестисненого" вмісту
        випадково є ще один стиснений потік, його знайде звичайний
        рекурсивний прохід — так само, як для будь-якого іншого вузла.
        """
        import gzip

        inner = gzip.compress(b"nested payload data " * 200)
        outer_payload = b"\x00" * 100 + inner + b"\x00" * 100

        uimg = _make_uimage(0, outer_payload)
        data = b"\xFF" * 500 + uimg + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1)
        uimage_child = root.children[0]
        self.assertEqual(len(uimage_child.children), 1)
        grandchild = uimage_child.children[0]
        self.assertEqual(grandchild.data, b"nested payload data " * 200)


class UimageInvalidObjectTests(unittest.TestCase):

    def test_invalid_uimage_header_produces_no_child(self):
        # ih_size вказує на більше даних, ніж насправді є -> analyze_uimage
        # позначає obj.validated=False; жоден вузол не має з'явитись.
        broken = bytearray(_make_uimage(0, b"short"))
        # ih_size стоїть на офсеті 12..16 (big-endian) — робимо його величезним
        broken[12:16] = struct.pack(">I", 0xFFFFFFF0)

        data = b"\xFF" * 500 + bytes(broken) + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(root.children, [])

    def test_zero_size_payload_produces_no_child(self):
        uimg = _make_uimage(0, b"")
        data = b"\xFF" * 500 + uimg + b"\xFF" * 500

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(root.children, [])


if __name__ == "__main__":
    unittest.main()
