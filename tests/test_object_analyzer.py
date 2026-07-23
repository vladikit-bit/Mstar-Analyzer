"""
Регресійні тести для object_analyzer.py — валідні й невалідні
PNG/JPEG/Lua/ELF кандидати.
"""

from __future__ import annotations

import struct
import unittest
import zlib

from mstar_analyzer.detectors.objects import EmbeddedObject
from mstar_analyzer.object_analyzer import (
    analyze_elf,
    analyze_jpeg,
    analyze_lua,
    analyze_png,
)


def _real_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(
            ">I", zlib.crc32(ctype + data) & 0xFFFFFFFF
        )

    ihdr = struct.pack(">IIBBBBB", 4, 3, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00" + b"\xff\x00\x00" * 4 * 3)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _real_jpeg(width: int, height: int) -> bytes:
    soi = b"\xff\xd8"
    sof = (
        b"\xff\xc0"
        + struct.pack(">HB", 11, 8)
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00"
    scan = bytes(range(1, 51))
    eoi = b"\xff\xd9"
    return soi + sof + sos + scan + eoi


class PngTests(unittest.TestCase):

    def test_real_png_is_validated_with_dimensions(self):
        data = _real_png()
        obj = EmbeddedObject(offset=0, size=None, kind="PNG", description="PNG image")
        analyze_png(obj, data)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["width"], 4)
        self.assertEqual(obj.metadata["height"], 3)
        self.assertEqual(obj.size, len(data))

    def test_fake_png_signature_downgrades_confidence(self):
        # Сигнатура PNG знайдена, але наступний chunk не IHDR — типовий
        # false positive.
        data = b"\x89PNG\r\n\x1a\n" + b"XXXXnotIHDR" + b"\x00" * 20
        obj = EmbeddedObject(offset=0, size=None, kind="PNG", description="PNG image")
        analyze_png(obj, data)
        self.assertFalse(obj.validated)
        self.assertEqual(obj.confidence, "low")
        self.assertEqual(obj.metadata["reason"], "invalid_png")


class JpegTests(unittest.TestCase):

    def test_real_jpeg_dimensions_and_size(self):
        data = _real_jpeg(64, 48)
        obj = EmbeddedObject(offset=0, size=None, kind="JPEG", description="JPEG image")
        analyze_jpeg(obj, data)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["width"], 64)
        self.assertEqual(obj.metadata["height"], 48)
        self.assertEqual(obj.size, len(data))

    def test_implausible_dimensions_downgrade_confidence(self):
        # Той самий випадок, що й реальний false positive у прошивці:
        # width=49151 height=0.
        data = (
            b"\xff\xd8\xff\xc0"
            + struct.pack(">HB", 11, 8)
            + struct.pack(">HH", 0, 49151)
            + b"\x01\x01\x11\x00"
            + b"\xff\xd9"
        )
        obj = EmbeddedObject(offset=0, size=None, kind="JPEG", description="JPEG image")
        analyze_jpeg(obj, data)
        self.assertFalse(obj.validated)
        self.assertEqual(obj.confidence, "low")
        self.assertEqual(obj.metadata["reason"], "implausible_dimensions")


class LuaTests(unittest.TestCase):

    def test_valid_lua_51_header(self):
        header = b"\x1bLua" + bytes([0x51, 0x00, 0x00, 0x04, 0x08, 0x04, 0x08, 0x00])
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["lua_version"], "5.1")

    def test_implausible_header_lists_specific_issues(self):
        header = b"\x1bLua" + bytes([0x50, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99])
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertFalse(obj.validated)
        self.assertEqual(obj.confidence, "low")
        self.assertIn("header_issues", obj.metadata)
        self.assertGreater(len(obj.metadata["header_issues"]), 0)
        # version-байт 0x50 — реальна історична версія Lua 5.0, тож
        # мусить бути окрема примітка про це.
        self.assertIn("note", obj.metadata)


# ============================================================================
# ELF fixtures
# ============================================================================

def _elf_ident(class_byte: int, data_byte: int) -> bytes:
    """16-байтний e_ident: magic + class + endian + version + padding."""
    return (
        b"\x7fELF"
        + bytes([class_byte, data_byte, 1])  # EI_CLASS, EI_DATA, EI_VERSION=1
        + b"\x00" * 9                          # EI_OSABI + padding
    )


def _elf32_header(
    e_type: int, e_machine: int, e_entry: int,
    e_phoff: int, e_shoff: int,
    e_phnum: int, e_shnum: int, e_shstrndx: int,
    endian: str = "<",
) -> bytes:
    """52-байтний ELF32 header (без e_ident — додається окремо)."""
    return struct.pack(
        endian + "HHIIIIIHHHHHH",
        e_type,        # e_type
        e_machine,     # e_machine
        1,             # e_version
        e_entry,       # e_entry
        e_phoff,       # e_phoff
        e_shoff,       # e_shoff
        0,             # e_flags
        52,            # e_ehsize
        32,            # e_phentsize
        e_phnum,       # e_phnum
        40,            # e_shentsize
        e_shnum,       # e_shnum
        e_shstrndx,    # e_shstrndx
    )


def _elf32_phdr(
    p_type: int, p_offset: int, p_vaddr: int, p_paddr: int,
    p_filesz: int, p_memsz: int, p_flags: int, p_align: int,
    endian: str = "<",
) -> bytes:
    return struct.pack(
        endian + "IIIIIIII",
        p_type, p_offset, p_vaddr, p_paddr,
        p_filesz, p_memsz, p_flags, p_align,
    )


def _elf32_shdr(
    sh_name: int, sh_type: int, sh_flags: int, sh_addr: int,
    sh_offset: int, sh_size: int,
    endian: str = "<",
) -> bytes:
    # sh_link(I) sh_info(I) sh_addralign(I) sh_entsize(I) доповнюємо нулями.
    return struct.pack(
        endian + "IIIIIIIIII",
        sh_name, sh_type, sh_flags, sh_addr,
        sh_offset, sh_size, 0, 0, 0, 0,
    )


def _real_elf32_mips() -> bytes:
    """
    Мінімальний валідний ELF32 LE MIPS EXEC. Розкладка у файлі:

        0x000  e_ident + e_header   (52 байти)
        0x034  program header       (32 байти, PT_LOAD)
        0x100  .text                (0x40 байт коду)
        0x140  .shstrtab            (22 байти string table)
        0x200  section header table (4 × 40 байт)

    section header table:
        [0] NULL
        [1] .text     (PROGBITS, AX)
        [2] .bss      (NOBITS,   AX)
        [3] .shstrtab (STRTAB)  <- e_shstrndx вказує сюди
    """
    strtab = b"\x00.text\x00.bss\x00.shstrtab\x00"
    # Індекси імен у string table (зсув від її початку)
    name_text = 1        # "\x00" + ".text\x00"     -> 1
    name_bss = 7         # ".bss\x00"               -> 7
    name_shstrtab = 12   # ".shstrtab\x00"          -> 12

    text_offset = 0x100
    text_size = 0x40
    strtab_offset = text_offset + text_size   # 0x140
    phoff = 0x34
    shoff = 0x200   # section header table — в кінці, нічого не перекриває

    ident = _elf_ident(class_byte=1, data_byte=1)  # 32-bit, LE
    header = _elf32_header(
        e_type=2,          # EXEC
        e_machine=8,       # MIPS
        e_entry=0x80010000,
        e_phoff=phoff,
        e_shoff=shoff,
        e_phnum=1,
        e_shnum=4,         # NULL + .text + .bss + .shstrtab
        e_shstrndx=3,      # .shstrtab — третя (індекс 3)
    )
    phdr = _elf32_phdr(
        p_type=1,            # PT_LOAD
        p_offset=text_offset,
        p_vaddr=0x80010000,
        p_paddr=0x80010000,
        p_filesz=text_size,
        p_memsz=text_size + 0x20,  # .bss розширює memsize
        p_flags=5,            # R+X
        p_align=0x1000,
    )

    text_blob = b"\xCC" * text_size

    shdrs = b"".join([
        # [0] SHT_NULL — заглушка, обов'язково присутня, sh_name=0, усі поля 0.
        _elf32_shdr(0, 0, 0, 0, 0, 0),
        # [1] .text — PROGBITS, AX, займає місце у файлі.
        _elf32_shdr(name_text, 1, 0x6, 0x80010000, text_offset, text_size),
        # [2] .bss — NOBITS (sh_type=8): у файлі місця НЕ займає.
        _elf32_shdr(name_bss, 8, 0x6, 0x80010040, text_offset + text_size, 0x20),
        # [3] .shstrtab — STRTAB, e_shstrndx вказує сюди.
        _elf32_shdr(name_shstrtab, 3, 0x0, 0, strtab_offset, len(strtab)),
    ])

    blob = bytearray(shoff + len(shdrs))
    blob[0:len(ident)] = ident
    blob[len(ident):len(ident) + len(header)] = header
    blob[phoff:phoff + len(phdr)] = phdr
    blob[text_offset:text_offset + text_size] = text_blob
    blob[strtab_offset:strtab_offset + len(strtab)] = strtab
    blob[shoff:shoff + len(shdrs)] = shdrs
    return bytes(blob)


def _real_elf64_aarch64() -> bytes:
    """Мінімальний валідний ELF64 BE AArch64 EXEC, без секцій (stripped-стиль)."""
    ident = _elf_ident(class_byte=2, data_byte=2)  # 64-bit, BE
    header = struct.pack(
        ">HHIQQQIHHHHHH",
        2,          # e_type EXEC
        183,        # e_machine AArch64
        1,          # e_version
        0x400000,   # e_entry
        64,         # e_phoff (одразу за header)
        0,          # e_shoff — немає секцій
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        1,          # e_phnum
        64,         # e_shentsize (не має значення, бо shnum=0)
        0,          # e_shnum
        0,          # e_shstrndx
    )
    phdr = struct.pack(
        ">IIQQQQQQ",
        1,          # PT_LOAD
        5,          # flags R+X
        0x100,      # offset
        0x400000,   # vaddr
        0x400000,   # paddr
        0x80,       # filesz
        0x80,       # memsz
        0x1000,     # align
    )
    blob = bytearray(0x200)
    blob[0:len(ident)] = ident
    blob[len(ident):len(ident) + len(header)] = header
    blob[64:64 + len(phdr)] = phdr
    blob[0x100:0x100 + 0x80] = b"\x99" * 0x80
    return bytes(blob)


def _bad_elf_header() -> bytes:
    """ELF-сигнатура + невалідні e_ident поля."""
    return (
        b"\x7fELF"
        + bytes([9, 9, 9])  # EI_CLASS, EI_DATA, EI_VERSION — все невалідне
        + b"\x00" * 9
        + b"\x00" * 40      # решта header
    )


class ElfTests(unittest.TestCase):

    def test_valid_elf32_mips_exec(self):
        data = _real_elf32_mips()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["class"], "32-bit")
        self.assertEqual(obj.metadata["data"], "little-endian")
        self.assertEqual(obj.metadata["machine"], "MIPS")
        self.assertIn("EXEC", obj.metadata["type"])
        self.assertTrue(obj.metadata["has_section_headers"])

    def test_valid_elf64_aarch64_stripped(self):
        data = _real_elf64_aarch64()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["class"], "64-bit")
        self.assertEqual(obj.metadata["data"], "big-endian")
        self.assertEqual(obj.metadata["machine"], "AArch64")
        self.assertFalse(obj.metadata["has_section_headers"])
        self.assertIn("stripped", obj.metadata["note"].lower())

    def test_bad_header_demotes(self):
        data = _bad_elf_header()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        self.assertFalse(obj.validated)
        self.assertEqual(obj.confidence, "low")
        self.assertEqual(obj.metadata["reason"], "invalid_elf_header")
        self.assertIn("header_issues", obj.metadata)
        self.assertGreater(len(obj.metadata["header_issues"]), 0)

    def test_load_segment_present(self):
        data = _real_elf32_mips()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        segments = obj.metadata["segments"]
        load_segs = [s for s in segments if s["type"] == "PT_LOAD"]
        self.assertEqual(len(load_segs), 1)
        self.assertEqual(load_segs[0]["vaddr"], "0x80010000")
        self.assertIn("R", load_segs[0]["flags"])
        self.assertIn("X", load_segs[0]["flags"])

    def test_section_names_resolved(self):
        data = _real_elf32_mips()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        section_names = {s["name"] for s in obj.metadata["sections"]}
        self.assertIn(".text", section_names)
        self.assertIn(".bss", section_names)
        self.assertIn(".shstrtab", section_names)

    def test_size_computed_from_segments(self):
        data = _real_elf32_mips()
        obj = EmbeddedObject(offset=0, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        # Розмір береться як max від:
        #   - PT_LOAD:          0x100 + 0x40         = 0x140 (320)
        #   - .shstrtab:        0x140 + 22           = 0x156 (342)
        #   - section hdr table: 0x200 + 4*40        = 0x2A0 (672)  <- найбільше
        # .bss (NOBITS) у файлі місця не займає, тож не враховується.
        self.assertEqual(obj.size, 672)

    def test_offset_elf_analyzed_in_place(self):
        # ELF, що лежить не на початку буфера — офсет має врахуватись.
        data = b"\x00" * 0x50 + _real_elf32_mips()
        obj = EmbeddedObject(offset=0x50, size=None, kind="ELF", description="ELF binary")
        analyze_elf(obj, data)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["machine"], "MIPS")


if __name__ == "__main__":
    unittest.main()
