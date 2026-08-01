"""
Регресійні тести для object_analyzer.py — валідні й невалідні
PNG/JPEG/Lua/ELF кандидати.
"""

from __future__ import annotations

import struct
import unittest
import zlib

from mstar_analyzer.detectors.objects import EmbeddedObject, detect_uimage
from mstar_analyzer.object_analyzer import (
    analyze_dtb,
    analyze_elf,
    analyze_jpeg,
    analyze_lua,
    analyze_png,
    analyze_uimage,
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
        # мусить бути окрема примітка про це — навіть при повністю
        # сміттєвих полях (це саме шлях _analyze_lua_5_0, а не 5.1+).
        self.assertIn("note", obj.metadata)


class Lua50HeaderTests(unittest.TestCase):
    """
    Lua 5.0 (lundump.h/lundump.c 5.0.3, перевірено за lua.org/source/5.0/)
    має ІНШУ розкладку заголовка за 5.1+: без окремого байта LUAC_FORMAT,
    з чотирма додатковими байтами SIZE_OP/A/B/C, і завершується не одним
    "integral_flag" байтом, а РЕАЛЬНИМ числом TEST_NUMBER (кратним π).
    Раніше версія 0x50 завжди йшла через 5.1-парсер і практично гарантовано
    провалювала перевірку навіть на СПРАВЖНІХ Lua 5.0 чанках.
    """

    @staticmethod
    def _build_50_header(*, little_endian: bool, size_number: int = 8,
                          size_op=6, size_a=8, size_b=9, size_c=9,
                          test_number: float | None = None) -> bytes:

        order = "<" if little_endian else ">"

        if test_number is None:
            test_number = 3.14159265358979323846E7

        num_fmt = "f" if size_number == 4 else "d"

        return (
            b"\x1bLua"
            + bytes([0x50])
            + bytes([1 if little_endian else 0])
            + bytes([4, 4, 4])  # size_int, size_size_t, size_instruction
            + bytes([size_op, size_a, size_b, size_c])
            + bytes([size_number])
            + struct.pack(f"{order}{num_fmt}", test_number)
        )

    def test_valid_lua_50_header_little_endian(self):
        header = self._build_50_header(little_endian=True)
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["lua_version"], "5.0")
        self.assertEqual(obj.metadata["endianness"], "little")

    def test_valid_lua_50_header_big_endian(self):
        header = self._build_50_header(little_endian=False)
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["endianness"], "big")

    def test_valid_lua_50_header_extracts_chunk_name(self):
        header = self._build_50_header(little_endian=True)
        chunk = b"@menu/main.lua\x00"
        chunk_block = struct.pack("<I", len(chunk)) + chunk
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + chunk_block + b"\x00" * 20)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["chunk_name"], "@menu/main.lua")

    def test_valid_lua_50_header_at_nonzero_offset(self):
        header = self._build_50_header(little_endian=True)
        data = b"\xAB" * 37 + header + b"\x00" * 20
        obj = EmbeddedObject(offset=37, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, data)
        self.assertTrue(obj.validated)

    def test_wrong_test_number_is_rejected(self):
        # Структурно правдоподібний заголовок (усі розміри в допустимих
        # межах, OP+A+B+C=32=size_instruction*8), але TEST_NUMBER не
        # відповідає π·10⁷ — це має провалити перевірку, а не пройти
        # лише тому, що байти розмірів виглядають ОК.
        header = self._build_50_header(little_endian=True, test_number=123456.0)
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertFalse(obj.validated)
        self.assertIn("header_issues", obj.metadata)
        self.assertTrue(any("TEST_NUMBER" in issue for issue in obj.metadata["header_issues"]))

    def test_inconsistent_opcode_bit_widths_rejected(self):
        # OP+A+B+C=31, size_instruction=4 (=32 біт очікується) — не сходиться.
        header = self._build_50_header(little_endian=True, size_op=6, size_a=8, size_b=8, size_c=9)
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertFalse(obj.validated)
        self.assertTrue(any("OP/A/B/C" in issue for issue in obj.metadata["header_issues"]))

    def test_51_header_still_uses_old_layout_not_50_path(self):
        # Регресія: переконатись, що диспетчеризація за version_byte==0x50
        # не зачепила існуючий 5.1-шлях.
        header = b"\x1bLua" + bytes([0x51, 0x00, 0x00, 0x04, 0x08, 0x04, 0x08, 0x00])
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        analyze_lua(obj, header + b"\x00" * 20)
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["lua_version"], "5.1")
        self.assertNotIn("size_op_bits", obj.metadata)  # 5.0-специфічне поле не мало б з'явитись

    def test_nan_test_number_bytes_do_not_crash(self):
        # 0x7FF8000000000000 (little-endian double) декодується як NaN.
        # int(nan) кидає ValueError, а не struct.error — без явного
        # перехоплення це впало б необробленим винятком і зупинило б
        # аналіз усієї прошивки (analyze_objects не має try/except
        # навколо окремих аналізаторів).
        nan_bytes = bytes.fromhex("000000000000f87f")  # little-endian double NaN
        header = self._build_50_header(little_endian=True)[:-8] + nan_bytes
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        try:
            analyze_lua(obj, header + b"\x00" * 20)
        except (ValueError, OverflowError) as exc:
            self.fail(f"analyze_lua crashed on NaN TEST_NUMBER bytes: {exc!r}")
        self.assertFalse(obj.validated)
        self.assertTrue(any("TEST_NUMBER" in issue for issue in obj.metadata["header_issues"]))

    def test_inf_test_number_bytes_do_not_crash(self):
        inf_bytes = bytes.fromhex("000000000000f07f")  # little-endian double +Inf
        header = self._build_50_header(little_endian=True)[:-8] + inf_bytes
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        try:
            analyze_lua(obj, header + b"\x00" * 20)
        except (ValueError, OverflowError) as exc:
            self.fail(f"analyze_lua crashed on Inf TEST_NUMBER bytes: {exc!r}")
        self.assertFalse(obj.validated)


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


def _build_dtb(model="mstar,titania", compatible=("mstar,titania", "mstar,generic"), empty=False):
    """Мінімальний, спец-коректний .dtb: лише model/compatible кореня (без дочірніх вузлів)."""

    strings_block = b"model\x00compatible\x00"
    model_nameoff = strings_block.index(b"model\x00")
    compat_nameoff = strings_block.index(b"compatible\x00")

    struct_block = bytearray()
    struct_block += struct.pack(">I", 0x00000001)  # FDT_BEGIN_NODE
    struct_block += b"\x00"                          # ім'я кореня = ""
    while len(struct_block) % 4:
        struct_block += b"\x00"

    def add_prop(name_off, value):
        struct_block.extend(struct.pack(">III", 0x00000003, len(value), name_off))
        struct_block.extend(value)
        while len(struct_block) % 4:
            struct_block.extend(b"\x00")

    if not empty:
        add_prop(model_nameoff, model.encode() + b"\x00")
        add_prop(compat_nameoff, b"\x00".join(c.encode() for c in compatible) + b"\x00")

    struct_block += struct.pack(">I", 0x00000002)  # FDT_END_NODE
    struct_block += struct.pack(">I", 0x00000009)  # FDT_END

    off_mem_rsvmap = 40
    mem_rsvmap = struct.pack(">QQ", 0, 0)
    off_dt_struct = off_mem_rsvmap + len(mem_rsvmap)
    off_dt_strings = off_dt_struct + len(struct_block)
    used_strings = b"" if empty else strings_block
    totalsize = off_dt_strings + len(used_strings)

    header = struct.pack(
        ">10I",
        0xD00DFEED, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap,
        17, 16, 0, len(used_strings), len(struct_block),
    )

    return bytes(header) + mem_rsvmap + bytes(struct_block) + used_strings


class DtbHeaderTests(unittest.TestCase):
    """
    Формат заголовка перевірений за офіційною Devicetree Specification
    (devicetree-specification.readthedocs.io, §5.2) — 10 полів по
    4 байти, big-endian.
    """

    def test_valid_dtb_extracts_model_and_compatible(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, _build_dtb())
        self.assertTrue(obj.validated)
        self.assertEqual(
            obj.metadata["root_properties"],
            {"model": "mstar,titania", "compatible": ["mstar,titania", "mstar,generic"]},
        )

    def test_single_compatible_string_not_wrapped_in_list(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, _build_dtb(compatible=("mstar,titania",)))
        self.assertEqual(obj.metadata["root_properties"]["compatible"], "mstar,titania")

    def test_unaligned_offset_still_parses_correctly(self):
        # Регресія: вирівнювання рахувалось відносно абсолютного нуля
        # буфера замість початку самого DTB-блоба — ламалось щоразу,
        # коли DTB вбудований не з offset, кратного 4 (типовий випадок
        # у реальній прошивці).
        dtb = _build_dtb()
        for offset in (1, 2, 3, 5, 77, 123):
            data = b"\xAB" * offset + dtb
            obj = EmbeddedObject(offset=offset, size=None, kind="DTB", description="Flattened Device Tree")
            analyze_dtb(obj, data)
            self.assertTrue(obj.validated, f"failed at offset={offset}")
            self.assertEqual(
                obj.metadata["root_properties"]["model"],
                "mstar,titania",
                f"wrong result at offset={offset}",
            )

    def test_empty_root_with_zero_length_strings_block_is_valid(self):
        # Регресія: off_dt_strings, що вказує РІВНО на кінець totalsize
        # з size_dt_strings=0 (дерево без властивостей), хибно
        # відхилялось як "поза межами".
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, _build_dtb(empty=True))
        self.assertTrue(obj.validated)
        self.assertNotIn("root_properties", obj.metadata)

    def test_truncated_header_rejected(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, b"\xd0\x0d\xfe\xed" + b"\x00" * 10)
        self.assertFalse(obj.validated)
        self.assertEqual(obj.metadata["reason"], "truncated_header")

    def test_corrupted_magic_rejected(self):
        dtb = bytearray(_build_dtb())
        dtb[0] = 0x00
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, bytes(dtb))
        self.assertFalse(obj.validated)
        self.assertTrue(any("magic" in issue for issue in obj.metadata["header_issues"]))

    def test_totalsize_beyond_available_data_rejected(self):
        header = struct.pack(">10I", 0xD00DFEED, 99_999_999, 40, 9999, 40, 17, 16, 0, 10, 20)
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, header + b"\x00" * 100)
        self.assertFalse(obj.validated)
        self.assertTrue(any("totalsize" in issue for issue in obj.metadata["header_issues"]))

    def test_all_zero_data_does_not_crash(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, b"\x00" * 60)  # не повинно кидати виняток
        self.assertFalse(obj.validated)

    def test_last_comp_version_greater_than_version_rejected(self):
        header = struct.pack(">10I", 0xD00DFEED, 100, 40, 60, 40, 17, 18, 0, 10, 20)
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        analyze_dtb(obj, header + b"\x00" * 60)
        self.assertFalse(obj.validated)
        self.assertTrue(any("last_comp_version" in issue for issue in obj.metadata["header_issues"]))


def _build_uimage(name=b"linux-3.13.0", payload=b"KERNELDATA" * 100, little=False):
    """Спец-коректний .uimage з правильними ih_hcrc/ih_dcrc (CRC32)."""

    order = "<" if little else ">"
    magic = 0x27051956
    os_type, arch, img_type, comp = 5, 2, 2, 0  # Linux, ARM, kernel, none
    dcrc = zlib.crc32(payload) & 0xFFFFFFFF

    name_field = name + b"\x00" * (32 - len(name))
    header_wo_hcrc = (
        struct.pack(f"{order}I", magic)
        + b"\x00\x00\x00\x00"
        + struct.pack(f"{order}5I", 0x12345678, len(payload), 0x80008000, 0x80008000, dcrc)
        + bytes([os_type, arch, img_type, comp])
        + name_field
    )
    hcrc = zlib.crc32(header_wo_hcrc) & 0xFFFFFFFF
    header = struct.pack(f"{order}I", magic) + struct.pack(f"{order}I", hcrc) + header_wo_hcrc[8:]

    return header + payload


class UImageHeaderTests(unittest.TestCase):
    """
    Формат перевірений за офіційним джерелом U-Boot (github.com/u-boot/
    u-boot include/image.h) та незалежно — Kaitai Struct format spec.
    64-байтний заголовок, мережевий порядок байтів (big-endian) для
    всіх 32-бітних полів.
    """

    def test_valid_uimage_extracts_metadata(self):
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, _build_uimage())
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["name"], "linux-3.13.0")
        self.assertEqual(obj.metadata["os"], "Linux")
        self.assertEqual(obj.metadata["architecture"], "ARM")
        self.assertEqual(obj.metadata["type"], "OS Kernel Image")
        self.assertEqual(obj.metadata["compression"], "None")
        self.assertEqual(obj.metadata["endianness"], "big")

    def test_header_and_data_crc_validated_correctly(self):
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, _build_uimage())
        self.assertTrue(obj.metadata["header_crc_valid"])
        self.assertTrue(obj.metadata["data_crc_valid"])

    def test_corrupted_payload_fails_data_crc_but_header_still_valid(self):
        img = bytearray(_build_uimage())
        img[-1] ^= 0xFF  # псуємо останній байт payload, заголовок не чіпаємо
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, bytes(img))
        self.assertTrue(obj.validated)  # структура заголовка й далі коректна
        self.assertTrue(obj.metadata["header_crc_valid"])
        self.assertFalse(obj.metadata["data_crc_valid"])

    def test_little_endian_variant_detected(self):
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, _build_uimage(little=True))
        self.assertTrue(obj.validated)
        self.assertEqual(obj.metadata["endianness"], "little")
        self.assertTrue(obj.metadata["header_crc_valid"])

    def test_unaligned_offsets_all_parse_identically(self):
        img = _build_uimage()
        for offset in (0, 1, 2, 3, 4, 55, 133):
            data = b"\xAB" * offset + img
            obj = EmbeddedObject(offset=offset, size=None, kind="uImage", description="U-Boot legacy image header")
            analyze_uimage(obj, data)
            self.assertTrue(obj.validated, f"failed at offset={offset}")
            self.assertEqual(obj.metadata["name"], "linux-3.13.0", f"wrong result at offset={offset}")

    def test_truncated_header_rejected(self):
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, _build_uimage()[:30])
        self.assertFalse(obj.validated)
        self.assertEqual(obj.metadata["reason"], "truncated_header")

    def test_size_exceeding_available_data_rejected(self):
        img = _build_uimage()
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, img[:64])  # лише заголовок, без payload
        self.assertFalse(obj.validated)
        self.assertTrue(any("ih_size" in issue for issue in obj.metadata["header_issues"]))

    def test_unknown_enum_values_labeled_not_dropped(self):
        img = bytearray(_build_uimage())
        img[28] = 255  # ih_os за межами відомої таблиці (28 = 7*4, після 7 uint32-полів)
        obj = EmbeddedObject(offset=0, size=None, kind="uImage", description="U-Boot legacy image header")
        analyze_uimage(obj, bytes(img))
        self.assertTrue(obj.validated)  # невідомий enum — не структурна помилка
        self.assertEqual(obj.metadata["os"], "unknown (255)")

    def test_detect_uimage_finds_both_endianness_magics(self):
        data = _build_uimage()[:20] + b"\x00" * 40 + _build_uimage(little=True)
        objects = detect_uimage(data)
        offsets = sorted(o.offset for o in objects)
        self.assertEqual(len(objects), 2)
        self.assertEqual(offsets, [0, 60])


if __name__ == "__main__":
    unittest.main()
