"""
LZ4 Frame format екстрактор (magic 04 22 4D 18).

Frame format обгортає сирий "block format" (../lz4_block.py):

  * 4-байтне magic число
  * FLG/BD дескриптор-байти (+ опційне 8-байтне поле content size,
    опційне 4-байтне поле dictionary ID)
  * 1-байтний header checksum
  * послідовність Data Block-ів, кожен з 4-байтним little-endian
    префіксом розміру (старший біт = "block збережено нестисненим"),
    опційно з 4-байтним block checksum після
  * 4-байтний EndMark (усі нулі), що завершує послідовність блоків
  * опційний 4-байтний content checksum

Checksums (header/block/content) використовують xxHash32 — тут НЕ
верифікуються. Framing повністю визначається префіксами розміру блоків
незалежно від checksums, тож їх перевірка не потрібна для коректної
декомпресії — так само, як object_analyzer.py трактує uImage CRC
(ih_hcrc/ih_dcrc) як інформаційні, а не блокуючі поле. Якщо колись
знадобиться сувора верифікація — це самодостатній follow-up (xxh32 —
~20 рядків), а не причина відкладати вже робочу декомпресію.

"Linked blocks" (типовий режим за замовчуванням) означає, що пізніші
блоки можуть посилатись (offset у match) за межі свого власного блока,
у розпаковані дані ПОПЕРЕДНІХ блоків того самого фрейму. Тому всі
блоки декодуються в ОДИН спільний, зростаючий буфер (lz4_block.py
приймає його як ``output``), а не незалежно з наступною конкатенацією
— останнє дало б неправильний результат щоразу, коли реальний
back-reference перетинає межу блоку.

Спека: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
"""

from __future__ import annotations

import struct

from .base import Extractor, ExtractResult, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from ..lz4_block import decompress_block, Lz4BlockError

MAGIC = b"\x04\x22\x4d\x18"

# Бітові поля FLG-байта (Frame Descriptor, перший байт після magic).
_FLG_VERSION_SHIFT = 6
_FLG_CONTENT_CHECKSUM_BIT = 0b00000100
_FLG_CONTENT_SIZE_BIT = 0b00001000
_FLG_BLOCK_CHECKSUM_BIT = 0b00010000
_FLG_DICT_ID_BIT = 0b00000001

_BLOCK_UNCOMPRESSED_FLAG = 0x80000000
_BLOCK_SIZE_MASK = 0x7FFFFFFF


class LZ4Extractor(Extractor):
    """LZ4 Frame контейнер (magic 04 22 4D 18)."""

    method = "lz4"

    def extract(
        self,
        data: bytes,
        offset: int,
        max_output: int = DEFAULT_MAX_OUTPUT,
        chunk_size: int = DEFAULT_CHUNK,
    ) -> ExtractResult:

        try:
            return self._extract(data, offset, max_output)
        except (Lz4BlockError, struct.error, IndexError) as exc:
            return ExtractResult(
                offset=offset,
                method=self.method,
                success=False,
                error=str(exc),
            )

    def _extract(self, data: bytes, offset: int, max_output: int) -> ExtractResult:

        pos = offset
        n = len(data)

        def fail(msg: str) -> ExtractResult:
            return ExtractResult(offset=offset, method=self.method, success=False, error=msg)

        if data[pos:pos + 4] != MAGIC:
            return fail("bad magic")

        pos += 4

        if pos + 2 > n:
            return fail("truncated frame descriptor")

        flg = data[pos]
        pos += 1
        pos += 1  # BD byte — потрібен лише енкодеру (max block size hint), для декодування не використовується

        version = flg >> _FLG_VERSION_SHIFT
        if version != 1:
            return fail(f"unsupported FLG version {version}")

        if flg & _FLG_CONTENT_SIZE_BIT:
            if pos + 8 > n:
                return fail("truncated content size field")
            pos += 8

        if flg & _FLG_DICT_ID_BIT:
            if pos + 4 > n:
                return fail("truncated dictionary id field")
            pos += 4

        has_block_checksum = bool(flg & _FLG_BLOCK_CHECKSUM_BIT)

        if pos >= n:
            return fail("truncated header checksum")
        pos += 1  # HC byte — не верифікуємо, див. docstring файлу

        # Спільний зростаючий буфер для ВСІХ блоків фрейму — обов'язково
        # для коректності "linked blocks" режиму (див. docstring файлу).
        out = bytearray()

        while True:

            if pos + 4 > n:
                return fail("truncated block size field")

            block_size_field = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            if block_size_field == 0:
                break  # EndMark

            is_uncompressed = bool(block_size_field & _BLOCK_UNCOMPRESSED_FLAG)
            block_size = block_size_field & _BLOCK_SIZE_MASK

            if pos + block_size > n:
                return fail("truncated block data")

            block_data = data[pos:pos + block_size]
            pos += block_size

            if has_block_checksum:
                if pos + 4 > n:
                    return fail("truncated block checksum")
                pos += 4  # не верифікуємо

            if is_uncompressed:
                out += block_data
            else:
                decompress_block(block_data, output=out)

            if max_output and len(out) > max_output:
                return fail(f"output exceeded {max_output} byte cap before end-of-stream")

        if flg & _FLG_CONTENT_CHECKSUM_BIT:
            if pos + 4 <= n:
                pos += 4  # не верифікуємо, лише коректно позиціонуємо consumed

        return ExtractResult(
            offset=offset,
            method=self.method,
            success=True,
            data=bytes(out),
            consumed=pos - offset,
            output_size=len(out),
        )
