"""
Pure-Python декодер LZ4 "block format" — без жодної сторонньої
runtime-залежності (stdlib не має модуля lz4; проєкт свідомо не додає
третьосторонніх runtime-залежностей, див. коментар у pyproject.toml).

Реалізує ЛИШЕ декомпресію "block format" (специфікація:
https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) — сирої,
безголовкової послідовності "sequences" (token + literals +
offset + match). Це саме те, у що:

  * extractors/lz4.py розпаковує кожен Data Block LZ4 Frame format
    (Frame format обгортає block format magic-числом, дескриптором і
    префіксами розміру на кожен блок — див. docstring того файлу);
  * analyzers/squashfs.py звертається НАПРЯМУ для LZ4-стиснених блоків
    даних SquashFS (SquashFS зберігає розмір кожного блока у власних
    inode-метаданих, без жодної LZ4 frame-обгортки).

Коректність перевірена наскрізно проти референсного пакету `lz4` з
PyPI (тестова, НЕ runtime-залежність — лише tests/test_lz4_block.py;
сам цей модуль його ніколи не імпортує).
"""

from __future__ import annotations


class Lz4BlockError(Exception):
    """Пошкоджені або обрізані LZ4 block-format дані."""


def _read_length_extension(data: bytes, pos: int, base: int) -> tuple[int, int]:
    """
    Читає розширення довжини для literal/match length коду, що впирається
    у свій 4-бітний максимум (15). Кожен наступний байт додає до 255 к
    накопиченій довжині; байт < 255 завершує послідовність (і теж
    додається). Повертає (фінальна_довжина, новий_pos).
    """

    length = base

    while True:

        if pos >= len(data):
            raise Lz4BlockError("truncated length extension")

        b = data[pos]
        pos += 1
        length += b

        if b != 255:
            break

    return length, pos


def decompress_block(data: bytes, output: bytearray | None = None) -> bytes:
    """
    Розпаковує один сирий LZ4 block.

    ``output``, якщо передано, трактується як УЖЕ розпаковані попередні
    дані, на які match-и в ЦЬОМУ блоці можуть посилатись (потрібно
    extractors/lz4.py для LZ4 Frame "linked block" режиму, де пізніші
    блоки можуть back-reference-итись за межі попередніх блоків) —
    змінюється на місці. Якщо не передано — використовується свіжий
    порожній буфер (саме так це використовує analyzers/squashfs.py:
    кожен блок SquashFS розпаковується незалежно, той самий принцип,
    що вже застосовано там для gzip/xz-блоків).

    Повертає ЛИШЕ байти, розкодовані з ЦЬОГО блока (не весь ``output``
    разом з попередньою історією) — виклик з linked-mode має читати
    сумарний результат з самого ``output`` (він мутується на місці).
    """

    out = output if output is not None else bytearray()
    start_len = len(out)

    pos = 0
    n = len(data)

    while pos < n:

        token = data[pos]
        pos += 1

        literal_len = token >> 4
        match_len_code = token & 0x0F

        if literal_len == 15:
            literal_len, pos = _read_length_extension(data, pos, 15)

        if literal_len:
            end = pos + literal_len
            if end > n:
                raise Lz4BlockError("literal run exceeds available block data")
            out += data[pos:end]
            pos = end

        # За специфікацією остання sequence блока містить ЛИШЕ literals —
        # жодного offset/match-length після них. Ознака "це остання
        # sequence" — вичерпаний вхід, рівно як вимагає формат (а не
        # якийсь окремий термінатор).
        if pos >= n:
            break

        if pos + 2 > n:
            raise Lz4BlockError("truncated match offset")

        offset = data[pos] | (data[pos + 1] << 8)
        pos += 2

        if offset == 0:
            raise Lz4BlockError("match offset of 0 is invalid (corrupt stream)")

        if offset > len(out):
            raise Lz4BlockError(
                f"match offset {offset} reaches before start of output "
                f"(only {len(out)} bytes decompressed so far)"
            )

        match_len = match_len_code + 4

        if match_len_code == 15:
            match_len, pos = _read_length_extension(data, pos, 19)  # 4 + 15

        # Копіювання може перекриватись (offset < match_len — класичний
        # RLE-трюк LZ77-родини форматів, напр. offset=1 повторює один і
        # той самий байт match_len разів). ОБОВ'ЯЗКОВО побайтово: масовий
        # зріз ``out[-offset:]`` узяв би СТАЛИЙ знімок і дав би неправильний
        # результат для перекриваючих копій.
        start = len(out) - offset
        for i in range(match_len):
            out.append(out[start + i])

    return bytes(out[start_len:])
