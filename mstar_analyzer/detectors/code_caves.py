"""
Code Cave Scanner.

"Печера коду" (code cave) — довгий прогін одного повторюваного байта
(типово 0xFF або 0x00) всередині виконуваної ділянки прошивки. Класичне
місце для розміщення нового коду при патчингу через Trampoline/Hook
(переспрямування виконання туди й назад).

ВАЖЛИВО — межі цього модуля: це ЛИШЕ кандидати за формою даних. Аналізатор
НЕ має дизасемблера, тож НЕ перевіряє:
  - чи справді ця ділянка виконується в рантаймі (лише що вона
    класифікована ентропійним аналізом як "code" за статистичною формою
    байтів — а не підтверджена дизасемблюванням);
  - чи безпечно туди щось записати (вирівнювання інструкцій, чи не
    розриває це таблицю переходів/vector table, чи не triggерить
    checksum/CRC перевірку прошивки при завантаженні).

Це відправна точка для РУЧНОГО дослідження в дизасемблері, а не готовий
patch plan. "Safe to write here" — окреме, набагато складніше питання,
яке цей модуль свідомо НЕ намагається відповісти.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Менші за це кандидати навряд чи вміщують щось корисне (реальний
# MIPS-хук зазвичай потребує щонайменше кілька інструкцій: збереження
# регістрів, виклик, відновлення, jr ra — 16 байт це вже дуже тісно,
# але лишаємо як нижню межу для показу "теоретично можливих" кейсів).
MIN_CAVE_SIZE = 16

# Класичні "заповнювачі" незапрограмованої/зарезервованої флеш-пам'яті.
CAVE_FILL_BYTES = (0xFF, 0x00)

_REGION_SIZE_RE = re.compile(r"(\d[\d,]*)")


@dataclass
class CodeCave:
    offset: int
    size: int
    fill_byte: int
    in_code_region: bool


def _find_byte_runs(data: bytes, fill_byte: int, min_size: int) -> list[tuple[int, int]]:
    """Повертає (offset, size) для кожного прогону `fill_byte` довжиною >= min_size."""

    runs: list[tuple[int, int]] = []
    start = None

    for i, b in enumerate(data):

        if b == fill_byte:
            if start is None:
                start = i
            continue

        if start is not None:
            if i - start >= min_size:
                runs.append((start, i - start))
            start = None

    if start is not None and len(data) - start >= min_size:
        runs.append((start, len(data) - start))

    return runs


def _code_regions(firmware_map) -> list[tuple[int, int]]:
    """
    Витягує (start, end) діапазони, які firmware_map вже класифікував
    як "region:code" за ентропією — це найкращий доступний сигнал без
    дизасемблера.
    """

    if firmware_map is None:
        return []

    ranges = []

    for entry in firmware_map.entries:

        if entry.kind != "region:code":
            continue

        match = _REGION_SIZE_RE.search(entry.detail)

        if match is None:
            continue

        length = int(match.group(1).replace(",", ""))
        ranges.append((entry.offset, entry.offset + length))

    return ranges


def detect_code_caves(
    data: bytes,
    firmware_map=None,
    min_size: int = MIN_CAVE_SIZE,
) -> list[CodeCave]:

    code_ranges = _code_regions(firmware_map)

    caves: list[CodeCave] = []

    for fill_byte in CAVE_FILL_BYTES:
        for offset, size in _find_byte_runs(data, fill_byte, min_size):

            in_code = any(start <= offset < end for start, end in code_ranges)

            caves.append(
                CodeCave(
                    offset=offset,
                    size=size,
                    fill_byte=fill_byte,
                    in_code_region=in_code,
                )
            )

    caves.sort(key=lambda c: c.offset)

    return caves
