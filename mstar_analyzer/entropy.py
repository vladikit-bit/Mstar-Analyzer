"""
Stage 3 — Entropy.

Ковзний аналіз ентропії Шеннона по вікнах фіксованого розміру.
Дозволяє відрізнити "на око" код / стиснені дані / порожні області / таблиці
ще до будь-якого дизасемблювання — так само, як це робить `binwalk -E`,
але без зовнішньої залежності.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class EntropyPoint:
    offset: int
    size: int
    entropy: float  # 0.0 .. 8.0 bits/byte


def shannon_entropy(data: bytes) -> float:
    """Ентропія Шеннона (біт на байт) для одного блоку даних."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def scan_entropy(data: bytes, window: int = 1024, step: int | None = None) -> list[EntropyPoint]:
    """Ковзний скан ентропії по всьому файлу."""
    if step is None:
        step = window
    points: list[EntropyPoint] = []
    n = len(data)
    offset = 0
    while offset < n:
        chunk = data[offset : offset + window]
        points.append(EntropyPoint(offset=offset, size=len(chunk), entropy=shannon_entropy(chunk)))
        offset += step
    return points


_BLOCKS = " ▁▂▃▄▅▆▇█"


def sparkline(points: list[EntropyPoint], width: int = 64) -> str:
    """ASCII/Unicode спарклайн ентропії — швидкий візуальний огляд файлу."""
    if not points:
        return ""
    # Ущільнюємо до `width` стовпчиків
    n = len(points)
    bucket = max(1, n // width)
    bars = []
    for i in range(0, n, bucket):
        group = points[i : i + bucket]
        avg = sum(p.entropy for p in group) / len(group)
        idx = min(len(_BLOCKS) - 1, int((avg / 8.0) * (len(_BLOCKS) - 1)))
        bars.append(_BLOCKS[idx])
    return "".join(bars)


def classify_region(entropy: float) -> str:
    """Дуже груба евристична класифікація ділянки за рівнем ентропії."""
    if entropy < 1.0:
        return "empty/padding"
    if entropy < 4.0:
        return "structured/text/tables"
    if entropy < 6.5:
        return "code"
    return "compressed/encrypted"


def high_entropy_regions(points: list[EntropyPoint], threshold: float = 7.2) -> list[tuple[int, int]]:
    """Об'єднує сусідні вікна з високою ентропією у діапазони (ймовірні LZMA/стиснені блоки)."""
    regions: list[tuple[int, int]] = []
    start = None
    last_end = None
    for p in points:
        if p.entropy >= threshold:
            if start is None:
                start = p.offset
            last_end = p.offset + p.size
        else:
            if start is not None:
                regions.append((start, last_end))
                start = None
    if start is not None:
        regions.append((start, last_end))
    return regions
