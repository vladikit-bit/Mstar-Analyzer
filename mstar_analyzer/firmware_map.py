"""
Stage 1 / Stage 4 — Firmware map / Chunk parser.

Відповідає на питання "з чого складається цей flash.bin?" ще до
розпаковування чи дизасемблювання. Об'єднує знахідки MagicScanner /
AsciiMarkerScanner з ентропійними регіонами у єдину впорядковану карту.

LzmaHeuristicScanner і ZlibHeuristicScanner свідомо запускаються лише
всередині high-entropy областей (а не по всьому файлу) — це на порядки
швидше та відповідає логіці "спочатку ентропія відкидає явно нецікаві
зони, потім вже шукаємо LZMA/zlib-заголовок".
"""

from __future__ import annotations

from dataclasses import dataclass

from .entropy import EntropyPoint, classify_region, high_entropy_regions, scan_entropy, sparkline
from .signatures import AsciiMarkerScanner, LzmaHeuristicScanner, MagicScanner, ZlibHeuristicScanner


@dataclass
class MapEntry:
    offset: int
    kind: str
    confidence: str
    detail: str = ""


@dataclass
class FirmwareMap:
    size: int
    entropy_points: list[EntropyPoint]
    entries: list[MapEntry]

    def sparkline(self, width: int = 64) -> str:
        return sparkline(self.entropy_points, width=width)

    def as_table(self) -> str:
        lines = [f"{'Offset':>10}   {'Type':<30} {'Confidence':<8} Detail"]
        for e in sorted(self.entries, key=lambda x: x.offset):
            lines.append(f"0x{e.offset:08X}   {e.kind:<30} {e.confidence:<8} {e.detail}")
        return "\n".join(lines)


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _dedupe_lzma_findings(findings: list[MapEntry], cluster_distance: int = 16) -> list[MapEntry]:
    """
    LzmaHeuristicScanner (і так само ZlibHeuristicScanner нижче)
    неминуче дають overlapping-спрацювання: справжній заголовок на
    зсуві X майже завжди "частково" проходить евристику ще й на
    X+1, X+2, ... (зсунувшись на кілька байт, структурні поля все одно
    можуть випадково задовольнити обмеження — а для самих СТИСНЕНИХ
    даних одразу за заголовком це майже гарантовано, вони самі мають
    вигляд випадкового шуму). Це один шумовий кластер, а не N
    незалежних потоків.

    Групуємо сусідні знахідки (в межах `cluster_distance` байт одна від
    одної) і лишаємо з кожного кластера тільки одну — з найвищою
    confidence (а при рівності — найранішу).

    Назва лишається "_lzma_findings" з історичних причин (і тому, що
    tests/test_firmware_map.py вже імпортує її під цим ім'ям) — сама
    логіка не специфічна до LZMA, це спільний dedup для будь-якого
    byte-level евристичного сканера, що працює всередині одного вікна.
    """

    if not findings:
        return findings

    ordered = sorted(findings, key=lambda e: e.offset)

    clusters: list[list[MapEntry]] = [[ordered[0]]]

    for entry in ordered[1:]:
        if entry.offset - clusters[-1][-1].offset <= cluster_distance:
            clusters[-1].append(entry)
        else:
            clusters.append([entry])

    deduped: list[MapEntry] = []

    for cluster in clusters:

        best = max(cluster, key=lambda e: _CONFIDENCE_RANK.get(e.confidence, 0))

        if len(cluster) > 1:
            suffix = f"(+{len(cluster) - 1} overlapping match{'es' if len(cluster) > 2 else ''} suppressed)"
            best.detail = f"{best.detail} {suffix}".strip()

        deduped.append(best)

    return deduped


def build_firmware_map(data: bytes, entropy_window: int = 1024, lzma_confidence_threshold: float = 7.0) -> FirmwareMap:
    entries: list[MapEntry] = []

    # 1) фіксовані сигнатури по всьому файлу — вони дешеві, шукаємо одразу
    for scanner in (MagicScanner(), AsciiMarkerScanner()):
        for f in scanner.scan(data):
            entries.append(MapEntry(offset=f.offset, kind=f.name, confidence=f.confidence, detail=f.detail))

    # 2) ентропія по всьому файлу
    points = scan_entropy(data, window=entropy_window)

    # 3) LZMA- та zlib-евристики — тільки в межах high-entropy регіонів
    #    (сильно швидше і точніше; обидва сканери мають високий базовий
    #    рівень випадкових спрацювань на структурованих/малоентропійних
    #    ділянках, де відповідного потоку однаково не буде).
    lzma_scanner = LzmaHeuristicScanner()
    zlib_scanner = ZlibHeuristicScanner()
    for start, end in high_entropy_regions(points, threshold=lzma_confidence_threshold):
        window = data[start:end]

        lzma_entries = [
            MapEntry(offset=start + f.offset, kind=f.name, confidence=f.confidence, detail=f.detail)
            for f in lzma_scanner.scan(window)
        ]
        entries.extend(_dedupe_lzma_findings(lzma_entries))

        zlib_entries = [
            MapEntry(offset=start + f.offset, kind=f.name, confidence=f.confidence, detail=f.detail)
            for f in zlib_scanner.scan(window)
        ]
        entries.extend(_dedupe_lzma_findings(zlib_entries))

    # 4) сирі "невідомі" регіони за класифікацією ентропії (empty/code/compressed/...)
    #    зводимо сусідні вікна одного класу у діапазони, щоб не засмічувати карту
    if points:
        cur_class = classify_region(points[0].entropy)
        cur_start = points[0].offset
        for i in range(1, len(points)):
            cls = classify_region(points[i].entropy)
            if cls != cur_class:
                entries.append(
                    MapEntry(
                        offset=cur_start,
                        kind=f"region:{cur_class}",
                        confidence="low",
                        detail=f"~{points[i].offset - cur_start} bytes",
                    )
                )
                cur_class = cls
                cur_start = points[i].offset
        entries.append(
            MapEntry(
                offset=cur_start,
                kind=f"region:{cur_class}",
                confidence="low",
                detail=f"~{len(data) - cur_start} bytes",
            )
        )

    return FirmwareMap(size=len(data), entropy_points=points, entries=entries)
