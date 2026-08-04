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

import re
from dataclasses import dataclass

from .entropy import EntropyPoint, classify_region, high_entropy_regions, scan_entropy, sparkline
from .signatures import AsciiMarkerScanner, Finding, Jffs2Scanner, LzmaHeuristicScanner, MagicScanner, ZlibHeuristicScanner


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

    def as_table(self, exclude_kinds: frozenset[str] = frozenset()) -> str:
        """
        exclude_kinds — kind-и, які свідомо НЕ друкуються тут (за
        замовчуванням — жодних, повна зворотна сумісність).

        Призначення: kind-и на кшталт "zlib"/"gzip"/... — це сирі,
        НЕПІДТВЕРДЖЕНІ Stage 2 кандидати. Ця таблиця друкується в
        analyze.py::_run() ДО Stage 5 (build_firmware_map() — крок
        [1/3], аналіз/екстракція — крок [2/3]), тобто за конструкцією
        не може знати, який candidate підтвердився, а який — ні. Той
        самий candidate пізніше з'являється в секції "Findings"
        (render_node_findings(), render.py) ВЖЕ зі статусом
        confirmed/rejected/unresolved і зі згортанням непідтверджених
        у підсумковий рядок замість переліку кожного окремо — там ця
        інформація значно точніша й корисніша. Друкувати candidate-и і
        тут, і там — не просто зайве, а вводить в оману: сира таблиця
        виглядає так само авторитетно, як підтверджений результат,
        хоча (для zlib, зокрема) переважна більшість "кандидатів" —
        типово статистичний шум 2-байтного заголовка (детально —
        ZlibHeuristicScanner, signatures.py).
        """
        lines = [f"{'Offset':>10}   {'Type':<30} {'Confidence':<8} Detail"]
        for e in sorted(self.entries, key=lambda x: x.offset):
            if e.kind in exclude_kinds:
                continue
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


_JFFS2_LEN_RE = re.compile(r"len=(\d+)")


def _group_jffs2_nodes(findings: list[Finding], gap_tolerance: int = 32) -> list[MapEntry]:
    """
    Jffs2Scanner (signatures.py) повертає ОДНУ Finding на кожен окремий
    JFFS2-вузол (inode/dirent/padding-заголовок, кожен з власним CRC32).
    Реальний JFFS2-розділ складається з тисяч таких вузлів підряд — якби
    ми клали їх у firmware map по одному рядку на вузол, реальний
    firmware-образ з JFFS2-розділом перетворив би "Firmware map" на
    список у тисячі рядків, і жоден з них окремо не був би корисніший за
    сусідній (сирий заголовок вузла сам по собі каже лише "тут JFFS2",
    не більше).

    Натомість групуємо суміжні вузли (кінець вузла N ~ початок вузла
    N+1, з допуском `gap_tolerance` байт на padding/вирівнювання) в один
    "JFFS2 filesystem region" запис із діапазоном офсетів і кількістю
    вузлів. Це той сигнал, який реально потрібен на цьому етапі: "тут є
    JFFS2-розділ розміром ~X, від offset Y" — досить, щоб піти дослідити
    його вручну чи чекати на повний парсер (Stage 3, ще не реалізовано;
    на відміну від SquashFS цей проект поки НЕ вміє розпаковувати
    JFFS2 — лише виявляти межі).

    totlen кожного вузла беремо з `finding.detail` (формат
    "type=0x.... len=N", Jffs2Scanner) — той самий підхід, що вже
    використовує detectors/code_caves.py для "region:code"-записів.
    """

    if not findings:
        return []

    ordered = sorted(findings, key=lambda f: f.offset)

    def _end(f: Finding) -> int:
        match = _JFFS2_LEN_RE.search(f.detail)
        length = int(match.group(1)) if match else Jffs2Scanner.HEADER_SIZE
        return f.offset + length

    regions: list[list[Finding]] = [[ordered[0]]]
    region_end = _end(ordered[0])

    for finding in ordered[1:]:
        if finding.offset <= region_end + gap_tolerance:
            regions[-1].append(finding)
        else:
            regions.append([finding])
        region_end = max(region_end, _end(finding))

    entries: list[MapEntry] = []

    for region in regions:
        start = region[0].offset
        end = max(_end(f) for f in region)
        count = len(region)
        entries.append(
            MapEntry(
                offset=start,
                kind="JFFS2 filesystem region",
                confidence="high",
                detail=f"{count} node{'s' if count != 1 else ''}, ~{end - start} bytes (not extracted)",
            )
        )

    return entries


def build_firmware_map(data: bytes, entropy_window: int = 1024, lzma_confidence_threshold: float = 7.0) -> FirmwareMap:
    entries: list[MapEntry] = []

    # 1) фіксовані сигнатури по всьому файлу — вони дешеві, шукаємо одразу
    for scanner in (MagicScanner(), AsciiMarkerScanner()):
        for f in scanner.scan(data):
            entries.append(MapEntry(offset=f.offset, kind=f.name, confidence=f.confidence, detail=f.detail))

    # 2) JFFS2 — теж по всьому файлу (Jffs2Scanner тепер швидкий, див.
    #    signatures.py: iter_find() замість посимвольного Python-циклу,
    #    ~0.03с/32МБ проти ~3с раніше). Один реальний розділ JFFS2 — це
    #    тисячі суміжних вузлів; групуємо їх у "JFFS2 filesystem region",
    #    інакше карта потонула б у рядках на кожен окремий inode/dirent.
    entries.extend(_group_jffs2_nodes(Jffs2Scanner().scan(data)))

    # 3) ентропія по всьому файлу
    points = scan_entropy(data, window=entropy_window)

    # 4) LZMA- та zlib-евристики — тільки в межах high-entropy регіонів
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

    # 5) сирі "невідомі" регіони за класифікацією ентропії (empty/code/compressed/...)
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
