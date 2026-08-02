"""
SPI Flash layout reconstruction (Roadmap.md, Stage 4 / "MStar-first
Objectives").

Навмисно НЕ парсер якогось конкретного пропрієтарного формату таблиці
розділів — на відміну від DTB/uImage вище, для "MStar SPI flash
partition table" немає жодного публічно задокументованого, перевіреного
джерела (на відміну від Devicetree Specification чи U-Boot image.h), і
вигадувати байтову структуру означало б порушити власний принцип
проєкту "Evidence-based analysis instead of assumptions" (Roadmap.md).

Натомість: СИНТЕЗ уже наявних, окремо підтверджених доказів у єдину,
впорядковану, іменовану карту:

  1. Провалідовані EmbeddedObject кореневого вузла з відомим розміром
     (MBootEnvBlock/DTB/uImage/ELF/...) — "якорі" з точними межами.
  2. Дочірні вузли дерева (успішно розпаковані LZMA/gzip/xz/bzip2
     потоки) — теж "якорі" з точними межами (offset+size вже обчислені
     Stage 5).
  3. Проміжки МІЖ якорями — заповнюються ентропійною класифікацією
     (entropy.py, уже існуючий, протестований механізм) РІВНО того
     діапазону байтів, а не інтерпольовані з грубих fixed-window
     семплів.

Результат — не "вгадана" таблиця розділів, а прозоро виведена мапа:
кожен запис або посилається на конкретний, окремо провалідований
доказ, або чесно позначений як "unclassified" з ентропійною міткою.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .entropy import classify_region, shannon_entropy
from .firmware_tree import FirmwareNode


@dataclass(slots=True)
class FlashRegion:

    start: int
    end: int
    label: str
    source: str        # "object" | "extracted stream" | "entropy"
    confidence: str     # "high" | "low"
    detail: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class FlashLayout:

    total_size: int
    regions: list[FlashRegion] = field(default_factory=list)


def _describe_object(obj) -> str:

    label = f"{obj.kind}: {obj.description}"

    # Скромне збагачення лейбла для kind'ів, де вже є особливо
    # інформативні metadata-поля — не намагаємось узагальнити це під
    # усі можливі kind, лише ті два, де це прямо додає цінності без
    # додаткового вгадування.
    if obj.kind == "uImage" and obj.metadata.get("name"):
        label += f" ({obj.metadata['name']!r}, {obj.metadata.get('os', '?')}/{obj.metadata.get('architecture', '?')})"

    elif obj.kind == "DTB":
        root_props = obj.metadata.get("root_properties") or {}
        if root_props.get("model"):
            label += f" (model={root_props['model']!r})"

    return label


def _object_anchors(root: FirmwareNode) -> list[FlashRegion]:

    anchors: list[FlashRegion] = []

    for obj in root.objects:

        if not obj.validated or obj.size is None or obj.size <= 0:
            continue

        anchors.append(
            FlashRegion(
                start=obj.offset,
                end=obj.offset + obj.size,
                label=_describe_object(obj),
                source="object",
                confidence="high",
            )
        )

    return anchors


def _child_stream_anchors(root: FirmwareNode) -> list[FlashRegion]:

    anchors: list[FlashRegion] = []

    for child in root.children:

        # child.size — це len(child.data), тобто розмір РОЗПАКОВАНИХ
        # даних, а не скільки СИРИХ (стиснутих) байтів цей потік займає
        # в самому root.data — для карти flash-розкладки нам потрібне
        # саме друге. analyze.py кладе його явно в metadata під час
        # створення дочірнього вузла (result.consumed з Extractor) —
        # якщо раптом відсутнє (напр. вузол створений іншим шляхом),
        # чесно пропускаємо, а не тихо підставляємо неправильне число.
        raw_size = child.metadata.get("raw_consumed_bytes")

        if not isinstance(raw_size, int) or raw_size <= 0:
            continue

        descriptor = child.format or child.node_type or "stream"

        label = f"{descriptor} stream"

        if child.label:
            label += f" → {child.label}"

        anchors.append(
            FlashRegion(
                start=child.offset,
                end=child.offset + raw_size,
                label=label,
                source="extracted stream",
                confidence="high",
            )
        )

    return anchors


def build_flash_layout(root: FirmwareNode) -> FlashLayout:

    total_size = len(root.data)

    anchors = _object_anchors(root) + _child_stream_anchors(root)
    anchors.sort(key=lambda r: r.start)

    regions: list[FlashRegion] = []
    cursor = 0

    for anchor in anchors:

        # Захист від перекриття (у теорії малоймовірне: об'єкти —
        # магічні байти, потоки — стиснені діапазони, різні патерни
        # байтів — але не покладаємось на це мовчки): якщо цей якір
        # починається РАНІШЕ за курсор, просто пропускаємо створення
        # прогалини для нього (сам якір усе одно додасться нижче).
        if anchor.start > cursor:

            gap = root.data[cursor:anchor.start]
            entropy = shannon_entropy(gap)
            regions.append(
                FlashRegion(
                    start=cursor,
                    end=anchor.start,
                    label=f"unclassified ({classify_region(entropy)})",
                    source="entropy",
                    confidence="low",
                    detail=f"entropy={entropy:.2f} bits/byte",
                )
            )

        regions.append(anchor)
        cursor = max(cursor, anchor.end)

    if cursor < total_size:

        gap = root.data[cursor:total_size]
        entropy = shannon_entropy(gap)
        regions.append(
            FlashRegion(
                start=cursor,
                end=total_size,
                label=f"unclassified ({classify_region(entropy)})",
                source="entropy",
                confidence="low",
                detail=f"entropy={entropy:.2f} bits/byte",
            )
        )

    return FlashLayout(total_size=total_size, regions=regions)
