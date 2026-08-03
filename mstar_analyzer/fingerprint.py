"""
SDK fingerprinting / firmware similarity (Roadmap.md, "MStar-first
Objectives"; докстрінг SdkSymbolProfile у analyzers/sdk_symbols.py
прямо називає це метою: "якщо назбирати такі профілі з кількох
прошивок різних OEM, з'являється основа для порівняння 'ця прошивка на
N% схожа на CADENA X'").

Не CFG/BinDiff-рівня бінарне порівняння (це окремий, набагато більший
напрямок) — а порівняння вже наявних, структурованих сигналів, які
аналізатор і так рахує для одного прогону:

  - SDK symbol profile (MDrv_/MApi_/HAL_/... — які саме функції SDK
    присутні), по категоріях окремо;
  - Capabilities (детектовані Feature) — множина назв фіч;
  - chip identification (підтверджені моделі SoC);
  - LibC (з урахуванням eCos/eCos Pro пріоритету — те саме
    LIBC_LABEL_PRIORITY, що вже використовує analyzers/runtime.py);
  - eCos package versions.

Similarity — індекс Жаккара (|A∩B| / |A∪B|) на кожному з цих сигналів
окремо; загальний "overall_score" — зважене середнє, вага — власне,
суб'єктивне рішення (задокументовано нижче), а не стандартна формула.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzers.runtime import LIBC_LABEL_PRIORITY
from .firmware_tree import FirmwareNode


@dataclass(slots=True)
class FirmwareFingerprint:

    sdk_symbols: dict[str, set[str]] = field(default_factory=dict)
    capabilities: set[str] = field(default_factory=set)
    chip_models: set[str] = field(default_factory=set)
    libc: str | None = None
    ecos_package_versions: set[str] = field(default_factory=set)


def build_fingerprint(root: FirmwareNode) -> FirmwareFingerprint:

    fp = FirmwareFingerprint()

    for node in root.walk():

        sdk = node.analysis.get("sdk_symbols")

        if sdk is not None:
            for category, names in sdk.symbols.items():
                fp.sdk_symbols.setdefault(category, set()).update(names)

        for feature in node.features:
            fp.capabilities.add(feature.name)

        chip = node.analysis.get("chip_id")

        if chip is not None:
            fp.chip_models.update(chip.confirmed_models)

        runtime = node.analysis.get("runtime")

        if runtime is not None:

            if runtime.libc and (
                fp.libc is None
                or LIBC_LABEL_PRIORITY.get(runtime.libc, 0) > LIBC_LABEL_PRIORITY.get(fp.libc, 0)
            ):
                fp.libc = runtime.libc

            fp.ecos_package_versions.update(runtime.libc_package_versions)

    return fp


def fingerprint_from_dict(data: dict) -> FirmwareFingerprint:
    """
    Зворотне до серіалізації в JSON (json_export.py, ключ
    "fingerprint") — множини на диску зберігаються як списки
    (JSON не має set), тут відновлюємо set() для порівняння.
    """

    return FirmwareFingerprint(
        sdk_symbols={k: set(v) for k, v in (data.get("sdk_symbols") or {}).items()},
        capabilities=set(data.get("capabilities") or []),
        chip_models=set(data.get("chip_models") or []),
        libc=data.get("libc"),
        ecos_package_versions=set(data.get("ecos_package_versions") or []),
    )


@dataclass(slots=True)
class CategorySimilarity:

    jaccard: float
    shared: int
    total: int


@dataclass(slots=True)
class SimilarityResult:

    sdk_symbol_similarity: dict[str, CategorySimilarity] = field(default_factory=dict)
    capabilities_similarity: float = 0.0
    capabilities_shared: int = 0
    capabilities_total: int = 0
    chip_match: bool = False
    shared_chip_models: set[str] = field(default_factory=set)
    libc_match: bool = False
    shared_ecos_versions: set[str] = field(default_factory=set)
    overall_score: float = 0.0


def _jaccard(a: set, b: set) -> float:

    if not a and not b:
        return 1.0

    union = a | b

    return len(a & b) / len(union) if union else 1.0


def compare_fingerprints(a: FirmwareFingerprint, b: FirmwareFingerprint) -> SimilarityResult:

    result = SimilarityResult()

    categories = set(a.sdk_symbols) | set(b.sdk_symbols)

    for category in categories:

        set_a = a.sdk_symbols.get(category, set())
        set_b = b.sdk_symbols.get(category, set())

        result.sdk_symbol_similarity[category] = CategorySimilarity(
            jaccard=_jaccard(set_a, set_b),
            shared=len(set_a & set_b),
            total=len(set_a | set_b),
        )

    result.capabilities_similarity = _jaccard(a.capabilities, b.capabilities)
    result.capabilities_shared = len(a.capabilities & b.capabilities)
    result.capabilities_total = len(a.capabilities | b.capabilities)

    result.shared_chip_models = a.chip_models & b.chip_models
    result.chip_match = bool(a.chip_models and b.chip_models and result.shared_chip_models)

    result.libc_match = bool(a.libc and b.libc and a.libc == b.libc)

    result.shared_ecos_versions = a.ecos_package_versions & b.ecos_package_versions

    sdk_scores = [c.jaccard for c in result.sdk_symbol_similarity.values()]
    sdk_avg = sum(sdk_scores) / len(sdk_scores) if sdk_scores else 0.0

    # Вагова схема нижче — власне рішення, а не стандартна формула:
    # SDK-символи (60%) — найпряміший доказ спільного коду (реальні
    # імена функцій, а не побічний ефект); Capabilities (20%) —
    # вторинний, менш специфічний сигнал (та сама фіча може з'явитись
    # з різних причин); chip/libc (по 10%) — грубі бінарні підказки,
    # корисні для контексту, але сам факт "той самий чип" нічого не
    # каже про схожість коду.
    result.overall_score = (
        sdk_avg * 0.6
        + result.capabilities_similarity * 0.2
        + (1.0 if result.chip_match else 0.0) * 0.1
        + (1.0 if result.libc_match else 0.0) * 0.1
    )

    return result
