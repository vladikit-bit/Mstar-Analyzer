from __future__ import annotations

from dataclasses import dataclass, field

from .detectors.features import FEATURE_CATEGORIES
from .firmware_tree import FirmwareNode

@dataclass(slots=True)
class OpenSSLSummary:

    versions: set[str] = field(default_factory=set)
    nodes: list[str] = field(default_factory=list)

    detected: bool = False


def collect_openssl(root: FirmwareNode) -> OpenSSLSummary | None:

    summary = OpenSSLSummary()

    for node in root.walk():

        info = node.analysis.get("openssl")

        if info is None:
            continue

        summary.detected = True
        summary.versions.update(info.versions_found)
        summary.nodes.append(node.display_path)

    if not summary.detected:
        return None

    return summary


@dataclass(slots=True)
class FFmpegSummary:

    version: str | None = None

    uses_openssl: bool = False

    protocols: set[str] = field(default_factory=set)

    demuxers: set[str] = field(default_factory=set)

    parsers: set[str] = field(default_factory=set)

    filters: set[str] = field(default_factory=set)

    bsfs: set[str] = field(default_factory=set)

    muxers: set[str] = field(default_factory=set)

    decoders: set[str] = field(default_factory=set)

    encoders: set[str] = field(default_factory=set)

    enabled: set[str] = field(default_factory=set)

    disabled_groups: set[str] = field(default_factory=set)

    disabled_options: set[str] = field(default_factory=set)

    nodes: list[str] = field(default_factory=list)

def collect_ffmpeg(root: FirmwareNode) -> FFmpegSummary | None:

    summary = FFmpegSummary()

    for node in root.walk():

        info = node.analysis.get("ffmpeg")

        if info is None:
            continue

        if summary.version is None and info.version:
            summary.version = info.version

        summary.uses_openssl |= info.uses_openssl

        summary.protocols.update(info.protocols)
        summary.demuxers.update(info.demuxers)
        summary.parsers.update(info.parsers)
        summary.filters.update(info.filters)
        summary.bsfs.update(info.bsfs)
        summary.muxers.update(info.muxers)
        summary.decoders.update(info.decoders)
        summary.encoders.update(info.encoders)

        summary.enabled.update(info.enabled)

        summary.disabled_groups.update(
            info.disabled_groups
        )

        summary.disabled_options.update(
            info.disabled_options
        )

        summary.nodes.append(node.display_path)

    if (
        summary.version is None
        and
        not summary.protocols
        and
        not summary.demuxers
        and
        not summary.parsers
        and
        not summary.filters
        and
        not summary.bsfs
        and
        not summary.muxers
        and
        not summary.decoders
        and
        not summary.encoders
    ):
        return None

    return summary


@dataclass(slots=True)
class RuntimeSummary:

    libc: str | None = None
    libc_package_versions: set[str] = field(default_factory=set)
    ecos_packages: dict[str, set[str]] = field(default_factory=dict)
    architecture: str | None = None
    compiler: str | None = None
    nodes: list[str] = field(default_factory=list)


def collect_runtime(root: FirmwareNode) -> RuntimeSummary | None:

    summary = RuntimeSummary()

    for node in root.walk():

        info = node.analysis.get("runtime")

        if info is None:
            continue

        if summary.libc is None and info.libc:
            summary.libc = info.libc

        summary.libc_package_versions.update(info.libc_package_versions)

        for pkg_name, versions in info.ecos_packages.items():
            summary.ecos_packages.setdefault(pkg_name, set()).update(versions)

        if summary.architecture is None and info.architecture:
            summary.architecture = info.architecture

        if summary.compiler is None and info.compiler:
            summary.compiler = info.compiler

        if info.libc or info.architecture or info.compiler:
            summary.nodes.append(node.display_path)

    if (
        summary.libc is None
        and summary.architecture is None
        and summary.compiler is None
    ):
        return None

    return summary


@dataclass(slots=True)
class LibpngSummary:

    versions: set[str] = field(default_factory=set)
    nodes: list[str] = field(default_factory=list)


def collect_libpng(root: FirmwareNode) -> LibpngSummary | None:
    """
    На відміну від OpenSSL/FFmpeg (окремі analyzers/*), libpng наразі
    виявляється лише як побічний ефект object_analyzer.analyze_fake_png()
    (реальних .png у флеші й не очікується — це радше залишки
    error-рядків самої бібліотеки). Тому збираємо не з node.analysis,
    а безпосередньо з node.objects.
    """

    summary = LibpngSummary()

    for node in root.walk():

        for obj in node.objects:

            if obj.metadata.get("classification") != "libpng_resource":
                continue

            version = obj.metadata.get("embedded_version")

            if version:
                summary.versions.add(version)

            if node.display_path not in summary.nodes:
                summary.nodes.append(node.display_path)

    if not summary.nodes:
        return None

    return summary


@dataclass(slots=True)
class CapabilityEntry:

    name: str
    confidence: str    # найкраща (найвища) confidence, що зустрілась деінде в дереві
    score: int         # відповідний їй score
    nodes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CapabilitySummary:

    # категорія -> список фіч у ній (уже відсортований за спаданням score)
    by_category: dict[str, list[CapabilityEntry]] = field(default_factory=dict)


def collect_capabilities(root: FirmwareNode) -> CapabilitySummary | None:
    """
    Наскрізне зведення ВСІХ Feature, знайдених по дереву (node.features —
    те, що вже показує render_node_features на кожному вузлі окремо),
    згруповане за категорією (FEATURE_CATEGORIES у detectors/features.py)
    замість розкиданого по вузлах списку. Те саме, про що просили в
    кількох рев'ю: "Networking / Streaming / 3D / Dolby одним блоком".

    Одна й та сама feature може зустрітись у кількох вузлах (напр.
    "FFmpeg" і в MBoot, і в Network/streaming module) з РІЗНИМ score —
    зведення бере найсильніший (найвищий score) прояв і перелічує УСІ
    вузли, де вона зустрічалась.
    """

    entries: dict[str, CapabilityEntry] = {}

    for node in root.walk():

        for feature in node.features:

            existing = entries.get(feature.name)

            if existing is None:
                entries[feature.name] = CapabilityEntry(
                    name=feature.name,
                    confidence=feature.confidence,
                    score=feature.score,
                    nodes=[node.display_path],
                )
                continue

            if node.display_path not in existing.nodes:
                existing.nodes.append(node.display_path)

            if feature.score > existing.score:
                existing.score = feature.score
                existing.confidence = feature.confidence

    if not entries:
        return None

    summary = CapabilitySummary()

    for entry in entries.values():
        category = FEATURE_CATEGORIES.get(entry.name, "Other")
        summary.by_category.setdefault(category, []).append(entry)

    for category_entries in summary.by_category.values():
        category_entries.sort(key=lambda e: -e.score)

    return summary