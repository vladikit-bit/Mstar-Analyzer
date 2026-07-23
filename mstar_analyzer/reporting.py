from __future__ import annotations

from dataclasses import dataclass, field

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