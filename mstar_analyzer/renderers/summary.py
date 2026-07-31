from __future__ import annotations

from ..reporting import (
    CapabilitySummary,
    FFmpegSummary,
    LibpngSummary,
    OpenSSLSummary,
    RuntimeSummary,
    collect_capabilities,
    collect_ffmpeg,
    collect_libpng,
    collect_openssl,
    collect_runtime,
)
from ..firmware_tree import FirmwareNode
from ..detectors.features import FEATURE_CATEGORY_ORDER, FEATURE_CONFIDENCE_MARKER
from .runtime import render_ecos_packages


def render_cross_tree_summary(root: FirmwareNode) -> None:
    """
    "Наскрізне" зведення по всьому дереву прошивки — на відміну від
    per-node секцій нижче, тут видно, наприклад, що OpenSSL 0.9.8o
    зустрічається у двох різних вузлах одразу, без потреби гортати
    весь звіт вручну. Це саме той "довідник по прошивці", про який
    йшлося в обговоренні архітектури проєкту.

    Runtime іде першим — це найбільш "фундаментальний" факт про
    прошивку (яка ОС/архітектура/toolchain), Capabilities — одразу за
    ним як функціональний огляд ("що вміє"), а решта — конкретні
    бібліотеки й версії поверх нього (доповнюють, а не дублюють
    Capabilities: там є номери версій, яких немає в самому переліку
    можливостей).
    """

    runtime = collect_runtime(root)
    capabilities = collect_capabilities(root)
    openssl = collect_openssl(root)
    ffmpeg = collect_ffmpeg(root)
    libpng = collect_libpng(root)

    if (
        runtime is None
        and capabilities is None
        and openssl is None
        and ffmpeg is None
        and libpng is None
    ):
        return

    print()
    print("Cross-tree summary")
    print("-" * 70)

    if runtime is not None:
        _render_runtime(runtime)

    if capabilities is not None:
        _render_capabilities(capabilities)

    if openssl is not None:
        _render_openssl(openssl)

    if ffmpeg is not None:
        _render_ffmpeg(ffmpeg)

    if libpng is not None:
        _render_libpng(libpng)


def _render_runtime(summary: RuntimeSummary) -> None:

    parts = []

    if summary.compiler:
        parts.append(summary.compiler)

    if summary.architecture:
        parts.append(summary.architecture)

    print("Runtime : " + (", ".join(parts) if parts else "unknown"))

    if summary.libc:
        line = f"    LibC: {summary.libc}"
        if summary.libc_package_versions:
            line += " (package " + ", ".join(sorted(summary.libc_package_versions)) + ")"
        print(line)

    render_ecos_packages(summary.ecos_packages)

    for path in summary.nodes:
        print(f"    {path}")


def _render_capabilities(summary: CapabilitySummary) -> None:

    print()
    print("Capabilities")

    for category in FEATURE_CATEGORY_ORDER:

        entries = summary.by_category.get(category)

        if not entries:
            continue

        print(f"    {category}:")

        for entry in entries:
            marker = FEATURE_CONFIDENCE_MARKER.get(entry.confidence, "?")
            print(f"        {marker} {entry.name}")


def _render_openssl(summary: OpenSSLSummary) -> None:
    versions = ", ".join(sorted(summary.versions)) if summary.versions else "unknown"
    print(f"OpenSSL : {versions}")

    for path in summary.nodes:
        print(f"    {path}")


def _render_ffmpeg(summary: FFmpegSummary) -> None:
    version = summary.version or "unknown"
    print(f"FFmpeg  : {version}")

    if summary.protocols:
        print("    protocols: " + ", ".join(sorted(summary.protocols)))

    if summary.uses_openssl:
        print("    TLS backend: OpenSSL")

    for path in summary.nodes:
        print(f"    {path}")


def _render_libpng(summary: LibpngSummary) -> None:
    versions = ", ".join(sorted(summary.versions)) if summary.versions else "unknown"
    print(f"libpng  : {versions}")

    for path in summary.nodes:
        print(f"    {path}")
