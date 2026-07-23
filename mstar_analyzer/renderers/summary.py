from __future__ import annotations

from ..reporting import (
    FFmpegSummary,
    LibpngSummary,
    OpenSSLSummary,
    RuntimeSummary,
    collect_ffmpeg,
    collect_libpng,
    collect_openssl,
    collect_runtime,
)
from ..firmware_tree import FirmwareNode


def render_cross_tree_summary(root: FirmwareNode) -> None:
    """
    "Наскрізне" зведення по всьому дереву прошивки — на відміну від
    per-node секцій нижче, тут видно, наприклад, що OpenSSL 0.9.8o
    зустрічається у двох різних вузлах одразу, без потреби гортати
    весь звіт вручну. Це саме той "довідник по прошивці", про який
    йшлося в обговоренні архітектури проєкту.

    Runtime іде першим — це найбільш "фундаментальний" факт про
    прошивку (яка ОС/архітектура/toolchain), решта — конкретні
    бібліотеки й версії поверх нього.
    """

    runtime = collect_runtime(root)
    openssl = collect_openssl(root)
    ffmpeg = collect_ffmpeg(root)
    libpng = collect_libpng(root)

    if runtime is None and openssl is None and ffmpeg is None and libpng is None:
        return

    print()
    print("Cross-tree summary")
    print("-" * 70)

    if runtime is not None:
        _render_runtime(runtime)

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

    for path in summary.nodes:
        print(f"    {path}")


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
