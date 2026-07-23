from __future__ import annotations

from ..analyzers.ffmpeg import FFmpegInfo


def render(summary: FFmpegInfo) -> None:

    if summary is None:
        return

    print()
    print("FFmpeg analysis")
    print("-" * 70)

    if summary.version:
        print(f"Version : {summary.version}")

    if summary.uses_openssl:
        print("TLS backend : OpenSSL")

    if summary.protocols:
        print(
            "Protocols : "
            + ", ".join(sorted(summary.protocols))
        )

    if summary.demuxers:
        print(
            "Demuxers : "
            + ", ".join(sorted(summary.demuxers))
        )

    if summary.parsers:
        print(
            "Parsers : "
            + ", ".join(sorted(summary.parsers))
        )

    if summary.filters:
        print(
            "Filters : "
            + ", ".join(sorted(summary.filters))
        )

    if summary.disabled_groups:
        print(
            "Disabled codec groups : "
            + ", ".join(sorted(summary.disabled_groups))
        )

    if summary.disabled_options:
        print(
            "Disabled options : "
            + ", ".join(sorted(summary.disabled_options))
        )

    if summary.enabled:
        print(
            "Other enabled : "
            + ", ".join(sorted(summary.enabled))
        )

    if summary.bsfs:
        print(
            "Bitstream filters : "
            + ", ".join(sorted(summary.bsfs))
        )

    if summary.muxers:
        print(
            "Muxers : "
            + ", ".join(sorted(summary.muxers))
        )

    if summary.decoders:
        print(
            "Decoders : "
            + ", ".join(sorted(summary.decoders))
        )

    if summary.encoders:
        print(
            "Encoders : "
            + ", ".join(sorted(summary.encoders))
        )
    