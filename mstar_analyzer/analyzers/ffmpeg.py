from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding


VERSION_RE = re.compile(
    r"FFMPEG\s+VERSION\s*:\s*([0-9.]+)",
    re.I,
)

ENABLE_RE = re.compile(
    r"--enable-([a-z0-9_-]+)(?:=([a-z0-9_.+-]+))?",
    re.I,
)

DISABLE_RE = re.compile(
    r"--disable-([a-z0-9_-]+)",
    re.I,
)

@dataclass(slots=True)
class FFmpegInfo:

    version: str | None = None

    uses_openssl: bool = False

    protocols: set[str] = field(default_factory=set)

    demuxers: set[str] = field(default_factory=set)

    parsers: set[str] = field(default_factory=set)

    filters: set[str] = field(default_factory=set)

    bsfs: set[str] = field(default_factory=set)

    muxers: set[str] = field(default_factory=set)

    enabled: set[str] = field(default_factory=set)

    disabled_groups: set[str] = field(default_factory=set)

    disabled_options: set[str] = field(default_factory=set)

    decoders: set[str] = field(default_factory=set)

    encoders: set[str] = field(default_factory=set)

    evidence: list[str] = field(default_factory=list)


def analyze_ffmpeg(
    strings: Iterable[StringFinding],
) -> FFmpegInfo | None:

    info = FFmpegInfo()

    for s in strings:

        matched = False

        m = VERSION_RE.search(s.text)

        if m:
            info.version = m.group(1)
            matched = True

        for match in ENABLE_RE.finditer(s.text):

            matched = True

            kind = match.group(1).lower()
            value = match.group(2)

            if value is None:

                if kind == "openssl":
                    info.uses_openssl = True
                else:
                    info.enabled.add(kind)

                continue

            value = value.lower()

            if kind == "protocol":
                info.protocols.add(value)

            elif kind == "demuxer":
                info.demuxers.add(value)

            elif kind == "parser":
                info.parsers.add(value)

            elif kind == "filter":
                info.filters.add(value)

            elif kind == "bsf":
                info.bsfs.add(value)

            elif kind == "muxer":
                info.muxers.add(value)

            elif kind == "decoder":
                info.decoders.add(value)

            elif kind == "encoder":
                info.encoders.add(value)

            else:
                info.enabled.add(f"{kind}={value}")

        for match in DISABLE_RE.finditer(s.text):

            matched = True

            name = match.group(1).lower()

            if name in {
                "encoders",
                "decoders",
                "demuxers",
                "muxers",
                "parsers",
                "protocols",
                "filters",
                "bsfs",
            }:
                info.disabled_groups.add(name)

            else:
                info.disabled_options.add(name)

        if matched:
            info.evidence.append(s.text)
    if (
        info.version is None
        and
        not info.evidence
    ):
        return None

    return info