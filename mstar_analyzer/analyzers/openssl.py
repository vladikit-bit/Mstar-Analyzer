from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding


VERSION_PATTERNS = [

    # OpenSSL 1.0.2u
    re.compile(
        r"OpenSSL\s+([0-9][0-9A-Za-z._-]*)",
        re.I,
    ),

    # openssl-1.1.1w
    re.compile(
        r"openssl[-_]([0-9][0-9A-Za-z._-]*)",
        re.I,
    ),

    # openssl/v_0_9_8o
    re.compile(
        r"openssl[/\\]v_([0-9_]+[A-Za-z]?)",
        re.I,
    ),

    # openssl-3.0.9.tar.gz
    re.compile(
        r"openssl[-_]([0-9]+\.[0-9]+\.[0-9]+[A-Za-z]?)",
        re.I,
    ),
]



@dataclass(slots=True)
class OpenSSLInfo:

    version: str | None = None

    versions_found: set[str] = field(default_factory=set)

    evidence: list[str] = field(default_factory=list)


def analyze_openssl(
    strings: Iterable[StringFinding],
) -> OpenSSLInfo | None:

    info = OpenSSLInfo()

    for s in strings:

        original = s.text
        text = original.lower()

        is_openssl = (
            "openssl" in text
            or "libssl" in text
            or "libcrypto" in text
    )

        if not is_openssl:
            continue

        info.evidence.append(original)

        for regex in VERSION_PATTERNS:

            m = regex.search(original)

            if not m:
                continue

            version = m.group(1).replace("_", ".")

            info.versions_found.add(version)

            if info.version is None:
                info.version = version

            break

    if not info.evidence:
        return None

    return info
