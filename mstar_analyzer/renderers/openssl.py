from __future__ import annotations

from ..analyzers.openssl import OpenSSLInfo


def render(summary: OpenSSLInfo) -> None:

    if summary is None:
        return

    print()
    print("OpenSSL analysis")
    print("-" * 70)

    if summary.version:
        print(f"Version : {summary.version}")
    else:
        print("Version : unknown")

    if summary.versions_found:
        print(
            "All versions : "
            + ", ".join(sorted(summary.versions_found))
        )

    if summary.evidence:
        print()
        print("Evidence:")

        for s in summary.evidence[:5]:
            print(f"    {s}")

        if len(summary.evidence) > 5:
            print(f"    ... ({len(summary.evidence)-5} more)")
