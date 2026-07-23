from __future__ import annotations

from ..analyzers.runtime import RuntimeInfo


def _print_evidence(title: str, evidence: list[str]) -> None:
    if not evidence:
        return

    print()
    print(f"{title} evidence:")

    for s in evidence[:5]:
        print(f"    {s}")

    if len(evidence) > 5:
        print(f"    ... ({len(evidence)-5} more)")


def render(summary: RuntimeInfo) -> None:

    if summary is None:
        return

    print()
    print("Runtime analysis")
    print("-" * 70)

    if summary.compiler:
        print(f"Compiler     : {summary.compiler}")

    if summary.architecture:
        print(f"Architecture : {summary.architecture}")

    if summary.endian:
        print(f"Endian       : {summary.endian}")

    if summary.libc:
        print(f"LibC         : {summary.libc}")

    if summary.libc_package_versions:
        # НЕ "версія ОС" — це версія(ї) конкретних eCos-пакетів,
        # знайдених у шляхах збірки. Зазвичай усі пакети одного релізу
        # мають однакову версію, звідси й формулювання нижче.
        versions = ", ".join(sorted(summary.libc_package_versions))
        label = "package version" if len(summary.libc_package_versions) == 1 else "package versions"
        print(f"LibC {label} : {versions}")

    _print_evidence("Compiler", summary.compiler_evidence)
    if summary.architecture:
        _print_evidence(
    	    "Architecture",
     	    summary.architecture_evidence.get(
                summary.architecture,
                [],
            ),
        )
    _print_evidence("Endian", summary.endian_evidence)
    _print_evidence("LibC", summary.libc_evidence)