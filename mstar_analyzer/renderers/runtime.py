from __future__ import annotations

from ..analyzers.runtime import RuntimeInfo


def render_ecos_packages(ecos_packages: dict[str, set[str]]) -> None:
    """
    Табличний інвентар eCos-пакетів: ІМ'Я пакета -> версія(ї), а не єдиний
    "LibC package version" номер, що приховує, з яких саме пакетів SDK
    він насправді зібраний. Вирівнювання по найдовшій назві пакета —
    самі назви (напр. "services/memalloc/common") довші за типове число
    колонок, тому фіксована ширина тут недоречна.
    """

    if not ecos_packages:
        return

    print()
    print("eCos package inventory:")

    name_width = max(len(name) for name in ecos_packages)

    all_versions: set[str] = set()

    for name in sorted(ecos_packages):
        versions = ", ".join(sorted(ecos_packages[name]))
        all_versions.update(ecos_packages[name])
        print(f"    {name:<{name_width}} {versions}")

    if len(all_versions) == 1:
        (release,) = all_versions
        print(f"    (all observed packages agree — likely eCos release {release})")
    elif len(all_versions) > 1:
        print("    (observed packages do NOT all agree on one version — mixed release, or coincidental path collision)")


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

    render_ecos_packages(summary.ecos_packages)

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