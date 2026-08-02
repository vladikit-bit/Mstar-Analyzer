from __future__ import annotations

from ..analyzers.chip_id import ChipIdentification


def render(summary: ChipIdentification) -> None:

    if summary is None:
        return

    print()
    print("Chip identification")
    print("-" * 70)

    if summary.confirmed_models:
        print("SoC model     : " + ", ".join(sorted(summary.confirmed_models)))

    if summary.unconfirmed_models:
        print(
            "Possible SoC  : "
            + ", ".join(sorted(summary.unconfirmed_models))
            + "  (known MStar series prefix, not directly confirmed in this firmware's data)"
        )

    if summary.board_identifiers:
        print("Board string  : " + ", ".join(sorted(summary.board_identifiers)))
