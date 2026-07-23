from __future__ import annotations

from ..analyzers.sdk_symbols import SdkSymbolProfile

# Скільки прикладів символів показувати на підсистему/категорію —
# більше просто засмічує звіт (реальні прошивки легко дають по 400+
# MDrv_ символів).
MAX_EXAMPLES = 4


def render(summary: SdkSymbolProfile) -> None:

    print()
    print("SDK symbol profile")
    print("-" * 70)

    for category, count in sorted(summary.counts.items(), key=lambda kv: -kv[1]):

        print(f"{category:<12} {count}")

        subsystems = summary.subsystems.get(category)

        if not subsystems:
            continue

        for subsystem, names in sorted(subsystems.items(), key=lambda kv: -len(kv[1])):

            examples = sorted(names)[:MAX_EXAMPLES]
            more = len(names) - len(examples)

            line = f"    {subsystem} ({len(names)}): " + ", ".join(examples)

            if more > 0:
                line += f", ... (+{more} more)"

            print(line)

    print()
    print(f"Total distinct symbols : {summary.total}")
