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

        if subsystems:

            for subsystem, names in sorted(subsystems.items(), key=lambda kv: -len(kv[1])):

                examples = sorted(names)[:MAX_EXAMPLES]
                more = len(names) - len(examples)

                line = f"    {subsystem} ({len(names)}): " + ", ".join(examples)

                if more > 0:
                    line += f", ... (+{more} more)"

                print(line)

            continue

        # Категорії без розбивки на підсистеми (lua_/MsOS_/luaL_ — див.
        # коментар над PATTERNS у analyzers/sdk_symbols.py: у їхній
        # конвенції немає окремого "підсистемного" сегмента імені).
        # Раніше тут не друкувалось НІЧОГО, крім самого count вище —
        # хоча плаский список символів (summary.symbols[category]) уже
        # існував і просто ніколи не показувався.
        names = summary.symbols.get(category)

        if not names:
            continue

        examples = sorted(names)[:MAX_EXAMPLES]
        more = len(names) - len(examples)

        line = "    " + ", ".join(examples)

        if more > 0:
            line += f", ... (+{more} more)"

        print(line)

    print()
    print(f"Total distinct symbols : {summary.total}")
