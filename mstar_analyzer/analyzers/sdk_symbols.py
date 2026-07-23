from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding, is_signal_quality


# Кожен запис: (категорія, regex, чи regex має групу підсистеми).
#
# MDrv_/MApi_/HAL_/Cyg_/app* мають стійку конвенцію
# "PREFIX_ПІДСИСТЕМА_дія" — підсистема одразу видна з самого імені
# (MDrv_GE_SetBlt -> GE, cyg_thread_create -> thread, appPvr -> Pvr).
# MsOS_/lua_/luaL_ такої конвенції не мають (MsOS_CreateTask —
# "Create" це дія, а не підсистема), тому лишаються плоскими
# категоріями без розбивки.
#
# НЕ re.I для MDrv_/MApi_/app* — так само, як у detectors/features.py:
# ці префікси в реальному SDK завжди у фіксованому регістрі, і
# case-insensitive пошук лише додав би шум із непроявлених рядків
# (той самий клас багу, що вже виправлявся для "GE"/"MIU").
PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    ("MDrv_", re.compile(r"\bMDrv_([A-Za-z0-9]+)_[A-Za-z0-9_]+\b"), True),
    ("MApi_", re.compile(r"\bMApi_([A-Za-z0-9]+)_[A-Za-z0-9_]+\b"), True),
    ("HAL_", re.compile(r"\bHAL_([A-Za-z0-9]+)_[A-Za-z0-9_]+\b", re.I), True),
    ("MsOS_", re.compile(r"\bMsOS_[A-Za-z0-9_]+\b"), False),
    # eCos kernel API — cyg_thread_*, cyg_mutex_*, cyg_scheduler_*, ... —
    # "об'єкт ядра" одразу за префіксом і є природною підсистемою.
    ("Cyg_/cyg_", re.compile(r"\b[Cc]yg_([A-Za-z0-9]+)_[A-Za-z0-9_]*\b"), True),
    # lua_ (сам VM API: lua_pcall, lua_getinfo, ...) і luaL_ (auxiliary
    # library: luaL_newstate, luaL_loadstring, ...) — різні шари одного
    # й того ж Lua API, тому окремі категорії, а не одна змішана.
    ("lua_", re.compile(r"\blua_[A-Za-z0-9_]+\b"), False),
    ("luaL_", re.compile(r"\bluaL_[A-Za-z0-9_]+\b"), False),
    # appZapper, appPvr, appDevMgr, ... — MStar-специфічний app-layer шар;
    # сама назва додатку (Pvr, Zapper, DevMgr) і є "підсистемою".
    ("app*", re.compile(r"\bapp([A-Z][A-Za-z0-9]*)\b"), True),
)


@dataclass
class SdkSymbolProfile:
    """
    "Профіль SDK" — статистика реальних ідентифікаторів MDrv_/MApi_/...,
    знайдених серед рядків, згрупована за підсистемами там, де назва це
    дозволяє (MDrv_GE_* -> GE, cyg_thread_* -> thread, appPvr -> Pvr).

    Це саме той "довідник по MStar SDK", про який йшлося в первісному
    обговоренні архітектури: якщо назбирати такі профілі з кількох
    прошивок різних OEM, з'являється основа для порівняння "ця
    прошивка на N% схожа на CADENA X" — поки на рівні множини символів
    (і тепер підсистем), а не повного CFG/BinDiff-порівняння.
    """

    counts: dict[str, int] = field(default_factory=dict)
    symbols: dict[str, set[str]] = field(default_factory=dict)
    # категорія -> підсистема -> символи. Заповнюється лише для
    # категорій, де регекс має групу підсистеми (див. PATTERNS вище).
    subsystems: dict[str, dict[str, set[str]]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def analyze_sdk_symbols(strings: Iterable[StringFinding]) -> SdkSymbolProfile | None:

    profile = SdkSymbolProfile()

    for s in strings:

        if not is_signal_quality(s.text):
            continue

        for category, pattern, has_subsystem in PATTERNS:

            for match in pattern.finditer(s.text):

                name = match.group(0)

                bucket = profile.symbols.setdefault(category, set())

                if name in bucket:
                    continue

                bucket.add(name)

                profile.counts[category] = profile.counts.get(category, 0) + 1

                if has_subsystem:

                    subsystem = match.group(1)

                    sub_bucket = (
                        profile.subsystems
                        .setdefault(category, {})
                        .setdefault(subsystem, set())
                    )

                    sub_bucket.add(name)

    if not profile.counts:
        return None

    return profile
