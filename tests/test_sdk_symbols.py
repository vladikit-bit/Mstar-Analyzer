"""
Регресійні тести для renderers/sdk_symbols.py.

Категорії без розбивки на підсистеми (lua_/MsOS_/luaL_ — див.
analyzers/sdk_symbols.py PATTERNS) раніше друкували ЛИШЕ загальний
count і нічого більше — хоча плаский список символів
(SdkSymbolProfile.symbols[category]) уже існував і просто ніколи не
показувався в рендері. Підтверджено реальним звітом користувача:
"lua_         31" / "MsOS_        27" без жодного прикладу символу.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from mstar_analyzer.analyzers.sdk_symbols import SdkSymbolProfile
from mstar_analyzer.renderers.sdk_symbols import render


def _render(summary: SdkSymbolProfile) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        render(summary)
    return buf.getvalue()


class FlatCategoryFallbackTests(unittest.TestCase):

    def test_category_without_subsystems_shows_example_symbols(self):
        profile = SdkSymbolProfile()
        profile.counts = {"lua_": 3}
        profile.symbols = {"lua_": {"lua_close", "lua_concat", "lua_getinfo"}}
        profile.subsystems = {}

        output = _render(profile)

        self.assertIn("lua_", output)
        self.assertIn("lua_close", output)

    def test_examples_truncated_with_more_count_for_large_flat_category(self):
        profile = SdkSymbolProfile()
        symbols = {f"lua_fn{i}" for i in range(10)}
        profile.counts = {"lua_": len(symbols)}
        profile.symbols = {"lua_": symbols}
        profile.subsystems = {}

        output = _render(profile)

        self.assertIn("more)", output)

    def test_category_with_subsystems_still_shows_breakdown_not_flat_list(self):
        # Регресія: категорії, що ВЖЕ мали розбивку (MDrv_/HAL_/...),
        # не повинні почати показувати ще й плаский список поверх неї.
        profile = SdkSymbolProfile()
        profile.counts = {"MDrv_": 2}
        profile.symbols = {"MDrv_": {"MDrv_GE_SetBlt", "MDrv_GOP_Init"}}
        profile.subsystems = {"MDrv_": {"GE": {"MDrv_GE_SetBlt"}, "GOP": {"MDrv_GOP_Init"}}}

        output = _render(profile)

        self.assertIn("GE (1)", output)
        self.assertIn("GOP (1)", output)

    def test_category_with_no_symbols_at_all_does_not_crash(self):
        profile = SdkSymbolProfile()
        profile.counts = {"lua_": 0}
        profile.symbols = {}
        profile.subsystems = {}

        output = _render(profile)  # не повинно кидати виняток
        self.assertIn("lua_", output)


if __name__ == "__main__":
    unittest.main()
