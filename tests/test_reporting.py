"""
Регресійні тести для reporting.collect_runtime — крос-дерева агрегація
Runtime-аналізу з кількох вузлів.

Той самий "перший збіг перемагає" баг, що виправлений у
analyzers/runtime.py::analyze_runtime (per-node), існував і тут на рівні
дерева: якщо вузол лише із generic "eCos"-доказом обробляється РАНІШЕ за
вузол зі специфічним "eCos Pro"-доказом, summary.libc міг назавжди
застрягнути на менш точному лейблі.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.analyzers.runtime import analyze_runtime
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.reporting import collect_runtime
from mstar_analyzer.strings import StringFinding


def _node_with_runtime_text(name: str, text: str, parent: FirmwareNode | None = None) -> FirmwareNode:
    node = FirmwareNode(name=name, offset=0, data=b"\x00" * 4, parent=parent)
    node.analysis = {"runtime": analyze_runtime([StringFinding(offset=0, text=text)])}
    if parent is not None:
        parent.children.append(node)
    return node


class CollectRuntimeEcosProTests(unittest.TestCase):

    def test_generic_node_first_pro_node_second_upgrades(self):
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        _node_with_runtime_text("mboot", "/home/x/ecos_os/packages/net/dns/v2_0_1/src/dns.c", root)
        _node_with_runtime_text("app", "/home/x/stb_ecospro/packages/net/tcpip/v2_0_1/src/tcp.c", root)

        summary = collect_runtime(root)
        self.assertEqual(summary.libc, "eCos Pro")

    def test_pro_node_first_generic_node_second_does_not_downgrade(self):
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        _node_with_runtime_text("app", "/home/x/stb_ecospro/packages/net/tcpip/v2_0_1/src/tcp.c", root)
        _node_with_runtime_text("mboot", "/home/x/ecos_os/packages/net/dns/v2_0_1/src/dns.c", root)

        summary = collect_runtime(root)
        self.assertEqual(summary.libc, "eCos Pro")

    def test_only_generic_evidence_across_tree_stays_plain_ecos(self):
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        _node_with_runtime_text("mboot", "/home/x/ecos_os/packages/net/dns/v2_0_1/src/dns.c", root)

        summary = collect_runtime(root)
        self.assertEqual(summary.libc, "eCos")


if __name__ == "__main__":
    unittest.main()
