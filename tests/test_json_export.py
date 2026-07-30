"""
Регресійні тести для json_export.py.

Два окремі приводи для цих тестів:

1. build_json_report() раніше не містив жодних метаданих про сам звіт
   (версія формату/інструмента, час генерації) — споживачі назовні
   (diff-тули, БД, скрипти) не мали як відрізнити один формат від іншого.

2. Плоский словник "nodes" був ключований за display_path, а
   classify_node() призначає label за фіксованою таблицею правил — два
   РІЗНІ вузли одного дерева можуть отримати ІДЕНТИЧНИЙ display_path
   (напр. дві незалежні "OpenSSL library" гілки). Старий код у такому
   випадку мовчки губив один з двох вузлів під час експорту.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.json_export import SCHEMA_VERSION, build_json_report


def _node(name: str, label: str, parent: FirmwareNode | None = None) -> FirmwareNode:
    node = FirmwareNode(name=name, offset=0, data=b"\x00" * 4, label=label)
    if parent is not None:
        parent.add_child(node)
    return node


class ReportMetadataTests(unittest.TestCase):

    def test_report_has_schema_and_scanner_metadata(self):
        root = _node("firmware.bin", "firmware.bin")
        report = build_json_report(root)

        self.assertEqual(report["schema_version"], SCHEMA_VERSION)
        self.assertIsInstance(report["scanner_version"], str)
        self.assertTrue(report["scanner_version"])
        self.assertIn("generated_at", report)
        # ISO-8601 з таймзоною (UTC) — має розбиратись без додаткових домовленостей.
        self.assertRegex(report["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class NodeIdentityCollisionTests(unittest.TestCase):

    def test_sibling_nodes_with_identical_label_both_present_in_flat_nodes(self):
        root = _node("firmware.bin", "firmware.bin")
        child_a = _node("lzma-alone", "OpenSSL library", parent=root)
        child_b = _node("gzip", "OpenSSL library", parent=root)

        # Передумова тесту: display_path у цих двох вузлів справді
        # ідентичний (інакше сам тест нічого не перевіряє).
        self.assertEqual(child_a.display_path, child_b.display_path)

        report = build_json_report(root)

        self.assertEqual(len(report["nodes"]), 3)  # root + 2 children, жоден не загублений

        offsets_or_names = {
            entry["name"] for entry in report["nodes"].values()
        }
        self.assertIn("lzma-alone", offsets_or_names)
        self.assertIn("gzip", offsets_or_names)

    def test_flat_nodes_and_tree_share_the_same_ids(self):
        root = _node("firmware.bin", "firmware.bin")
        _node("child", "child", parent=root)

        report = build_json_report(root)

        tree_ids = {report["tree"]["id"]} | {c["id"] for c in report["tree"]["children"]}
        flat_ids = set(report["nodes"].keys())

        self.assertEqual(tree_ids, flat_ids)


if __name__ == "__main__":
    unittest.main()
