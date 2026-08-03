"""
Регресійні тести для flash_layout.py — синтез уже наявних доказів
(провалідовані об'єкти + розпаковані дочірні потоки + ентропія
прогалин) у суцільну, іменовану карту flash-розкладки.

Ключовий баг, спійманий ще ДО написання формальних тестів (під час
ручної перевірки): child.size — це len(child.data), тобто розмір
РОЗПАКОВАНИХ даних, а не скільки СИРИХ (стиснутих) байтів цей потік
займає в самому root.data. Використання child.size напряму дало б
абсурдно завеликі, такі що виходять за межі файлу, межі регіону.
Виправлено проведенням result.consumed через child.metadata
["raw_consumed_bytes"] (analyze.py) — ці тести це й фіксують.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.detectors.objects import EmbeddedObject
from mstar_analyzer.firmware_map import FirmwareMap, MapEntry
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.flash_layout import build_flash_layout


def _assert_contiguous_coverage(test_case: unittest.TestCase, layout) -> None:
    """Регіони мають суцільно покривати [0, total_size) без прогалин/перекриттів."""
    prev_end = 0
    for region in layout.regions:
        test_case.assertEqual(region.start, prev_end, f"gap or overlap at {region.start}")
        prev_end = region.end
    test_case.assertEqual(prev_end, layout.total_size)


class BasicCoverageTests(unittest.TestCase):

    def test_empty_data_with_no_evidence_is_one_entropy_region(self):
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\xFF" * 200)
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(len(layout.regions), 1)
        self.assertEqual(layout.regions[0].source, "entropy")

    def test_object_anchor_in_the_middle_produces_three_regions(self):
        data = b"\xFF" * 100 + b"X" * 50 + b"\x00" * 80
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=100, size=50, kind="uImage", description="U-Boot legacy image header", validated=True)
        ]
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(len(layout.regions), 3)
        self.assertEqual(layout.regions[1].source, "object")
        self.assertEqual(layout.regions[1].start, 100)
        self.assertEqual(layout.regions[1].end, 150)

    def test_object_anchor_at_the_very_start_produces_no_leading_gap(self):
        data = b"X" * 50 + b"\xFF" * 80
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=0, size=50, kind="DTB", description="Flattened Device Tree", validated=True)
        ]
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(layout.regions[0].source, "object")

    def test_object_anchor_at_the_very_end_produces_no_trailing_gap(self):
        data = b"\xFF" * 80 + b"X" * 50
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=80, size=50, kind="DTB", description="Flattened Device Tree", validated=True)
        ]
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(layout.regions[-1].source, "object")

    def test_unvalidated_objects_are_ignored(self):
        data = b"\xFF" * 200
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=50, size=50, kind="Lua bytecode", description="x", validated=False)
        ]
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(len(layout.regions), 1)  # єдиний, суцільний entropy-регіон

    def test_objects_without_size_are_ignored(self):
        data = b"\xFF" * 200
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=50, size=None, kind="Lua bytecode", description="x", validated=True)
        ]
        layout = build_flash_layout(root)
        self.assertEqual(len(layout.regions), 1)


class ChildStreamSizeCorrectnessTests(unittest.TestCase):
    """
    Регресія на конкретний баг: дочірній регіон мусить використовувати
    raw_consumed_bytes (сирий, стислий "відбиток" у батьківських
    байтах), а НЕ len(child.data) (розмір РОЗПАКОВАНИХ даних — типово
    значно більший і не має жодного стосунку до меж у батьківському
    flash).
    """

    def test_child_region_uses_raw_consumed_bytes_not_decompressed_size(self):
        data = b"\xFF" * 100 + b"C" * 400 + b"\xFF" * 100
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        child = FirmwareNode(
            name="lzma-alone",
            offset=100,
            data=b"D" * 50_000,  # розпаковані дані — набагато більші за сирий "відбиток"
            metadata={"raw_consumed_bytes": 400},
        )
        root.children.append(child)

        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)

        stream_region = next(r for r in layout.regions if r.source == "extracted stream")
        self.assertEqual(stream_region.size, 400)
        self.assertEqual(stream_region.end, 500)

    def test_child_without_raw_consumed_bytes_metadata_is_skipped_not_guessed(self):
        data = b"\xFF" * 200
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        child = FirmwareNode(name="lzma-alone", offset=50, data=b"D" * 5000)  # без metadata
        root.children.append(child)

        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(len(layout.regions), 1)  # дочірній вузол без потрібних метаданих не став якорем

    def test_child_label_included_when_classify_node_assigned_one(self):
        data = b"\xFF" * 100 + b"C" * 100
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        child = FirmwareNode(
            name="lzma-alone", offset=100, data=b"D" * 1000,
            metadata={"raw_consumed_bytes": 100}, label="eCos system image (MBoot)",
        )
        root.children.append(child)

        layout = build_flash_layout(root)
        stream_region = next(r for r in layout.regions if r.source == "extracted stream")
        self.assertIn("eCos system image (MBoot)", stream_region.label)


class LabelEnrichmentTests(unittest.TestCase):

    def test_uimage_label_includes_name_and_os_arch_when_present(self):
        data = b"\xFF" * 100 + b"X" * 50 + b"\xFF" * 50
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(
                offset=100, size=50, kind="uImage", description="U-Boot legacy image header",
                validated=True, metadata={"name": "linux-3.13.0", "os": "Linux", "architecture": "ARM"},
            )
        ]
        layout = build_flash_layout(root)
        obj_region = next(r for r in layout.regions if r.source == "object")
        self.assertIn("linux-3.13.0", obj_region.label)
        self.assertIn("Linux", obj_region.label)
        self.assertIn("ARM", obj_region.label)

    def test_dtb_label_includes_model_when_present(self):
        data = b"\xFF" * 100 + b"X" * 50 + b"\xFF" * 50
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(
                offset=100, size=50, kind="DTB", description="Flattened Device Tree",
                validated=True, metadata={"root_properties": {"model": "mstar,titania"}},
            )
        ]
        layout = build_flash_layout(root)
        obj_region = next(r for r in layout.regions if r.source == "object")
        self.assertIn("mstar,titania", obj_region.label)

    def test_object_without_enrichable_metadata_does_not_crash(self):
        data = b"\xFF" * 100 + b"X" * 50 + b"\xFF" * 50
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=100, size=50, kind="ELF", description="ELF executable", validated=True)
        ]
        layout = build_flash_layout(root)  # не має кидати виняток
        _assert_contiguous_coverage(self, layout)


class OverlapDefenseTests(unittest.TestCase):

    def test_overlapping_anchors_do_not_produce_negative_size_regions(self):
        data = b"X" * 200
        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        root.objects = [
            EmbeddedObject(offset=0, size=100, kind="DTB", description="x", validated=True),
            EmbeddedObject(offset=50, size=100, kind="uImage", description="y", validated=True),  # перекриває перший
        ]
        layout = build_flash_layout(root)
        for region in layout.regions:
            self.assertGreaterEqual(region.size, 0)


class RealPipelineIntegrationTests(unittest.TestCase):
    """
    На відміну від решти тестів вище (ізольований build_flash_layout з
    вручну зібраними вузлами) — це наскрізна перевірка через СПРАВЖНІЙ
    analyze_node(), що й виявила потребу в цьому фіксі: без явного
    проведення result.consumed у child.metadata, дочірній регіон
    отримав би розмір РОЗПАКОВАНИХ даних замість сирого "відбитка" в
    батьківському flash. gzip навмисно (а не lzma-alone): детектується
    напряму за magic bytes (MagicScanner), а не лише всередині
    high-entropy вікон — надійніше для маленького тестового файлу.
    """

    def test_real_gzip_extraction_produces_correct_raw_footprint_in_layout(self):
        import gzip as gzip_module

        from mstar_analyzer.analyze import analyze_node

        payload = b"eCos kernel image data " * 200  # розпаковані дані — набагато більші за стиснуті
        compressed = gzip_module.compress(payload)

        data = b"\xFF" * 600 + compressed + b"\xFF" * 600

        root = FirmwareNode(name="flash.bin", offset=0, data=data)
        analyze_node(root)

        self.assertEqual(len(root.children), 1)
        child = root.children[0]
        self.assertIn("raw_consumed_bytes", child.metadata)
        # Розпаковані дані мають бути значно більшими за сирий "відбиток" —
        # інакше цей тест сам собі нічого не доводить.
        self.assertGreater(len(child.data), child.metadata["raw_consumed_bytes"])

        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)

        stream_region = next(r for r in layout.regions if r.source == "extracted stream")
        self.assertEqual(stream_region.size, child.metadata["raw_consumed_bytes"])
        self.assertLess(stream_region.size, len(payload))  # НЕ розмір розпакованих даних


class Jffs2AnchorTests(unittest.TestCase):
    """
    "JFFS2 filesystem region" живе в root.firmware_map.entries — окремо
    від root.objects/root.children, які раніше були ЄДИНИМИ джерелами
    якорів тут. Без _jffs2_anchors() такий регіон мовчки провалювався б
    в "unclassified", попри те, що в сирій "Firmware map" таблиці він
    уже показаний коректно (firmware_map.py::_group_jffs2_nodes()).
    """

    def _root_with_jffs2_entry(self, offset: int, detail: str, total_size: int = 400) -> FirmwareNode:
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\xFF" * total_size)
        root.firmware_map = FirmwareMap(
            size=total_size,
            entropy_points=[],
            entries=[MapEntry(offset=offset, kind="JFFS2 filesystem region", confidence="high", detail=detail)],
        )
        return root

    def test_jffs2_region_becomes_a_flash_layout_anchor(self):
        root = self._root_with_jffs2_entry(offset=100, detail="30 nodes, ~150 bytes (not extracted)")
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)

        jffs2_regions = [r for r in layout.regions if "JFFS2" in r.label]
        self.assertEqual(len(jffs2_regions), 1, layout.regions)
        self.assertEqual(jffs2_regions[0].start, 100)
        self.assertEqual(jffs2_regions[0].end, 250)  # 100 + 150
        self.assertEqual(jffs2_regions[0].source, "object")

    def test_no_firmware_map_means_no_jffs2_anchors(self):
        # root.firmware_map лишається None (default) — не повинно падати.
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\xFF" * 200)
        layout = build_flash_layout(root)
        _assert_contiguous_coverage(self, layout)
        self.assertEqual(len(layout.regions), 1)
        self.assertEqual(layout.regions[0].source, "entropy")

    def test_entry_with_unparseable_detail_is_skipped_not_crashed(self):
        root = self._root_with_jffs2_entry(offset=100, detail="something without a byte count")
        layout = build_flash_layout(root)  # не повинно кинути виняток
        _assert_contiguous_coverage(self, layout)
        self.assertFalse([r for r in layout.regions if "JFFS2" in r.label])


if __name__ == "__main__":
    unittest.main()
