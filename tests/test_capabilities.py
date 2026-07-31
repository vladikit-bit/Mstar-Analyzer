"""
Регресійні тести для Capabilities (reporting.collect_capabilities +
renderers/summary._render_capabilities) — крос-дерева зведення всіх
node.features за категоріями, про яке просили в кількох рев'ю
("Networking / Streaming / 3D / Dolby одним блоком").
"""

from __future__ import annotations

import io
import re
import unittest
from contextlib import redirect_stdout

from mstar_analyzer.detectors.features import Feature, Signature
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.reporting import collect_capabilities
from mstar_analyzer.renderers.summary import render_cross_tree_summary


def _feature_plain(name: str, score: int, confidence: str) -> Feature:
    # Feature.confidence — обчислювана властивість (score_to_confidence),
    # тож напряму її не підмінити; будуємо Feature із таким score, який
    # ДІЙСНО відповідає бажаній тарифній категорії (HIGH/MEDIUM/LOW) —
    # asserted нижче, щоб тест сам собі не міг збрехати про фікстуру.
    sig = Signature(feature=name, pattern=re.compile("x"), weight=score)
    f = Feature(name=name, score=score, evidence="ev", evidences={"ev"}, best_signature=sig)
    assert f.confidence == confidence, f"score {score} maps to {f.confidence}, not {confidence}"
    return f


def _node_with_features(name: str, *features: Feature) -> FirmwareNode:
    node = FirmwareNode(name=name, offset=0, data=b"\x00" * 4)
    node.features = list(features)
    return node


class CollectCapabilitiesTests(unittest.TestCase):

    def test_no_features_anywhere_returns_none(self):
        root = _node_with_features("flash.bin")
        self.assertIsNone(collect_capabilities(root))

    def test_features_grouped_by_category(self):
        root = _node_with_features(
            "flash.bin",
            _feature_plain("H.264 decoder", 200, "HIGH"),
            _feature_plain("Memory controller", 150, "MEDIUM"),
        )
        summary = collect_capabilities(root)
        self.assertIn("Codecs", summary.by_category)
        self.assertIn("System", summary.by_category)
        self.assertEqual(summary.by_category["Codecs"][0].name, "H.264 decoder")

    def test_unmapped_feature_name_falls_back_to_other_without_crashing(self):
        root = _node_with_features("flash.bin", _feature_plain("Totally New Thing", 150, "MEDIUM"))
        summary = collect_capabilities(root)
        self.assertIn("Other", summary.by_category)

    def test_same_feature_in_two_nodes_takes_the_stronger_score_and_lists_both_nodes(self):
        root = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        child = FirmwareNode(name="mboot", offset=0, data=b"\x00" * 4, parent=root)
        root.children.append(child)

        root.features = [_feature_plain("FFmpeg", 150, "MEDIUM")]
        child.features = [_feature_plain("FFmpeg", 250, "HIGH")]

        summary = collect_capabilities(root)
        (entry,) = summary.by_category["Codecs"]
        self.assertEqual(entry.score, 250)
        self.assertEqual(entry.confidence, "HIGH")
        self.assertEqual(len(entry.nodes), 2)

    def test_within_category_sorted_by_descending_score(self):
        root = _node_with_features(
            "flash.bin",
            _feature_plain("MPEG codec", 100, "MEDIUM"),
            _feature_plain("H.264 decoder", 250, "HIGH"),
        )
        summary = collect_capabilities(root)
        names = [e.name for e in summary.by_category["Codecs"]]
        self.assertEqual(names, ["H.264 decoder", "MPEG codec"])


class RenderCapabilitiesTests(unittest.TestCase):

    def test_capabilities_section_appears_with_confidence_markers(self):
        root = _node_with_features("flash.bin", _feature_plain("H.264 decoder", 250, "HIGH"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            render_cross_tree_summary(root)
        output = buf.getvalue()
        self.assertIn("Capabilities", output)
        self.assertIn("Codecs:", output)
        self.assertIn("✓ H.264 decoder", output)

    def test_no_capabilities_no_section_printed(self):
        root = _node_with_features("flash.bin")
        buf = io.StringIO()
        with redirect_stdout(buf):
            render_cross_tree_summary(root)
        self.assertNotIn("Capabilities", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
