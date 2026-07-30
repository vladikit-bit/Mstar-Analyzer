"""
Регресійні тести для render.py.

render_node_features() довгий час друкував однаковий "✓" для КОЖНОЇ
фічі незалежно від score/confidence — тобто слабкий поодинокий збіг
("eygp3-ge", \\bGE\\b, weight=5) на екрані виглядав так само переконливо,
як підтверджений ("MDrv_GE_SetStrBltSckType"). Дані для розрізнення
(Feature.confidence/.score) вже існували в detectors/features.py —
бракувало лише самого рендеру. Ці тести ловлять регрес САМЕ на рівні
друкованого виводу, а не лише на рівні даних (те окремо покрито в
tests/test_features.py::FeatureConfidenceTests).
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from mstar_analyzer.detectors.features import detect_features
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.render import render_node_features
from mstar_analyzer.strings import StringFinding


def _node_with_strings(*texts: str) -> FirmwareNode:
    node = FirmwareNode(name="test-node", offset=0, data=b"\x00" * 4)
    node.features = detect_features([StringFinding(offset=i, text=t) for i, t in enumerate(texts)])
    return node


def _render(node: FirmwareNode) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        render_node_features(node)
    return buf.getvalue()


class FeatureConfidenceMarkerTests(unittest.TestCase):

    def test_weak_and_strong_matches_get_different_markers(self):
        weak_output = _render(_node_with_strings("eygp3-ge"))
        strong_output = _render(_node_with_strings("MDrv_GE_SetStrBltSckType"))

        self.assertIn("[LOW,", weak_output)
        self.assertNotIn("[LOW,", strong_output)

        # Різні markery на початку рядка з фічею ("? " проти "~ "/"✓ ") —
        # не просто інший текст поруч із тим самим "✓". Пропускаємо
        # заголовок ("Detected features" + роздільник) і шукаємо сам
        # рядок фічі за назвою.
        weak_line = next(line for line in weak_output.splitlines() if "Graphics Engine" in line)
        strong_line = next(line for line in strong_output.splitlines() if "Graphics Engine" in line)
        self.assertNotEqual(weak_line[0], strong_line[0])

    def test_score_is_printed_for_each_feature(self):
        output = _render(_node_with_strings("MDrv_GE_SetStrBltSckType"))
        self.assertIn("score=", output)

    def test_no_features_prints_nothing(self):
        node = FirmwareNode(name="empty-node", offset=0, data=b"\x00" * 4)
        self.assertEqual(_render(node), "")


if __name__ == "__main__":
    unittest.main()
