"""
Регресійні тести для detectors/features.py.

"GET_PARAMETER" — реальний RTSP-метод, знайдений у справжньому виводі
аналізатора хибно приписаним до Graphics Engine (той самий клас багу,
що й раніше виправлені "(GERD"/"GEOV" — \\bGE[A-Z]...\\b ловив "GE" на
початку будь-якого слова з наступною Великою літерою, включно з "GET").
"""

from __future__ import annotations

import unittest

from mstar_analyzer.strings import StringFinding
from mstar_analyzer.detectors.features import detect_features


def _finding(text: str, offset: int = 0) -> StringFinding:
    return StringFinding(offset=offset, text=text)


class GraphicsEngineFalsePositiveTests(unittest.TestCase):

    def test_get_parameter_does_not_imply_graphics_engine(self):
        strings = [_finding("GET_PARAMETER")]
        features = detect_features(strings)
        names = {f.name for f in features}
        self.assertNotIn("Graphics Engine", names)

    def test_genuine_ge_prefix_still_detected(self):
        strings = [_finding("MDrv_GE_SetStrBltSckType")]
        features = detect_features(strings)
        names = {f.name for f in features}
        self.assertIn("Graphics Engine", names)

    def test_driver_ge_init_still_detected(self):
        strings = [_finding("[0m[%s:%d] driver GE init ok")]
        features = detect_features(strings)
        names = {f.name for f in features}
        self.assertIn("Graphics Engine", names)


class FeatureConfidenceTests(unittest.TestCase):
    """
    detect_features() РОЗРІЗНЯЄ слабкі й сильні збіги через score/confidence
    (див. Feature.confidence у detectors/features.py) — але рендерер
    (render.render_node_features) довгий час малював однаковий "✓" для
    обох. Ці тести фіксують саме той факт, на який спирається виправлений
    рендерер: слабкий поодинокий збіг типу "eygp3-ge" (\\bGE\\b, weight=5)
    і сильний "MDrv_GE_..." мають РІЗНУ Feature.confidence, а не однакову.
    """

    def test_weak_coincidental_match_gets_low_confidence(self):
        # "eygp3-ge" — підтверджений false positive: \bGE\b ловить
        # ізольоване "ge" в кінці рядка, weight=5 (WEAK-сигнатура).
        strings = [_finding("eygp3-ge")]
        features = detect_features(strings)
        (feature,) = [f for f in features if f.name == "Graphics Engine"]
        self.assertEqual(feature.confidence, "LOW")

    def test_strong_match_gets_higher_confidence_than_weak_alone(self):
        weak_only = detect_features([_finding("eygp3-ge")])
        strong = detect_features([_finding("MDrv_GE_SetStrBltSckType")])

        weak_feature = next(f for f in weak_only if f.name == "Graphics Engine")
        strong_feature = next(f for f in strong if f.name == "Graphics Engine")

        self.assertNotEqual(weak_feature.confidence, strong_feature.confidence)
        self.assertGreater(strong_feature.score, weak_feature.score)


if __name__ == "__main__":
    unittest.main()
