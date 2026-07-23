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


if __name__ == "__main__":
    unittest.main()
