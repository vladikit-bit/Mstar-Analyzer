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


class StrongSignatureWeightingTests(unittest.TestCase):
    """
    Полишинг: сигнатури, позначені confidence="STRONG", мали б самі
    по собі (один-єдиний збіг) давати щонайменше MEDIUM (score>=100 з
    score_to_confidence) — так само, як уже поводиться MDrv_GE
    (weight=100). До цієї правки MIU\\d+ (weight=60) і "driver GE"
    (weight=80) лишались у LOW навіть на однозначному доказі. H.264 і
    FFmpeg раніше взагалі не мали жодної STRONG-сигнатури — лише голе
    слово вагою 50.
    """

    def test_single_miu_digit_match_reaches_at_least_medium(self):
        # Реальний рядок з прошивки: "Wait MIU0..." — один-єдиний збіг.
        features = detect_features([_finding("Wait MIU0...")])
        (feature,) = [f for f in features if f.name == "Memory controller"]
        self.assertIn(feature.confidence, ("MEDIUM", "HIGH"))
        self.assertGreaterEqual(feature.score, 100)

    def test_bare_miu_without_digit_stays_weak(self):
        # Без цифри контролера — це й далі лише WEAK-сигнатура (5),
        # нормалізація STRONG не мала торкнутись цього патерну.
        features = detect_features([_finding("check MIU status")])
        (feature,) = [f for f in features if f.name == "Memory controller"]
        self.assertEqual(feature.confidence, "LOW")

    def test_driver_ge_single_match_reaches_at_least_medium(self):
        features = detect_features([_finding("driver GE init ok")])
        (feature,) = [f for f in features if f.name == "Graphics Engine"]
        self.assertGreaterEqual(feature.score, 100)

    def test_h264_codec_tag_reaches_higher_confidence_than_bare_word(self):
        bare = detect_features([_finding("this stream uses h264 encoding")])
        tagged = detect_features([_finding("Vdec:H264")])

        bare_feature = next(f for f in bare if f.name == "H.264 decoder")
        tagged_feature = next(f for f in tagged if f.name == "H.264 decoder")

        self.assertLess(bare_feature.score, 100)
        self.assertGreaterEqual(tagged_feature.score, 100)

    def test_ffmpeg_version_banner_reaches_higher_confidence_than_bare_word(self):
        bare = detect_features([_finding("built with ffmpeg support")])
        banner = detect_features([_finding("FFMPEG VERSION : 2.5.4")])

        bare_feature = next(f for f in bare if f.name == "FFmpeg")
        banner_feature = next(f for f in banner if f.name == "FFmpeg")

        self.assertLess(bare_feature.score, 100)
        self.assertGreaterEqual(banner_feature.score, 100)


class NetSrvSemanticSubsystemTests(unittest.TestCase):
    """
    NetSrv-рядки в реальних прошивках виглядають як
    "[NetSrv][%s][line:%d][ERROR][Download Module], <-,Memory Allocate
    Fail" — раніше все це давало лише один недиференційований
    "Streaming Engine". Нові сигнатури вимагають тег "[NetSrv]" РАЗОМ
    із конкретним, підтвердженим реальними рядками ключовим словом у
    тому самому рядку — тобто окрема, вужча фіча, а не просто
    перейменування Streaming Engine.
    """

    def test_download_module_detected(self):
        text = "[NetSrv][%s][line:%d][ERROR][Download Module], <-,Memory Allocate Fail"
        features = detect_features([_finding(text)])
        names = {f.name for f in features}
        self.assertIn("NetSrv: Download Module", names)
        self.assertIn("Streaming Engine", names)  # старий блок нікуди не подівся

    def test_buffering_detected(self):
        text = "[NetSrv][%s][line:%d][ERROR][Download Module], GOT EOS stop Buffering!!!"
        features = detect_features([_finding(text)])
        names = {f.name for f in features}
        self.assertIn("NetSrv: Buffering", names)

    def test_client_session_detected(self):
        text = "[NetSrv][%s][line:%d]: Cuurent session count : %lu"
        features = detect_features([_finding(text)])
        names = {f.name for f in features}
        self.assertIn("NetSrv: Client session", names)

    def test_plain_netsrv_line_without_subtag_does_not_trigger_subfeatures(self):
        # Рядок без жодного з підтверджених під-тегів — лише базовий
        # "Streaming Engine", без хибних під-фіч.
        text = "[NetSrv][%s][line:%d]: ->"
        features = detect_features([_finding(text)])
        names = {f.name for f in features}
        self.assertIn("Streaming Engine", names)
        self.assertNotIn("NetSrv: Download Module", names)
        self.assertNotIn("NetSrv: Buffering", names)
        self.assertNotIn("NetSrv: Client session", names)

    def test_buffering_outside_netsrv_context_does_not_trigger(self):
        # "Buffering" саме по собі (без тегу [NetSrv]) — інший, не-NetSrv
        # контекст (напр. PVR/DVR), тому підфіча не мала б спрацювати.
        features = detect_features([_finding("PVR Buffering started")])
        names = {f.name for f in features}
        self.assertNotIn("NetSrv: Buffering", names)


if __name__ == "__main__":
    unittest.main()
