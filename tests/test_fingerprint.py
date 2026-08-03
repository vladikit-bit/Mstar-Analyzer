"""
Регресійні тести для fingerprint.py — SDK fingerprinting / firmware
similarity (Roadmap.md "MStar-first Objectives"; та сама мета, що
описана в докстрінгу SdkSymbolProfile: "ця прошивка на N% схожа на
CADENA X").
"""

from __future__ import annotations

import unittest

from mstar_analyzer.analyzers.chip_id import analyze_chip_id
from mstar_analyzer.analyzers.runtime import analyze_runtime
from mstar_analyzer.analyzers.sdk_symbols import analyze_sdk_symbols
from mstar_analyzer.detectors.features import detect_features
from mstar_analyzer.fingerprint import (
    FirmwareFingerprint,
    build_fingerprint,
    compare_fingerprints,
    fingerprint_from_dict,
)
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.json_export import build_json_report
from mstar_analyzer.strings import StringFinding


def _make_node(sdk_strings, feature_strings, chip_text, ecos_text) -> FirmwareNode:
    node = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
    node.analysis = {
        "sdk_symbols": analyze_sdk_symbols([StringFinding(offset=i, text=t) for i, t in enumerate(sdk_strings)]),
        "chip_id": analyze_chip_id([StringFinding(offset=0, text=chip_text)]) if chip_text else None,
        "runtime": analyze_runtime([StringFinding(offset=0, text=ecos_text)]) if ecos_text else None,
    }
    node.features = detect_features([StringFinding(offset=i, text=t) for i, t in enumerate(feature_strings)])
    return node


class BuildFingerprintTests(unittest.TestCase):

    def test_aggregates_sdk_symbols_by_category(self):
        node = _make_node(
            ["MDrv_GE_SetBlt", "MDrv_GE_FillRect", "MApi_HDMITx_Init"],
            [], None, None,
        )
        fp = build_fingerprint(node)
        self.assertEqual(fp.sdk_symbols["MDrv_"], {"MDrv_GE_SetBlt", "MDrv_GE_FillRect"})
        self.assertEqual(fp.sdk_symbols["MApi_"], {"MApi_HDMITx_Init"})

    def test_aggregates_capabilities_from_features(self):
        node = _make_node([], ["Wait MIU0...", "Vdec:H264"], None, None)
        fp = build_fingerprint(node)
        self.assertIn("Memory controller", fp.capabilities)
        self.assertIn("H.264 decoder", fp.capabilities)

    def test_confirmed_chip_model_captured(self):
        node = _make_node([], [], "K5AP_BD_MST297B_D01A", None)
        fp = build_fingerprint(node)
        self.assertEqual(fp.chip_models, {"MST297B"})

    def test_ecos_pro_priority_reused_for_libc(self):
        node = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        child = FirmwareNode(name="app", offset=0, data=b"\x00" * 4, parent=node)
        node.children.append(child)
        node.analysis = {"runtime": analyze_runtime([StringFinding(offset=0, text="/ecos_os/packages/net/dns/v2_0_1/x.c")])}
        child.analysis = {"runtime": analyze_runtime([StringFinding(offset=0, text="/stb_ecospro/packages/net/tcpip/v2_0_1/x.c")])}
        fp = build_fingerprint(node)
        self.assertEqual(fp.libc, "eCos Pro")

    def test_empty_tree_gives_empty_fingerprint(self):
        node = FirmwareNode(name="flash.bin", offset=0, data=b"\x00" * 4)
        fp = build_fingerprint(node)
        self.assertEqual(fp.sdk_symbols, {})
        self.assertEqual(fp.capabilities, set())
        self.assertIsNone(fp.libc)


class CompareFingerprintsTests(unittest.TestCase):

    def test_self_comparison_gives_perfect_score(self):
        node = _make_node(
            ["MDrv_GE_SetBlt", "MApi_HDMITx_Init"],
            ["Wait MIU0..."],
            "K5AP_BD_MST297B_D01A",
            "/ecos_os/stb_ecospro/packages/net/openssl/v_0_9_8o/x.c",
        )
        fp = build_fingerprint(node)
        result = compare_fingerprints(fp, fp)
        self.assertEqual(result.overall_score, 1.0)
        self.assertTrue(result.chip_match)
        self.assertTrue(result.libc_match)

    def test_completely_disjoint_fingerprints_give_low_score(self):
        fp_a = FirmwareFingerprint(
            sdk_symbols={"MDrv_": {"MDrv_A", "MDrv_B"}},
            capabilities={"Feature A"},
            chip_models={"MST100"},
            libc="glibc",
        )
        fp_b = FirmwareFingerprint(
            sdk_symbols={"MDrv_": {"MDrv_C", "MDrv_D"}},
            capabilities={"Feature B"},
            chip_models={"MST200"},
            libc="uClibc",
        )
        result = compare_fingerprints(fp_a, fp_b)
        self.assertEqual(result.overall_score, 0.0)
        self.assertFalse(result.chip_match)
        self.assertFalse(result.libc_match)

    def test_partial_symbol_overlap_jaccard_math(self):
        fp_a = FirmwareFingerprint(sdk_symbols={"MDrv_": {"A", "B", "C"}})
        fp_b = FirmwareFingerprint(sdk_symbols={"MDrv_": {"B", "C", "D"}})
        result = compare_fingerprints(fp_a, fp_b)
        # |shared|=2 (B,C), |union|=4 (A,B,C,D) -> 0.5
        sim = result.sdk_symbol_similarity["MDrv_"]
        self.assertEqual(sim.shared, 2)
        self.assertEqual(sim.total, 4)
        self.assertEqual(sim.jaccard, 0.5)

    def test_both_empty_categories_treated_as_perfect_match(self):
        # Категорія, відсутня в ОБОХ fingerprint — не має тягнути
        # оцінку вниз (немає доказу розбіжності, немає й доказу збігу,
        # тому нейтрально/perfect за визначенням Жаккара на порожніх множинах).
        fp_a = FirmwareFingerprint(capabilities=set())
        fp_b = FirmwareFingerprint(capabilities=set())
        result = compare_fingerprints(fp_a, fp_b)
        self.assertEqual(result.capabilities_similarity, 1.0)

    def test_shared_chip_models_and_ecos_versions_reported(self):
        fp_a = FirmwareFingerprint(chip_models={"MST297B", "MST296"}, ecos_package_versions={"2.0.60", "2.0.58"})
        fp_b = FirmwareFingerprint(chip_models={"MST297B"}, ecos_package_versions={"2.0.60", "2.0.55"})
        result = compare_fingerprints(fp_a, fp_b)
        self.assertEqual(result.shared_chip_models, {"MST297B"})
        self.assertEqual(result.shared_ecos_versions, {"2.0.60"})

    def test_asymmetric_categories_only_in_one_side_still_scored(self):
        # Категорія присутня лише в ОДНІЙ прошивці — жаккар=0 (не
        # ігнорується мовчки), бо union непорожній, intersection порожній.
        fp_a = FirmwareFingerprint(sdk_symbols={"HAL_": {"HAL_X"}})
        fp_b = FirmwareFingerprint(sdk_symbols={})
        result = compare_fingerprints(fp_a, fp_b)
        self.assertEqual(result.sdk_symbol_similarity["HAL_"].jaccard, 0.0)
        self.assertEqual(result.sdk_symbol_similarity["HAL_"].total, 1)


class JsonRoundTripTests(unittest.TestCase):

    def test_fingerprint_survives_full_json_export_and_reload(self):
        # Через СПРАВЖНІЙ публічний шлях (build_json_report), а не
        # приватний _jsonify напряму — так тест перевіряє реальний код,
        # яким користується --json/--compare-with, а не власну копію.
        node = _make_node(
            ["MDrv_GE_SetBlt", "MDrv_GOP_Init"],
            ["Wait MIU0...", "Vdec:H264"],
            "K5AP_BD_MST297B_D01A",
            "/ecos_os/stb_ecospro/packages/net/openssl/v_0_9_8o/x.c",
        )
        original = build_fingerprint(node)

        report = build_json_report(node)
        restored = fingerprint_from_dict(report["fingerprint"])

        self.assertEqual(restored.sdk_symbols, original.sdk_symbols)
        self.assertEqual(restored.capabilities, original.capabilities)
        self.assertEqual(restored.chip_models, original.chip_models)
        self.assertEqual(restored.libc, original.libc)
        self.assertEqual(restored.ecos_package_versions, original.ecos_package_versions)

    def test_missing_keys_in_dict_do_not_crash(self):
        # Напр. звіт, згенерований до появи якогось нового поля fingerprint.
        restored = fingerprint_from_dict({})
        self.assertEqual(restored.sdk_symbols, {})
        self.assertEqual(restored.capabilities, set())
        self.assertIsNone(restored.libc)


if __name__ == "__main__":
    unittest.main()
