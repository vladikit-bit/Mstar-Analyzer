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
from mstar_analyzer.detectors.objects import EmbeddedObject
from mstar_analyzer.firmware_tree import FirmwareNode
from mstar_analyzer.render import render_node_features, render_node_objects
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


class ObjectMetadataFormattingTests(unittest.TestCase):
    """
    render_node_objects() друкував КОЖНЕ значення metadata через один
    загальний f"{key}: {value}" — для list[dict] (MBoot mboot_variables)
    і list[str] (Lua header_issues) це виходило сирим Python repr:
    "[{'name': 'Board', 'value': 'K5AP_BD_MST297B_D01A', ...}, ...]".
    Ці тести перевіряють РЕАЛЬНУ форму даних (підтверджено реальним
    звітом користувача), а не вигадану.
    """

    @staticmethod
    def _render_objects(objs) -> str:
        node = FirmwareNode(name="test", offset=0, data=b"\x00" * 4)
        node.objects = objs
        buf = io.StringIO()
        with redirect_stdout(buf):
            render_node_objects(node)
        return buf.getvalue()

    def test_mboot_variables_render_as_name_value_table_not_repr(self):
        obj = EmbeddedObject(offset=0xB094, size=None, kind="MBootEnvBlock", description="MBoot environment block")
        obj.metadata = {
            "mboot_variables": [
                {"name": "Board", "value": "K5AP_BD_MST297B_D01A", "offset": 45312, "length": 28},
                {"name": "MBoot_IN", "value": "SPI_FLASH", "offset": 45340, "length": 20},
            ],
        }
        output = self._render_objects([obj])
        self.assertIn("Board = K5AP_BD_MST297B_D01A", output)
        self.assertIn("MBoot_IN = SPI_FLASH", output)
        self.assertNotIn("{'name'", output)   # сирий Python repr більше не має з'являтись
        self.assertNotIn("[{", output)

    def test_mboot_variables_list_is_truncated_with_more_count(self):
        obj = EmbeddedObject(offset=0, size=None, kind="MBootEnvBlock", description="MBoot environment block")
        obj.metadata = {
            "mboot_variables": [
                {"name": f"Var{i}", "value": str(i), "offset": i, "length": 1}
                for i in range(12)
            ],
        }
        output = self._render_objects([obj])
        self.assertIn("Var0 = 0", output)
        self.assertIn("more)", output)

    def test_lua_header_issues_render_as_bullet_list_not_repr(self):
        obj = EmbeddedObject(offset=0x444794, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        obj.metadata = {
            "header_issues": [
                "size_int=0 (очікується 2, 4 або 8)",
                "size_size_t=98 (очікується 4 або 8)",
            ],
        }
        output = self._render_objects([obj])
        self.assertIn("- size_int=0 (очікується 2, 4 або 8)", output)
        self.assertIn("- size_size_t=98 (очікується 4 або 8)", output)
        self.assertNotIn("['size_int", output)

    def test_empty_list_metadata_prints_nothing_for_that_key(self):
        obj = EmbeddedObject(offset=0, size=None, kind="MBootEnvBlock", description="MBoot environment block")
        obj.metadata = {"mboot_variables": []}
        output = self._render_objects([obj])
        self.assertNotIn("mboot_variables", output)

    def test_scalar_metadata_unaffected(self):
        obj = EmbeddedObject(offset=0, size=None, kind="Lua bytecode", description="Compiled Lua chunk")
        obj.metadata = {"lua_version": "5.0", "size_int": 0}
        output = self._render_objects([obj])
        self.assertIn("lua_version: 5.0", output)
        self.assertIn("size_int: 0", output)   # falsy-але-значущий скаляр (0) не повинен зникати

    def test_dict_metadata_renders_as_key_value_lines_not_repr(self):
        # DTB root_properties — {'model': '...', 'compatible': [...]}
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        obj.metadata = {
            "root_properties": {
                "model": "mstar,titania",
                "compatible": ["mstar,titania", "mstar,generic"],
            },
        }
        output = self._render_objects([obj])
        self.assertIn("model: mstar,titania", output)
        self.assertNotIn("{'model'", output)

    def test_fit_metadata_renders_readable_not_repr(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        obj.metadata = {
            "fit": {
                "images": {
                    "kernel": {"description": "Linux kernel", "type": "kernel", "os": "linux", "arch": "arm", "compression": "gzip"},
                },
                "configurations": {
                    "conf-1": {"description": "default config", "kernel": "kernel", "fdt": "fdt-1"},
                },
                "default_configuration": "conf-1",
            },
        }
        output = self._render_objects([obj])
        self.assertIn("kernel", output)
        self.assertIn("Linux kernel", output)
        self.assertIn("conf-1", output)
        self.assertIn("default configuration: conf-1", output)
        self.assertNotIn("{'description'", output)
        self.assertNotIn("{'kernel'", output)

    def test_empty_dict_metadata_prints_nothing_for_that_key(self):
        obj = EmbeddedObject(offset=0, size=None, kind="DTB", description="Flattened Device Tree")
        obj.metadata = {"root_properties": {}}
        output = self._render_objects([obj])
        self.assertNotIn("root_properties", output)


if __name__ == "__main__":
    unittest.main()
