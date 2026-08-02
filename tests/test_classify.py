"""
Регресійні тести для detectors/classify.py.

Ключовий баг, спійманий під час ручної перевірки JSON-звіту: COMPRESSION_BY_NAME
мала записи для "lzma-alone"/"gzip"/"xz", але НЕ для "bzip2" — хоча
BZip2Extractor.method == "bzip2" (extractors/bzip2.py) і саме це ім'я
classify_node() отримує в node.name для кожного bzip2-розпакованого
дочірнього вузла. Наслідок: node.format/node.compression лишались None
для bzip2 (на відміну від інших трьох компресорів), що мовчки псувало
дерево (firmware_tree.pretty()), JSON-звіт (json_export.py) та
flash-розкладку (flash_layout.py).

Тест перевіряє всі чотири компресори однаково, щоб той самий пропуск
для нового компресора в майбутньому (напр. LZ4) впав тут, а не був
виявлений лише вручну на реальній прошивці.
"""

from __future__ import annotations

import unittest

from mstar_analyzer.detectors.classify import classify_node
from mstar_analyzer.firmware_tree import FirmwareNode


class CompressionClassificationTests(unittest.TestCase):

    def _classify(self, extractor_method: str) -> FirmwareNode:
        # node.name = Extractor.method — так само, як analyze.py заповнює
        # його для щойно розпакованого дочірнього вузла (result.method).
        node = FirmwareNode(name=extractor_method, offset=0, data=b"payload")
        classify_node(node)
        return node

    def test_bzip2_gets_format_and_compression(self):
        node = self._classify("bzip2")
        self.assertEqual(node.format, "bzip2")
        self.assertEqual(node.compression, "bzip2")

    def test_gzip_gets_format_and_compression(self):
        node = self._classify("gzip")
        self.assertEqual(node.format, "gzip")
        self.assertEqual(node.compression, "gzip")

    def test_xz_gets_format_and_compression(self):
        node = self._classify("xz")
        self.assertEqual(node.format, "XZ")
        self.assertEqual(node.compression, "XZ")

    def test_lzma_alone_gets_format_and_compression(self):
        node = self._classify("lzma-alone")
        self.assertEqual(node.format, "LZMA")
        self.assertEqual(node.compression, "LZMA")

    def test_bzip2_tree_rendering_includes_compression_tag(self):
        """pretty() друкує "[bzip2]" так само, як "[gzip]"/"[XZ]"/"[LZMA]"."""
        node = self._classify("bzip2")
        self.assertIn("[bzip2]", node.pretty())

    def test_bzip2_title_matches_gzip_xz_lzma_pattern(self):
        """
        classify_node() ставить node.label = f"{format} stream", коли
        format відомий (та сама гілка, що вже працює для gzip/xz/
        lzma-alone) — title має повернути саме це, а не сирий node.name.
        До фіксу bzip2 випадав із цієї гілки (format був None) і title
        лишався голим "bzip2" без "stream".
        """
        node = self._classify("bzip2")
        self.assertEqual(node.title, "bzip2 stream")


if __name__ == "__main__":
    unittest.main()
