from __future__ import annotations

import lzma

from .base import Extractor, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .stream import _StreamExtractorMixin


class LZMAExtractor(Extractor, _StreamExtractorMixin):
    """
    "Класичний" .lzma (alone) формат — точно те, що знаходить
    LzmaHeuristicScanner. Формат сам містить lc/lp/pb, dict size та
    (опційно) uncompressed size, тож stdlib розпаковує його без
    додаткових filters — не треба передавати їх вручну.
    """

    method = "lzma-alone"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE),
            data, offset, max_output, chunk_size,
        )
