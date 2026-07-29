from __future__ import annotations

import bz2

from .base import Extractor, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .stream import _StreamExtractorMixin


class BZip2Extractor(Extractor, _StreamExtractorMixin):
    """
    bzip2 (BZh) — стандартний bz2-стрім. MagicScanner вже знаходить
    сигнатуру BZh, а цей екстрактор намагється реально розпакувати дані
    за допомогою bz2.BZ2Decompressor зі стандартної бібліотеки.
    """

    method = "bzip2"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: bz2.BZ2Decompressor(),
            data, offset, max_output, chunk_size,
        )
