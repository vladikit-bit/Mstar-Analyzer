from __future__ import annotations

import zlib

from .base import Extractor, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .stream import _StreamExtractorMixin


class GZipExtractor(Extractor, _StreamExtractorMixin):
    """gzip (1F 8B 08) — zlib з wbits=MAX_WBITS|16 (авто-детект gzip-заголовка)."""

    method = "gzip"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: zlib.decompressobj(zlib.MAX_WBITS | 16),
            data, offset, max_output, chunk_size,
        )
