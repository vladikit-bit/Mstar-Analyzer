from __future__ import annotations

import zlib

from .base import Extractor, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .stream import _StreamExtractorMixin


class ZlibExtractor(Extractor, _StreamExtractorMixin):
    """Сирий zlib/deflate потік — рідше трапляється, але буває у ресурсних блоках."""

    method = "zlib"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: zlib.decompressobj(),
            data, offset, max_output, chunk_size,
        )
