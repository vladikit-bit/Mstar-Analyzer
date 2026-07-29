from __future__ import annotations

import lzma

from .base import Extractor, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .stream import _StreamExtractorMixin


class XZExtractor(Extractor, _StreamExtractorMixin):
    """Контейнер .xz (magic FD 37 7A 58 5A 00) — про запас, якщо новіші прошивки перейдуть на нього."""

    method = "xz"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ),
            data, offset, max_output, chunk_size,
        )
