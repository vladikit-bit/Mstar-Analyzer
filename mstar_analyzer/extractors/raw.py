from __future__ import annotations

from .base import Extractor, ExtractResult, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT


class RawExtractor(Extractor):
    """
    Фолбек для методів без stdlib-реалізації (напр. LZO) або для
    нестиснутих блоків: просто копіює до max_output байт "as is",
    щоб було що подати далі у Stage 6 (Strings) без падіння пайплайну.
    """

    method = "raw"

    def extract(
        self,
        data,
        offset,
        max_output=DEFAULT_MAX_OUTPUT,
        chunk_size=DEFAULT_CHUNK,
    ):
        chunk = data[offset: offset + max_output]

        return ExtractResult(
            offset=offset,
            method=self.method,
            success=True,
            data=chunk,
            consumed=len(chunk),
            output_size=len(chunk),
        )
