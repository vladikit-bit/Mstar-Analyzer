from __future__ import annotations

from dataclasses import dataclass, field

from ..signatures import Finding

DEFAULT_CHUNK = 1 << 16          # 64 KiB за один "ковток" декомпресора
DEFAULT_MAX_OUTPUT = 64 << 20    # запобіжник: не більше 64 MiB на один candidate


@dataclass(slots=True)
class ExtractResult:
    offset: int
    method: str
    success: bool

    data: bytes | None = None
    consumed: int = 0
    output_size: int = 0
    error: str | None = None
    finding: Finding | None = None

    def __repr__(self) -> str:
        if self.success:
            return (f"<ExtractResult 0x{self.offset:08X} {self.method} "
                     f"OK out={self.output_size}B consumed={self.consumed}B>")
        return f"<ExtractResult 0x{self.offset:08X} {self.method} FAILED: {self.error}>"


class Extractor:
    """Базовий клас будь-якого розпаковувача (Stage 5 plugin API, симетрично Scanner у Stage 2)."""

    method = "base"

    def extract(self, data: bytes, offset: int,
                max_output: int = DEFAULT_MAX_OUTPUT,
                chunk_size: int = DEFAULT_CHUNK) -> ExtractResult:
        raise NotImplementedError
