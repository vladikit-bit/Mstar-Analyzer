from __future__ import annotations

from dataclasses import dataclass

from ..signatures import Finding

DEFAULT_CHUNK = 1 << 16          # 64 KiB за один "ковток" декомпресора
DEFAULT_MAX_OUTPUT = 64 << 20    # запобіжник: не більше 64 MiB на один candidate


@dataclass(slots=True)
class FileSystemEntry:
    """
    One file extracted from a filesystem image (SquashFS, UBIFS, CRAMFS, ...).

    Analogous to ExtractResult for single-stream extractors: holds the
    extracted content plus metadata needed to create a FirmwareNode.
    """
    name: str          # file path within the filesystem (e.g. "etc/passwd")
    data: bytes        # file content (decompressed)
    offset: int        # offset within the parent filesystem image
    size: int          # uncompressed size (len(data))


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

    # NEW: when populated, the pipeline creates child FirmwareNodes for each
    # entry instead of a single child from `data`. Used by filesystem
    # extractors (SquashFS, UBIFS, CRAMFS, ...). Single-stream extractors
    # (gzip, xz, lzma, bzip2) leave this as None — fully backward-compatible.
    entries: list[FileSystemEntry] | None = None

    # NEW: filesystem metadata to populate the container node's `analysis`.
    # E.g., {"squashfs": SquashFsInfo(...)}. Single-stream extractors
    # leave this as None.
    metadata: dict[str, object] | None = None

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
