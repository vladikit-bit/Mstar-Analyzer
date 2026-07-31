from __future__ import annotations

from .base import Extractor, ExtractResult, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT


class SquashFsExtractor(Extractor):
    """
    SquashFS filesystem extractor.

    Validates the superblock, then delegates to
    analyzers/squashfs.py:parse_squashfs() to walk the directory tree
    and decompress individual file blocks.

    Returns an ExtractResult with `entries` populated (list of FileSystemEntry),
    `metadata` populated (dict with "squashfs" key -> SquashFsInfo), and
    `data` set to the raw SquashFS image bytes (for the container node).
    """

    method = "squashfs"

    def extract(
        self,
        data: bytes,
        offset: int,
        max_output: int = DEFAULT_MAX_OUTPUT,
        chunk_size: int = DEFAULT_CHUNK,
    ) -> ExtractResult:
        from ..analyzers.squashfs import parse_squashfs, SquashFsError

        try:
            info, entries = parse_squashfs(data, offset)
            output_size = sum(e.size for e in entries)

            if max_output > 0 and output_size > max_output:
                return ExtractResult(
                    offset=offset,
                    method=self.method,
                    success=False,
                    error=f"Extracted file size ({output_size} B) exceeds max_output ({max_output} B)",
                )

            image_data = data[offset : offset + info.image_size]

            return ExtractResult(
                offset=offset,
                method=self.method,
                success=True,
                data=image_data,
                consumed=info.image_size,
                output_size=output_size,
                entries=entries,
                metadata={"squashfs": info},
            )
        except (SquashFsError, Exception) as e:
            return ExtractResult(
                offset=offset,
                method=self.method,
                success=False,
                error=str(e),
            )
