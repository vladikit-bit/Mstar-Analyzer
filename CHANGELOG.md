\# Changelog



\## 2026-08 – Compression & filesystem detection completeness



\### Added



\* zlib/deflate raw-stream detection (`ZlibHeuristicScanner`) — wired end-to-end into the extraction pipeline (was previously unreachable: `ZlibExtractor` existed and was tested, but nothing produced a matching `Finding`)

\* JFFS2 filesystem region detection, activated in `build_firmware_map()` (`Jffs2Scanner` existed and was registered in `DEFAULT_SCANNERS`, but no real analysis run ever invoked it)

\* JFFS2 node grouping (`_group_jffs2_nodes`) — collapses a real filesystem's worth of raw per-node hits into one "JFFS2 filesystem region" entry per contiguous run, instead of one row per inode/dirent header



\### Fixed



\* bzip2-decompressed nodes now get `format`/`compression` populated — `COMPRESSION_BY_NAME` (`detectors/classify.py`) was missing a `"bzip2"` entry, so the tree view, JSON export, and flash-layout labels silently dropped bzip2 streams to `null`/generic labels while gzip/xz/lzma-alone worked correctly



\### Performance



\* `Jffs2Scanner.scan()` rewritten to use fast substring search (`iter_find()`) instead of a per-byte Python loop — ~100x faster (32 MB: ~3.1s -> ~0.03s), which is what made turning it on above safe

\* `ZlibHeuristicScanner.scan()` rewritten the same way, searching the small enumerable set of valid CMF/FLG headers — ~6x faster on the worst case (32 MB uniform-entropy data: ~2.8s -> ~0.48s)



\### Testing



\* `tests/test_classify.py` — regression coverage for all four stream compressors (bzip2/gzip/xz/lzma-alone), so a future omission (e.g. LZ4) fails here instead of only on a real image

\* `tests/test_zlib_scanner.py` — scanner unit tests, header enumeration, factory wiring, full `analyze_node()` end-to-end extraction, performance guard

\* `tests/test_jffs2_scanner.py` — LE/BE detection, bad-CRC/truncated-totlen rejection, region grouping, full pipeline integration, performance guard



\### Known follow-ups (not done in this pass)



\* `LzmaHeuristicScanner` is still a per-byte Python loop and is now the dominant cost in the worst-case (uniform-high-entropy) scan — the header space is larger/non-enumerable than zlib's, so the same fix needs a bit more thought

\* SDK fingerprinting/similarity — separate, ongoing work, intentionally out of scope here

\* Full JFFS2 content parsing/extraction (file & directory listing) — this pass only establishes region boundaries; SquashFS remains the only filesystem this project can actually unpack



\## 2026-07 – Firmware analysis improvements



\### Added



\* Codec table analyzer

\* Codec table renderer

\* JSON export for codec table analysis

\* CLI regression tests

\* Codec table regression tests

\* SDK symbol regression tests



\### Improved feature detection



\* Strong signatures now contribute higher confidence scores

\* Added semantic NetSrv subsystem detection:



&#x20; \* Download Module

&#x20; \* Buffering

&#x20; \* Client session

\* Added FFmpeg version banner detection

\* Added H.264 runtime decoder signature

\* Improved MIU and Graphics Engine confidence scoring

\* Prevented duplicate scoring when multiple signatures match the same evidence



\### Rendering improvements



\* Human-readable metadata rendering

\* Pretty rendering of MBoot variables

\* Pretty rendering of Lua header issues

\* SDK symbol rendering for flat namespaces

\* Metadata preview truncation for long lists



\### CLI and JSON improvements



\* Automatic parent directory creation for:



&#x20; \* `--output`

&#x20; \* `--json`

\* Added codec table export to JSON



\### Testing



Added regression tests for:



\* CLI output generation

\* Codec table parsing

\* Feature confidence scoring

\* Metadata rendering

\* SDK symbol rendering



\### Internal improvements



\* Added codec analysis infrastructure

\* Improved renderer modularity

\* Improved analyzer registration

\* Extended JSON export system



