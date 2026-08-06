\# Changelog



\## 2026-08 (cont.) – LZ4, external review fixes, i18n cleanup



\### Added



\* uImage payload wiring — `analyze_uimage()` always decoded the header (OS/arch/compression/CRC), but the payload itself never became a tree node. Compressed payloads now nest properly under a `uImage payload (<compression>)` child instead of showing up as an anonymous stream with no link back to the container; previously-invisible cases (`ih_comp=0`/uncompressed, or unsupported compression) now get a real node too. `collect_extract_candidates()` gained an `exclude_ranges` parameter so the parent's own scan doesn't duplicate what the uImage-aware path already covers.

\* LZ4 support — pure-Python, no runtime dependency (stdlib has no lz4 module): `lz4_block.py` (raw block-format decoder) + `extractors/lz4.py` (Frame format, magic `04 22 4D 18`), wired into Stage 2 detection, Stage 5 extraction, and SquashFS's internal block decompression. Correctness verified via round-trip against the `lz4` PyPI package (dev/test-only dependency) — 500+ fuzz cases, all Frame-format flag combinations, 0 failures.



\### Performance



\* `LzmaHeuristicScanner` — the long-flagged deferred per-byte Python loop — sped up ~2x (32 MB pure noise: 6.33s -> 3.21s) via a precomputed 256-entry props lookup table, replacing a function call + modulo/division arithmetic on every position with a single index. Zero semantic change (verified byte-for-byte against the original function for all 256 values). Unlike JFFS2/zlib, a sparse-search primitive (iter_find/regex) doesn't help here — LZMA's first header byte alone has ~29% valid values, measured to be *slower* than the plain loop when tried.



\### Fixed



\* `flash_layout.py` didn't know about `JFFS2 filesystem region` entries (they live in `firmware_map.py`'s entry list, not `root.objects`/`root.children`) — a JFFS2 partition showed correctly in the raw "Firmware map" table but as "unclassified" in the higher-level Flash layout. Added `_jffs2_anchors()`.

\* `ZlibHeuristicScanner` strengthened after an external deep-engineering review found a near-100% false-positive rate on real firmware (weak 2-byte RFC 1950 header). Added a free structural check (deflate BTYPE + stored-block LEN~NLEN, no decoder call, ~50% reduction on its own) and a bounded 256-byte input-limited structural probe through the real zlib decoder (result always discarded — never becomes an `ExtractResult`/`FirmwareNode`, staying Stage 2 by the same test applied throughout: does this stage ever produce an artifact something else treats as ground truth). Verified on 40 MB of pure noise (10x the review's sample size): 0 false positives.

\* The early "Firmware map" table (`_run()`, printed before `analyze_node()` runs) no longer prints unconfirmed extraction candidates (zlib/gzip/xz/lzma/bzip2/lz4/SquashFS) as if they were final results — that data was always structurally unconfirmable at that point in the pipeline. The confirmed answer already existed later in the report (`render_node_findings()`'s confirmed/rejected/unresolved collapse) but the early table duplicated the same candidates without that context, visually indistinguishable from a real result.

\* `analyze_jpeg()` reported `confidence=high, validated=True` for a bare SOI magic (`FF D8`) with neither an EOI marker nor a plausible SOF/dimensions found — i.e. zero structural confirmation beyond 2 magic bytes. Found via a real firmware run: a JPEG "object" inside a still-compressed LZMA region turned out to be a coincidental magic match in high-entropy noise. Now downgrades to `low`/`validated=False` in that specific case; a real (if truncated) JPEG that found a plausible SOF is unaffected.

\* Several user-facing validation messages (`object_analyzer.py`: Lua 5.0 / generic Lua / uImage / DTB / ELF structural-check text surfaced via `metadata["header_issues"]`/`metadata["note"]`) were in Ukrainian, inconsistent with the rest of the tool's English output — found via a real report where one such message leaked through. Translated; source comments/docstrings are unaffected (Ukrainian stays the project's developer-facing convention).

\* `ZlibHeuristicScanner` was entropy-gated (scanned only inside `high_entropy_regions()`, same as LZMA) purely for performance from before it was hardened — meaning a small compressed blob surrounded by low-entropy content (e.g. a compressed config block in erased/`0xFF` flash padding) could dilute its window's *average* entropy below the scan threshold and never get looked at, even though the compressed bytes themselves were perfectly valid. Concretely reproduced and fixed: now scans the whole file (verified fast enough — 64 MB pure noise, ~1.4s — and precise enough — 0 false positives on structured low-entropy content — before making the change). LZMA remains entropy-gated; it doesn't yet meet the same bar.



\### Changed



\* Roadmap.md — LZ4 moved from Stage 2's "Planned" to "Done"; the recently-added JFFS2/uImage work folded into "Current Status".



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



