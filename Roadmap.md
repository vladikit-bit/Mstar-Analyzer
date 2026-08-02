# MStar Analyzer Roadmap

> Strategic roadmap for the long-term evolution of the MStar Analyzer project.

---

# Vision

**MStar Analyzer** is being developed as a modular firmware analysis framework capable of automatically discovering, extracting, classifying and visualizing embedded firmware.

Although the architecture is intentionally generic and extensible, the project currently follows a **MStar-first development strategy**.

Real-world MStar firmware serves as the primary design target, while support for additional vendors is expected to evolve naturally from this foundation.

The long-term objective is to create a professional reverse engineering framework for embedded firmware rather than a collection of standalone analysis scripts.

---

# Current Status

Current development stage:

**Early Alpha**

The core architecture has largely stabilized.

Implemented features include:

* Recursive firmware tree
* Modular extraction framework
* Modular detector pipeline
* Modular analyzer pipeline
* Modular renderer pipeline
* Runtime analysis
* Embedded object detection
* Library detection
* Feature detection
* SDK symbol profiling
* MBoot Environment parser
* Code Cave detection (experimental)
* JFFS2 filesystem region detection (boundaries + node count; content extraction still planned — see Stage 3)
* JSON export
* Unit test suite

Supported compression formats:

* Raw
* GZip
* Zlib
* LZMA
* XZ
* BZip2

---

# Core Architecture

The project is organized around independent modules rather than monolithic analysis logic.

Current architectural layers include:

* Extractors
* Detmectors
* Analyzers
* Renderers
* Reporting
* Firmware Tree
* JSON Export
* Testing

This modular design allows individual components to evolve independently while maintaining a consistent analysis pipeline.

---

# Development Stages

## Stage 1 — Core Framework

Status:

**Mostly complete**

Objectives:

* Stable architecture
* Recursive firmware tree
* Modular pipelines
* Automated testing
* JSON reporting

---

## Stage 2 — Compression Support

Goal:

Support the majority of compression formats found inside embedded firmware.

Planned:

* LZ4
* Zstandard
* LZO
* LZOP
* Multi-stream GZip
* Multi-stream LZMA

---

## Stage 3 — Filesystem Support

Goal:

Automatically detect and unpack embedded filesystems.

Done:

* SquashFS (LE/BE, full extraction)

In progress:

* JFFS2 — region detection only (magic + header CRC validation, contiguous nodes grouped into filesystem regions); content parsing/extraction (file & directory listing) not yet implemented

Planned:

* CramFS
* UBIFS
* YAFFS
* ROMFS

---

## Stage 4 — Bootloaders

Goal:

Provide deep understanding of embedded boot environments.

Planned:

* MBoot improvements
* U-Boot
* UImage
* FIT Image
* Vendor bootloaders
* SPI Flash layout reconstruction

---

## Stage 5 — Vendor-specific Analysis

Current priority:

**MStar firmware**

Future support:

* Realtek
* Rockchip
* Amlogic
* MediaTek
* HiSilicon
* Broadcom
* Sigma Designs
* Samsung
* LG

---

## Stage 6 — Reverse Engineering

Long-term goals:

* Function discovery
* MIPS disassembly
* Symbol recovery
* Call graph reconstruction
* Cross references
* Relocation analysis

---

## Stage 7 — Reporting

Planned outputs:

* Plain text
* JSON
* HTML
* Firmware comparison reports
* Interactive dependency graphs
* Statistical summaries

---

# Recently Activated Modules

Some modules get implemented ahead of their integration point and are
intentionally left disconnected from the main pipeline until the
remaining concern is addressed. As of 2026-08 (see CHANGELOG.md for
the full technical writeup):

* **JFFS2 scanner** — implemented with full structural validation
  (magic + header CRC32), integration into `build_firmware_map()`
  intentionally postponed pending performance validation. The
  original scanner walked every byte of the input in pure Python
  (~3.1s on a 32 MB image); rewritten around a fast substring search
  and activated. Currently detection-only — it reports JFFS2 region
  boundaries and node counts, not file/directory contents (see
  Stage 3 above).
* **Zlib heuristic scanner** — `ZlibExtractor` was fully implemented
  and unit-tested well before this, but no scanner ever produced a
  matching `Finding` for it, so it was unreachable from a real
  analysis run. Now wired up end-to-end.
* **SDK fingerprinting / similarity engine** — a separate, ongoing
  workstream (see *Research Topics* below), developed independently
  and intentionally **not** touched by the activation work above.

---

# MStar-first Objectives

Although the framework is becoming increasingly generic, several MStar-specific capabilities remain primary objectives.

These include:

* MBoot Environment analysis
* eCos package inventory
* SDK fingerprinting
* Firmware partition reconstruction
* Lua middleware analysis
* Vendor-specific runtime profiling
* SPI Flash layout analysis

Completing these features represents the primary milestone before broadening development toward additional platforms.

---

# Framework Evolution

## Plugin System

Allow third-party extensions without modifying the core project.

Long-term goals:

* Automatic plugin discovery
* Plugin registration
* Vendor packages
* Custom analyzers
* Custom detectors
* Custom extractors
* Custom renderers

---

## Input Formats

Current:

* Raw firmware images (.bin)

Planned:

* ZIP archives
* Vendor PKG packages
* Automatic archive inspection
* Multi-image firmware packages
* Automatic firmware candidate selection

---

## Configuration System

Long-term goals:

* YAML signatures
* YAML feature definitions
* Vendor databases
* User-defined detection rules
* External configuration profiles

---

## Binary Patching Support

Future capabilities:

* Improved Code Cave detection
* Executable cave verification
* Disassembly-assisted validation
* Optional Code Cave analysis
* Patch generation helpers
* Patch validation

---

## Reverse Engineering Integration

Planned integrations:

* Ghidra
* Binary Ninja
* IDA (optional)
* Export of analysis metadata
* Automatic annotation
* Cross-reference generation

---

## User Interfaces

Future interfaces include:

* Enhanced CLI
* HTML Dashboard
* Desktop GUI
* REST API
* Web Interface

---

# Research Topics

The following areas are considered long-term research directions rather than immediate implementation goals.

Examples include:

* Firmware similarity analysis
* SDK fingerprinting
* Automatic vendor identification
* Unknown filesystem detection
* Firmware diff engine
* AI-assisted firmware classification
* Automatic vulnerability hints
* Patch recommendation engine
* Firmware clustering

---

# Development Philosophy

The project follows several engineering principles.

* Correctness before performance.
* Modularity before complexity.
* Automated tests before refactoring.
* Incremental improvements over large rewrites.
* Evidence-based analysis instead of assumptions.
* System-level understanding over isolated file analysis.
* Practical usefulness over feature count.

These principles guide every architectural decision made within the project.

---

# Long-term Vision

The long-term vision is to transform MStar Analyzer into a professional firmware reverse engineering framework capable of assisting researchers, developers and security analysts in understanding complex embedded firmware across multiple vendors and architectures.

The project aims to remain modular, extensible, transparent and evidence-driven while preserving its original mission of providing best-in-class analysis for MStar-based firmware.
