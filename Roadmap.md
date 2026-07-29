# ROADMAP

# MStar Analyzer Roadmap

This document describes the long-term development strategy of **MStar Analyzer**.

Originally created for reverse engineering and analysis of **MStar firmware**, the project is gradually evolving into a modular framework capable of analyzing embedded firmware from multiple vendors and architectures while maintaining first-class support for MStar platforms.

Development follows functional milestones rather than fixed release dates.

---

# Current Status

**Project stage**

Early Alpha (v0.x)

## Implemented

### Core framework

* Recursive firmware tree
* Modular analyzer architecture
* Detector pipeline
* Renderer pipeline
* Recursive object analysis
* Firmware object classification
* Cross-tree reporting

### Extraction

* Raw streams
* GZip
* Zlib
* LZMA
* XZ
* BZip2
* Modular extractor framework
* Budget-aware decompression

### Analysis

* Runtime analyzer
* BusyBox analyzer
* OpenSSL analyzer
* FFmpeg analyzer
* SDK symbol analyzer
* MBoot Environment parser
* Embedded object analyzers

### Detection

* Library detection
* Feature detection
* Object detection
* Code cave detection (experimental)

### Output

* Console renderer
* JSON export

### Quality

* Comprehensive unit test suite
* Regression tests
* Modular project architecture

---

# Stage 1 — Core Framework

**Goal**

Build a stable architecture that allows future development without major refactoring.

**Status**

Mostly complete.

Includes

* Modular analyzers
* Detector pipeline
* Renderer pipeline
* Recursive firmware tree
* Modular extraction framework
* Automated unit testing
* JSON export

---

# Stage 2 — Compression Support

**Goal**

Support the compression formats most commonly encountered inside embedded firmware.

Planned

* LZ4
* Zstandard (Zstd)
* LZO
* LZOP
* Improved multi-stream GZip
* Improved multi-stream LZMA

---

# Stage 3 — Archive & Package Support

**Goal**

Automatically recognize firmware packages before firmware analysis begins.

Planned

* ZIP
* TAR
* 7z
* Vendor firmware packages
* OTA packages
* update.img
* PKG containers

---

# Stage 4 — Filesystem Support

**Goal**

Automatically detect, unpack and analyze embedded filesystems.

Planned

* SquashFS
* CramFS
* JFFS2
* UBIFS
* YAFFS
* ROMFS

---

# Stage 5 — Bootloaders

**Goal**

Improve bootloader recognition and metadata extraction.

Planned

* MBoot improvements
* U-Boot
* UImage
* FIT Image
* Broadcom boot formats
* Sigma Designs boot formats

---

# Stage 6 — Vendor Support

**Goal**

Expand firmware understanding beyond MStar while preserving MStar as the primary development target.

Planned

* MStar (primary focus)
* Realtek
* Amlogic
* Rockchip
* MediaTek
* HiSilicon
* Samsung
* LG
* Additional vendors

---

# Stage 7 — Reporting

**Goal**

Provide professional reporting capabilities.

Planned

* Improved JSON output
* HTML reports
* Better CLI output
* Confidence visualization
* Dependency reporting
* Firmware summaries

---

# Stage 8 — Extensibility

**Goal**

Transform MStar Analyzer into an extensible analysis framework.

Planned

* Plugin API
* Automatic plugin discovery
* External analyzers
* External detectors
* External renderers
* Stable plugin interface
* Versioned plugin API

---

# Stage 9 — Reverse Engineering

**Goal**

Assist firmware reverse engineering rather than only identifying firmware contents.

Planned

* Improved Code Cave detection
* Optional Code Cave analysis
* Code Cave verification
* MIPS disassembly support
* ARM disassembly support
* Patch suggestion engine
* Binary patch validation

---

# Stage 10 — Integration

**Goal**

Integrate with existing reverse engineering ecosystems.

Planned

* Ghidra integration
* IDA Pro integration
* Binary Ninja integration
* Capstone
* Keystone

---

# Stage 11 — User Experience

**Goal**

Improve usability without compromising the modular architecture.

Planned

* Graphical User Interface
* Interactive firmware tree
* Search
* Filtering
* Drag & Drop firmware loading
* Progress reporting

---

# Future Directions

Potential long-term improvements include

* External signature databases (YAML / JSON)
* Community-maintained signature packs
* Machine-readable firmware knowledge base
* Automatic firmware patch suggestions
* Optional deep analysis modes
* Performance optimizations
* Parallel analysis pipeline

---

# Long-term Vision

The long-term objective of **MStar Analyzer** is to become a modular firmware analysis framework capable of automatically discovering, extracting, classifying, analyzing and visualizing embedded firmware regardless of vendor or architecture, while continuing to provide best-in-class support for MStar-based firmware.

---

# Development Philosophy

The project follows several core principles:

* Correctness before performance.
* Modularity before complexity.
* Automated tests before refactoring.
* Incremental improvements over large rewrites.
* Evidence-based analysis instead of assumptions.
* Architecture should evolve slowly; capabilities should evolve continuously.
