# MStar Analyzer

**MStar Analyzer** is a modular firmware analysis framework focused on automatic discovery, extraction, classification and visualization of embedded firmware contents in **Set-Top OTT TV Boxes and similar embedded media devices**.

Originally developed for **MStar-based set-top box firmware**, the project is evolving into a general-purpose framework for embedded firmware analysis while maintaining first-class support for MStar platforms.

Unlike traditional Smart TV firmware tools, this project also targets **OTT ecosystems**, including runtime components such as Lua scripts, embedded control systems, and vendor-specific middleware layers.

---

## Features

Current capabilities include:

* Recursive firmware analysis
* Modular extraction framework
* Embedded object detection
* Runtime analysis of firmware components
* Lua script analysis (OTT middleware logic)
* ECoS / embedded system structure analysis
* Library detection
* Feature detection
* MBoot Environment parser
* JSON export
* Recursive firmware tree visualization

---

### Supported compression formats

* Raw
* GZip
* Zlib
* LZMA
* XZ
* BZip2

---

## Project Goals

The long-term objective is to build a modular firmware analysis framework capable of automatically discovering, extracting, classifying and visualizing embedded firmware from multiple vendors and architectures, with a strong focus on **Set-Top Box and OTT media platforms**.

See **ROADMAP.md** for detailed development plans.

---

## Current Status

**Development stage:** Early Alpha (v0.x)

The project is under active development.

Architectural changes are becoming less frequent, while new firmware analysis capabilities are continuously being added.

---

## Project Principles

The project follows several core engineering principles:

* Correctness before performance.
* Modularity before complexity.
* Automated tests before refactoring.
* Incremental improvements over large rewrites.
* Evidence-based analysis instead of assumptions.
* System-level understanding over isolated file analysis.

---

## Roadmap

Future development includes:

* Additional compression formats
* Filesystem support
* Bootloader analysis
* Vendor-specific analyzers
* Plugin system
* Reverse engineering helpers
* Ghidra integration
* Graphical User Interface

For details, see **ROADMAP.md**.

---

## License

License information will be added in a future release.
