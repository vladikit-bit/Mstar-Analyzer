\# Changelog



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



