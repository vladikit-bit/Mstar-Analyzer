# MBoot Env Block Parser — Design Spec

**Date:** 2026-07-25
**Branch:** feature-mboot-parser
**Status:** Approved

## 1. Purpose

MBoot (MStar Boot) is a modified U-Boot bootloader used in MStar semiconductor firmware.
Firmware images contain a structured **MBoot Environment Block** that holds bootloader
configuration variables (`Board=`, `MBoot_IN=`, `Security=`, etc.). Currently the analyzer
detects these only as scattered ASCII string markers — there is no structural parsing.

This spec describes a new **Object Detector + Analyzer** module that:

- Locates MBoot Env Blocks in firmware data
- Parses the preamble (binary metadata region)
- Extracts the version string (`MBOT-...`)
- Extracts all key=value environment variables
- Stores results as structured metadata in `EmbeddedObject`

## 2. MBoot Env Block Structure

Based on analysis of `firmware/flash.bin` at offset `0x0000B000`:

```
+------------------+
| Preamble          |  Binary region with MIPS instructions, addresses, flags
| (~0x94 bytes)     |  Format not yet fully understood
+------------------+
| Version String   |  "MBOT-1106.0.10.936a0fd.201806111716"
|                  |  Terminated by 0xFF byte(s)
+------------------+
| 0xFF Padding     |  Fill between version string and env variables
+------------------+
| Env Variables    |  key=value pairs separated by \n (0x0A)
|                  |  Terminated by \0 (0x00)
|  e.g.:           |
|    Board=K5AP_BD_MST297B_D01A \n
|    MBoot_IN=SPI_FLASH \n
|    Kernel=Unkown \n
|    Security=Non-TEE \n
|    Load_DTB=False \n
+------------------+
| 0xFF Padding     |  Remaining block filled with 0xFF
+------------------+
```

### 2.1. Key observations

- The **preamble** contains binary data (MIPS instructions, what appear to be addresses
  such as `0x07B00000` and `0x00B00000`). Its exact format is not yet reverse-engineered.
- The **version string** always starts with `MBOT-` and is terminated by one or more `0xFF`
  bytes (not `\0` — this is a notable difference from standard U-Boot env format).
- **Environment variables** use `\n` as separator (not `\0` like U-Boot). The block is
  terminated by `\0`.
- The entire unused portion of the block is filled with `0xFF`.

## 3. Architecture

### 3.1. Separation of concerns: Detector vs Analyzer

The contract follows the same shape already used by PNG/JPEG/ELF/Lua detectors
in this project: the detector only **finds a candidate**; the analyzer performs
all structural interpretation.

**Detector** (`detect_mboot_env_block()` in `detectors/objects.py`):
- Searches firmware data for the `b"MBOT-"` marker.
- Applies a minimal candidate guard (marker not at the very end of the file).
- Creates an `EmbeddedObject` with `size=None`, a static `description`,
  default `confidence`, and **no** metadata.
- Advances the scan position format-agnostically (by marker length), exactly
  like the PNG/ELF/Lua detectors advance by signature length.
- Does **not** compute block boundaries, does **not** parse the internal
  structure, does **not** compute confidence, does **not** build metadata,
  and does **not** import anything from the analyzer layer.

**Analyzer** (`analyze_mboot_env_block()` in `object_analyzer.py`,
delegating to `analyzers/mboot_env.py`):
- Performs the **single** full structural parse of the block (preamble,
  version string, env variables, block boundaries).
- Owns all format-specific logic and helper functions.
- Computes `obj.size`, `obj.confidence`, and fills `obj.metadata`.
- Demotes false-positive candidates (e.g. an `MBOT-` substring that happens
  to appear inside a variable value) through the confidence heuristic
  (`preamble_size == 0` → `confidence="low"`).

This separation ensures:
- Detector can be reused for different MBoot block formats.
- Analyzer can evolve independently (CRC validation, address parsing, etc.).
- Format-specific logic lives only in the analyzer layer.
- The detector never depends on the analyzer (no `detectors → analyzers`
  import direction).

### 3.2. EmbeddedObject field ownership

Consistent with the project-wide de-facto contract for `EmbeddedObject`:

| Field group | Fields | Created by | Mutated by analyzer? |
|---|---|---|---|
| Identity | `offset`, `kind`, `description` | detector | No — analyzer only reads them |
| Analysis | `size`, `confidence`, `validated`, `metadata` | detector (defaults) | Yes — analyzer owns and sets them |

For MBoot the analyzer therefore owns `size`, `confidence`, `validated`,
and `metadata`; it does **not** rewrite `offset`, `kind`, or `description`.

### 3.3. Incremental approach: A → C

- **Phase A (this spec):** Object Detector + Analyzer with metadata
- **Phase C (future):** Add dedicated renderer for formatted table output

## 4. Data Models

### 4.1. `MBootVariable`

```python
@dataclass(slots=True)
class MBootVariable:
    name: str          # Variable name: "Board", "Security", etc.
    value: str         # Variable value: "K5AP_BD_MST297B_D01A", etc.
    offset: int        # Absolute offset in firmware image
    length: int        # Length of "key=value\n" bytes
```

Using a dataclass instead of `dict[str, str]` enables:
- Per-variable offset tracking (for diff between firmware versions)
- Length tracking (for potential patch support)
- Preserving declaration order (ordered list, not dict)

### 4.2. `MBootEnvBlockInfo`

```python
@dataclass(slots=True)
class MBootEnvBlockInfo:
    version_string: str = ""
    preamble_offset: int = 0
    preamble_size: int = 0
    variables: list[MBootVariable] = field(default_factory=list)
```

Used internally by the analyzer. Not stored directly in `EmbeddedObject.metadata`.

### 4.3. `EmbeddedObject.metadata` schema

The detector/analyzer populates `EmbeddedObject.metadata` with these keys:

| Key | Type | Description |
|---|---|---|
| `mboot_version` | `str` | Full version string, e.g. `"MBOT-1106.0.10.936a0fd.201806111716"` |
| `mboot_preamble_offset` | `int` | Offset of preamble start in firmware |
| `mboot_preamble_size` | `int` | Size of preamble in bytes |
| `mboot_variables` | `list[dict]` | Each dict: `{"name": str, "value": str, "offset": int, "length": int}` |
| `mboot_variable_count` | `int` | Number of extracted variables |

Note: Raw hex dump of preamble is **not** stored in metadata to avoid bloating JSON exports.
It is available only in verbose/debug logging mode.

## 5. Detector: `detect_mboot_env_block()`

### 5.1. Signature

```python
def detect_mboot_env_block(data: bytes) -> list[EmbeddedObject]:
    ...
```

### 5.2. Detection algorithm

The detector performs candidate discovery **and** boundary computation
(preamble start, version end, block end), but **not** detailed structural
parsing (env variable extraction, metadata population). This allows the
detector to compute `size` and `confidence` for the `EmbeddedObject`,
while the analyzer owns all format-specific logic:

1. Search for byte pattern `b"MBOT-"` in `data`.
2. For each occurrence at position `pos`:
   a. Apply a minimal candidate guard (marker not within the last 10 bytes of the
      file — too close to EOF to form a real block).
   b. **Find preamble boundary** — scan backward from `pos` within a window of
      up to 256 bytes. Find the **longest run** of a single padding byte
      (`0x00` or `0xFF`) in the window. The preamble starts after this run.
      This handles both `0x00`-padded and `0xFF`-padded firmware, and is robust
      against short `0x00`/`0xFF` sequences inside the preamble (e.g., MIPS
      instructions like `0xFFFFFFFF`).
   c. **Read version string** from `pos` forward until `\xff` terminator.
   d. **Find env variables region** — skip past version string's `\xff` terminator
      and any `0xFF` padding, then read until `\0` or `0xFF` fill.
   e. **Compute block size** = `env_end - preamble_start`.
   f. **Compute confidence** based on preamble size and variable count.
   g. Create `EmbeddedObject(offset=preamble_start, size=block_size,
      kind="MBootEnvBlock", description="MBoot environment block ({version})",
      confidence=confidence)`.
   h. Advance scan position past `block_end` to avoid re-scanning the same
      region.

**Note on preamble boundary precision:** If the first byte of the preamble
matches the padding byte (e.g., preamble starts with `0x00` and padding is
`0x00`), the boundary may be off by 1 byte. This is a fundamental limitation
of the heuristic and does not affect version string or variable extraction.

**False positive handling:** An `MBOT-` substring that accidentally appears
inside a variable value will produce a candidate with `preamble_size == 0`,
which the analyzer demotes to `confidence="low"` (see §6.5).

### 5.3. Edge cases

- **No `MBOT-` found**: return empty list (silent skip).
- **Multiple MBoot blocks**: return one `EmbeddedObject` per `MBOT-` occurrence.
- **`MBOT-` inside a variable value (false positive)**: still produces a
  candidate; the analyzer demotes it via confidence (see §6.5).
- **Incomplete block** (truncated at end of file): created with `size=None`;
  the analyzer handles the truncated region gracefully.

## 6. Analyzer: `analyze_mboot_env_block()`

### 6.1. Dispatch

In `object_analyzer.py`, add to `analyze_objects()`:

```python
elif obj.kind == "MBootEnvBlock":
    analyze_mboot_env_block(obj, data)
```

### 6.2. Analysis algorithm

The analyzer computes **all** structural boundaries itself (the detector
provides only the candidate's marker offset):

1. **Extract version string**: From the `MBOT-` marker until `\xff` terminator.
   Store in `metadata["mboot_version"]`.
2. **Measure preamble**: scan backward from the marker within a window of up to
   256 bytes for the transition from `0xFF` padding to structured binary data
   (a run of at least 16 `0xFF` bytes). Store `metadata["mboot_preamble_offset"]`
   and `metadata["mboot_preamble_size"]`.
3. **Parse env variables**: skip past the version string's `\xff` terminator and
   any `0xFF` padding, then read the `\n`-separated text region until `\0` or
   `0xFF` fill. Split by `\n`, parse each line as `key=value`:
   - Strip trailing spaces (MBoot pads values with spaces before `\n`)
   - Skip empty lines
   - Create `MBootVariable` for each
   - Store as `metadata["mboot_variables"]` (list of dicts for JSON serialization)
4. **Compute block extent**: `obj.size = block_end - preamble_offset`, where
   `block_end` is the offset at which the env-variable region terminates
   (first `\0` or `0xFF` after the variables).
5. **Count variables**: `metadata["mboot_variable_count"]`.

### 6.3. Universal key=value parsing

The parser does **not** hardcode known variable names (`Board`, `Security`, etc.).
It extracts any `key=value` pair found in the env region. This ensures:
- Unknown variables in other firmware versions are captured automatically
- No code changes needed when new MBoot versions add new variables
- Special formatting of known keys is deferred to the renderer (Phase C)

### 6.4. Confidence rules

Confidence is assigned reproducibly based on evidence:

| Condition | Confidence | Rationale |
|---|---|---|
| `MBOT-` found + ≥2 key=value variables parsed + preamble detected | **high** | Complete, well-formed block |
| `MBOT-` found + ≥1 key=value variable + preamble detected | **high** | Block with minimal but valid content |
| `MBOT-` found + 0 variables + preamble detected | **medium** | Version string exists but no env data |
| `MBOT-` found + preamble boundary ambiguous | **medium** | Likely MBoot block but structure unclear |
| Only `MBOT-` found, no preamble boundary found | **low** | Marker present but no block structure |

### 6.5. False-positive demotion (invariant I11)

Because the detector no longer advances the scan past `block_end` (§5.2), an
`MBOT-` substring that happens to appear inside a variable value (e.g.
`Ref=MBOT-9999`) would produce an extra candidate. The analyzer is expected to
demote such candidates to `confidence="low"`:

- A false candidate has no real preamble — `_find_preamble_start` scans backward
  and finds no `0xFF`-padding run, so `preamble_size == 0`.
- With `preamble_found == False` and (typically) no valid variables,
  `compute_confidence` returns `"low"` (rule: *Only `MBOT-` found, no preamble
  boundary found → low*).

This is the analyzer's responsibility, not the detector's.

## 7. Files to Create/Modify

| File | Action | Description |
|---|---|---|
| `mstar_analyzer/analyzers/mboot_env.py` | **Create** | `MBootVariable`, `MBootEnvBlockInfo`, parsing functions |
| `mstar_analyzer/analyzers/__init__.py` | **Modify** | Re-export new types in `__all__` |
| `mstar_analyzer/detectors/objects.py` | **Modify** | Add `detect_mboot_env_block()`, register in `DETECTORS` |
| `mstar_analyzer/object_analyzer.py` | **Modify** | Add `analyze_mboot_env_block()` dispatch |
| `tests/test_mboot_env.py` | **Create** | Unit tests for detector and analyzer |

## 8. Integration Points

- **Automatic rendering**: `EmbeddedObject.metadata` is rendered automatically by
  `render_node_objects()` in `render.py`. No additional renderer needed for Phase A.
- **JSON export**: `_object_to_dict()` in `json_export.py` serializes metadata
  automatically. The `mboot_variables` list-of-dicts format is JSON-native.
- **Cross-tree summary**: Not needed in Phase A. Can be added in Phase C.

## 9. Tests

| Test | Description |
|---|---|
| `test_detect_mboot_env_block_flash` | Detector finds block in `flash.bin` at correct offset |
| `test_detect_mboot_env_block_no_false_positive` | Firmware without MBoot returns empty list |
| `test_parse_version_string` | Correct parsing of version string with `\xff` terminator |
| `test_parse_env_variables` | Correct extraction of all key=value pairs from flash.bin block |
| `test_parse_env_variables_strips_padding` | Trailing spaces before `\n` are stripped from values |
| `test_parse_env_variables_universal` | Unknown variable names (not Board/Security) are also captured |
| `test_mboot_variable_offsets` | Each `MBootVariable` has correct `offset` and `length` |
| `test_confidence_high` | Well-formed block gets `confidence="high"` |
| `test_confidence_medium` | Block with version but no variables gets `confidence="medium"` |
| `test_multiple_blocks` | Two `MBOT-` markers in same data produce two objects |
| `test_truncated_block` | Block cut off at EOF is handled gracefully |

## 10. Future Extensions (not implemented now)

These are anticipated directions for the MBoot parser module:

- **CRC validation** — many MBoot blocks contain a CRC; validate integrity
- **Physical flash address parsing** — extract `0x07B00000`-style addresses from preamble
- **Memory map reconstruction** — use preamble addresses to build flash memory layout
- **Boot partition detection** — identify primary/backup/secondary boot partitions
- **Environment diff** — compare MBoot env blocks between firmware versions
- **Environment patch** — modify individual variables and write back to firmware
- **Dedicated renderer** (Phase C) — formatted table with variable highlighting,
  grouped output, cross-tree summary
- **Preamble field mapping** — as more firmware samples are analyzed, document
  the meaning of each preamble byte offset

## 11. Example Output (Phase A)

```
[Objects]
  MBootEnvBlock           0x0000B000  1024 bytes   confidence: high
    kind         : MBootEnvBlock
    validated    : True
    mboot_version: MBOT-1106.0.10.936a0fd.201806111716
    mboot_preamble_offset: 0xB000
    mboot_preamble_size: 148
    mboot_variable_count: 5
    mboot_variables:
      Board=K5AP_BD_MST297B_D01A       offset=0xB100  length=27
      MBoot_IN=SPI_FLASH               offset=0xB11B  length=18
      Kernel=Unkown                    offset=0xB12D  length=14
      Security=Non-TEE                offset=0xB13B  length=16
      Load_DTB=False                  offset=0xB14B  length=16
```

## 12. Invariants (must hold after implementation)

These invariants are verified by the test suite and must not regress:

- **I1** `obj.metadata` contains exactly the five keys from §4.3 with the same
  values for the same input.
- **I2** `obj.confidence` after analysis is the same as the pre-refactor value
  (same `compute_confidence` function, same inputs).
- **I3** `obj.validated` is `True` for well-formed blocks.
- **I4** `variables` list has the same count and the same `name`/`value`/`offset`/`length`
  per variable.
- **I5** `parse_mboot_env_block` is called exactly once per block.
- **I6** `compute_confidence` is called exactly once per block.
- **I7** There is no `detectors → analyzers` import direction.
- **I8** `node.objects` is consumed only after `analyze_objects` runs
  (ordering in `analyze.py` is unchanged).
- **I9** No circular imports are introduced.
- **I10** `obj.size` after analysis is computed from the same structural
  boundaries as before (contract on the *bounds*, not a frozen number).
- **I11** False-positive candidates (`MBOT-` inside a variable value) are
  demoted to `confidence="low"` by the analyzer (§6.5).

## 13. Open questions

- **O1 — Mechanism for `block_end`:** `block_end` (end of the env-variable
  region) is currently a local variable inside `_extract_env_variables` and is
  not returned. The *ownership* of `size` (analyzer) is decided, but the
  *mechanism* by which the analyzer obtains `block_end` is an implementation
  detail (new field on `MBootEnvBlockInfo`, tuple return, etc.) — to be decided
  during implementation.
- **O2 — Semantics of `EmbeddedObject.offset`:** not decided in this spec.
  `offset` may mean the marker position (set by the detector) or the logical
  object start (preamble). Under the current contract (§3.2), the detector sets
  `offset` and the analyzer does not rewrite it; whether the analyzer is ever
  permitted to rewrite `offset` is a separate architectural question.
