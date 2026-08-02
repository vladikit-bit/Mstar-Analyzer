from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path
import hashlib
from .firmware_tree import FirmwareNode
from .firmware_map import build_firmware_map
from .extractors import extract_all
from .strings import extract_ascii_strings
from .render import render_report, render_similarity
from .json_export import build_json_report
from .signatures import Finding
from .detectors.features import detect_features
from .detectors.objects import detect_objects
from .object_analyzer import analyze_objects
from .detectors.classify import classify_node
from .detectors.libraries import analyze_libraries
from .detectors.code_caves import detect_code_caves
from .fingerprint import build_fingerprint, compare_fingerprints, fingerprint_from_dict

MAX_DEPTH = 8
MIN_SIZE = 512

def _annotate_findings_with_extraction_outcome(findings, results) -> None:
    """
    extract_all() вже РЕАЛЬНО намагається розпакувати кожен candidate —
    але раніше цей результат використовувався лише для побудови дочірніх
    вузлів (успішні), а причина невдачі для решти просто губилась. Тепер
    записуємо результат назад у сам Finding, щоб "Findings" у звіті
    показував не лише здогадку заголовка (dict=..., usize=...), а й
    реальний висновок: чи це справді був потік, чи ні, і чому.
    """

    by_offset = {result.finding.offset: result for result in results if result.finding is not None}

    for finding in findings:

        result = by_offset.get(finding.offset)

        if result is None:
            # candidate існував (мав зареєстрований Extractor), але
            # extract_all() його пропустив — його офсет потрапляє в
            # діапазон уже підтвердженого сусіднього потоку
            # (skip_covered=True за замовчуванням).
            finding.extraction = "not attempted (covered by a nearby confirmed stream)"
            continue

        if result.success:
            finding.extraction = f"confirmed — decompressed {result.output_size:,} bytes"
        else:
            finding.extraction = f"failed — {result.error}"


def collect_extract_candidates(fw_map):
    findings = []

    for entry in fw_map.entries:
        if entry.kind in (
            "lzma-alone-header",
            "gzip",
            "xz",
            "bzip2",
            "zlib",
            "SquashFS (LE)",
            "SquashFS (BE)",
        ):
            findings.append(
                Finding(
                    offset=entry.offset,
                    name=entry.kind,
                    confidence=entry.confidence,
                    detail=entry.detail,
                )
            )

    return findings

def analyze_node(node: FirmwareNode, depth: int = 0) -> None:
    if depth >= MAX_DEPTH:
        return

    if len(node.data) < MIN_SIZE:
        return

    fw = build_firmware_map(node.data)
    node.firmware_map = fw

    node.code_caves = detect_code_caves(node.data, firmware_map=fw)

    findings = collect_extract_candidates(fw)
    
    node.findings.extend(findings)

    results = extract_all(node.data, findings)

    _annotate_findings_with_extraction_outcome(findings, results)

    node.strings = extract_ascii_strings(node.data)

    node.features = detect_features(node.strings)

    node.objects = detect_objects(node.data)

    analyze_objects(
        node.objects,
        node.data,
    )

    node.analysis = analyze_libraries(node.strings)

    classify_node(node)

    seen = set()

    for result in results:

        if not result.success:
            continue

        if result.entries:
            # --- Filesystem extraction (SquashFS, UBIFS, CRAMFS, ...) ---
            # Create a container node for the filesystem image itself.
            container = None

            if result.data is not None:
                digest = hashlib.sha256(result.data).digest()
                if digest not in seen:
                    seen.add(digest)
                    container = FirmwareNode(
                        name=result.method,
                        offset=result.offset,
                        data=result.data,
                        metadata={"raw_consumed_bytes": result.consumed},
                    )
                    # Pass filesystem metadata to the container node before
                    # classification, so classifiers can use it in the future.
                    if result.metadata:
                        container.analysis = dict(result.metadata)
                    classify_node(container)
                    node.add_child(container)
                    # Container is NOT recursively analyzed — its children
                    # (the extracted files) are already parsed and will be
                    # analyzed individually below.

            # Create a child node for each extracted file.
            for entry in result.entries:
                entry_digest = hashlib.sha256(entry.data).digest()
                if entry_digest in seen:
                    continue
                seen.add(entry_digest)

                child = FirmwareNode(
                    name=entry.name,
                    offset=entry.offset,
                    data=entry.data,
                )
                classify_node(child)

                # Attach to container if one was created, else to parent.
                target = container if container is not None else node
                target.add_child(child)

                analyze_node(child, depth + 1)

        elif result.data is not None:
            # --- Single-stream extraction (gzip, xz, lzma, bzip2) ---
            # (existing code, unchanged)
            digest = hashlib.sha256(result.data).digest()

            if digest in seen:
                continue

            seen.add(digest)

            child = FirmwareNode(
                name=result.method,
                offset=result.offset,
                data=result.data,
                metadata={"raw_consumed_bytes": result.consumed},
            )

            classify_node(child)

            node.add_child(child)

            analyze_node(child, depth + 1)


def main():

    parser = argparse.ArgumentParser(
        description="MStar Firmware Analyzer"
    )

    parser.add_argument(
        "firmware",
        help="Path to firmware image"
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help=(
            "Write the full report to FILE instead of the terminal "
            "(plain text — identical content to what would print "
            "on screen)."
        ),
    )

    parser.add_argument(
        "-j", "--json",
        metavar="FILE",
        dest="json_path",
        help=(
            "Also write a machine-readable JSON snapshot of the full "
            "analysis to FILE (tree, per-node features/objects/findings/"
            "code caves/library analysis, and the cross-tree summary). "
            "Independent of --output — can be used together or alone."
        ),
    )

    parser.add_argument(
        "--compare-with",
        metavar="REPORT.json",
        dest="compare_with",
        help=(
            "Compare this firmware's SDK symbol profile / capabilities / "
            "chip / libc against a PREVIOUSLY generated JSON report "
            "(i.e. produced earlier via --json on another firmware image) "
            "and print a similarity summary. Read-only — does not modify "
            "the file passed here."
        ),
    )

    args = parser.parse_args()

    firmware = Path(args.firmware)

    if not firmware.exists():
        parser.error(f"File not found: {firmware}")

    if args.compare_with and not Path(args.compare_with).exists():
        parser.error(f"--compare-with file not found: {args.compare_with}")

    if args.output:

        output_path = Path(args.output)
        # --output/--json приймають шлях, а не лише ім'я файлу (напр.
        # "reports/flash.txt") — без цього відкриття файлу в
        # неіснуючій директорії падає FileNotFoundError ще до першого
        # print() звіту.
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            with contextlib.redirect_stdout(f):
                _run(firmware, json_path=args.json_path, compare_with=args.compare_with)

        # Це йде на реальний термінал, а не у файл — redirect_stdout
        # вище вже закрився разом із блоком `with`.
        print(f"Report written to {output_path}")

    else:
        _run(firmware, json_path=args.json_path, compare_with=args.compare_with)

    return 0


def _run(firmware: Path, json_path: str | None = None, compare_with: str | None = None) -> None:

    data = firmware.read_bytes()
    root = FirmwareNode(
       name=firmware.name,
       offset=0,
       data=data,
    )
    print("=" * 70)
    print("MStar Firmware Analyzer")
    print("=" * 70)
    print()

    print(f"Input : {firmware}")
    print(f"Size  : {len(data):,} bytes")
    print()

    print("[1/3] Building firmware map...")

    fw = build_firmware_map(root.data)

    print()
    print("Entropy")
    print("-" * 70)
    print(fw.sparkline())

    print()
    print("Firmware map")
    print("-" * 70)
    print(fw.as_table())

    print()
    print("[2/3] Extracting compressed streams...")
    print()

    analyze_node(root)

    if json_path:
        report = build_json_report(root)
        json_out = Path(json_path)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"JSON report written to {json_path}")
        print()

    if compare_with:
        _render_similarity(root, compare_with)

    render_report(root)


def _render_similarity(root: FirmwareNode, compare_with: str) -> None:

    try:
        other_report = json.loads(Path(compare_with).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print()
        print(f"--compare-with: could not read/parse {compare_with}: {exc}")
        return

    other_fp_data = other_report.get("fingerprint")

    if other_fp_data is None:
        print()
        print(
            f"--compare-with: {compare_with} has no \"fingerprint\" key "
            "(likely generated by an older scanner_version without "
            "fingerprinting support) — skipping comparison."
        )
        return

    this_fp = build_fingerprint(root)
    other_fp = fingerprint_from_dict(other_fp_data)

    result = compare_fingerprints(this_fp, other_fp)

    render_similarity(compare_with, result)


if __name__ == "__main__":
    raise SystemExit(main())
