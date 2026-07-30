from __future__ import annotations

from .firmware_tree import FirmwareNode
from .string_filter import filter_strings
from .renderers import RENDERERS
from .renderers.summary import render_cross_tree_summary


def render_tree(root: FirmwareNode) -> None:

    print()
    print("Firmware tree")
    print("-" * 70)

    print(root.pretty())


def render_summary(root: FirmwareNode) -> None:

    total_nodes = sum(1 for _ in root.walk())

    print()
    print("[3/3] Summary")
    print("-" * 70)

    print(f"Nodes : {total_nodes}")
    print(f"Children : {len(root.children)}")


def render_report(root: FirmwareNode) -> None:

    render_summary(root)

    render_tree(root)

    render_cross_tree_summary(root)

    for node in root.walk():
        render_node(node)


def render_node(node: FirmwareNode) -> None:

    print()
    print("=" * 70)
    print(node.display_path)
    print("=" * 70)

    render_node_features(node)

    render_node_objects(node)

    render_node_analysis(node)

    render_node_findings(node)

    render_node_code_caves(node)

    render_node_strings(node)


def render_node_analysis(node: FirmwareNode) -> None:

    if not node.analysis:
        return

    for name, renderer in RENDERERS.items():

        summary = node.analysis.get(name)

        if summary:
            renderer(summary)


def render_node_strings(node: FirmwareNode) -> None:

    strings = filter_strings(node.strings)

    if not strings:
        return

    print()
    print("Strings")
    print("-" * 70)

    for s in strings[:40]:
        print(f"0x{s.offset:08X}  {s.text}")

    if len(strings) > 40:
        print(f"... ({len(strings)-40} more)")


def _print_finding_line(f) -> None:

    line = (
        f"0x{f.offset:08X}   "
        f"{f.name:<32}"
        f"{f.confidence:<8}"
    )

    if f.detail:
        line += "   " + f.detail

    print(line)

    if f.extraction:
        print(f"               -> {f.extraction}")


def render_node_findings(node: FirmwareNode) -> None:

    if not node.findings:
        return

    print()
    print("Findings")
    print("-" * 70)

    # extract_all() вже РЕАЛЬНО перевірив кожен candidate (Stage 5), тому
    # "confidence" (лише здогадка з форми заголовка ще ДО спроби
    # декомпресії) для тих, що провалились, уже застаріла інформація —
    # ми точно знаємо, що це не реальний потік. Друкувати кожен такий
    # провал повним рядком лише засмічує звіт (у реальних прошивках їх
    # регулярно 15-20+ на вузол); підтверджені потоки натомість завжди
    # варто бачити повністю.
    confirmed = []
    rejected = []
    unresolved = []

    for f in node.findings:

        if f.extraction is None:
            unresolved.append(f)
        elif f.extraction.startswith("confirmed"):
            confirmed.append(f)
        else:
            rejected.append(f)

    for f in sorted(confirmed + unresolved, key=lambda x: x.offset):
        _print_finding_line(f)

    if not rejected:
        return

    if len(rejected) <= 3:

        for f in sorted(rejected, key=lambda x: x.offset):
            _print_finding_line(f)

        return

    failed = [f for f in rejected if f.extraction.startswith("failed")]
    skipped = [f for f in rejected if f.extraction.startswith("not attempted")]

    parts = []

    if failed:
        parts.append(f"{len(failed)} candidate{'s' if len(failed) != 1 else ''} failed to decompress (not real streams)")

    if skipped:
        parts.append(f"{len(skipped)} skipped (covered by a nearby confirmed stream)")

    sample_offsets = ", ".join(f"0x{f.offset:08X}" for f in sorted(rejected, key=lambda x: x.offset)[:5])

    if len(rejected) > 5:
        sample_offsets += ", ..."

    print()
    print(f"({' + '.join(parts)}; offsets: {sample_offsets})")


# Показуємо не більше N найбільших кандидатів у code-регіонах — реальна
# незапрограмована флеш-пам'ять може дати сотні прогонів 0xFF, і як з
# LZMA Findings, повний список лише засмічує звіт.
MAX_CODE_CAVES_SHOWN = 15


def render_node_code_caves(node: FirmwareNode) -> None:

    if not node.code_caves:
        return

    in_code = [c for c in node.code_caves if c.in_code_region]
    elsewhere_count = len(node.code_caves) - len(in_code)

    if not in_code:
        return

    print()
    print("Code cave candidates")
    print("-" * 70)
    print(
        "(candidates only — form-based, not disassembly-verified; "
        "confirm executability and safety manually before patching)"
    )
    print()

    in_code.sort(key=lambda c: c.size, reverse=True)

    for cave in in_code[:MAX_CODE_CAVES_SHOWN]:
        fill = f"0x{cave.fill_byte:02X}"
        print(f"0x{cave.offset:08X}   {cave.size:>6,} bytes   fill={fill}")

    hidden = len(in_code) - MAX_CODE_CAVES_SHOWN

    if hidden > 0:
        print(f"... ({hidden} more, smaller candidates not shown)")

    if elsewhere_count > 0:
        print(
            f"({elsewhere_count} additional same-byte run(s) found outside "
            f"code regions — skipped, not useful for a code cave)"
        )


# Феча — це сукупний score з УСІХ сигнатур, що збіглися під цим іменем
# (детально: detectors/features.py Feature.score / score_to_confidence),
# тож "✓" однаковий і для 5-очкового поодинокого слабкого патерна
# ("eygp3-ge" -> Graphics Engine WEAK), і для 100+-очкового підтвердженого
# (MDrv_GE_*) виглядало як однаково надійний доказ. Три різні маркери
# замість одного "✓" — щоб різницю між "вартий довіри" і "варто
# перевірити вручну" було видно з першого погляду, без походу у JSON.
_FEATURE_CONFIDENCE_MARKER = {
    "HIGH": "✓",
    "MEDIUM": "~",
    "LOW": "?",
}


def render_node_features(node: FirmwareNode) -> None:

    if not node.features:
        return

    print()
    print("Detected features")
    print("-" * 70)

    for feature in node.features:

        marker = _FEATURE_CONFIDENCE_MARKER.get(feature.confidence, "?")

        print(f"{marker} {feature.name}  [{feature.confidence}, score={feature.score}]")
        print(f"    evidence: {feature.evidence}")


def render_node_objects(node: FirmwareNode) -> None:

    if not node.objects:
        return

    print()
    print("Embedded objects")
    print("-" * 70)

    for obj in sorted(node.objects, key=lambda x: x.offset):

        line = (
            f"0x{obj.offset:08X}   "
            f"{obj.kind:<16}"
            f"{obj.confidence:<8}"
            f"{obj.description}"
        )

        print(line)

        if obj.metadata:

            for key, value in obj.metadata.items():

                if value is None:
                    continue

                print(f"               {key}: {value}")