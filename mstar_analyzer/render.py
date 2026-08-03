from __future__ import annotations

from .firmware_tree import FirmwareNode
from .string_filter import filter_strings
from .renderers import RENDERERS
from .renderers.summary import render_cross_tree_summary
from .detectors.features import FEATURE_CONFIDENCE_MARKER
from .analyzers.squashfs import SquashFsInfo
from .flash_layout import FlashLayout, build_flash_layout
from .fingerprint import SimilarityResult


def render_squashfs(summary: SquashFsInfo) -> None:
    """
    Render SquashFS filesystem metadata for a container node.

    Called from render_node_analysis() via the RENDERERS registry.
    """

    if summary is None:
        return

    print()
    print("SquashFS analysis")
    print("-" * 70)

    print(f"Version     : {summary.version}")
    print(f"Endian      : {summary.endian}")
    print(f"Compression : {summary.compression}")
    print(f"Block size  : {summary.block_size:,} bytes")
    print(f"Inode count : {summary.inode_count}")
    print(f"Image size  : {summary.image_size:,} bytes")


# Register the SquashFS renderer in the shared RENDERERS dict so that
# render_node_analysis() picks it up automatically — consistent with
# the existing ffmpeg/openssl/runtime/sdk_symbols renderers, and no
# changes needed to render_node_analysis() itself.
RENDERERS["squashfs"] = render_squashfs


def render_tree(root: FirmwareNode) -> None:

    print()
    print("Firmware tree")
    print("-" * 70)

    print(root.pretty())


def render_flash_layout(layout: FlashLayout) -> None:
    """
    Синтезоване, іменовані зведення "flash map" — на відміну від
    "Firmware map" (build_firmware_map/FirmwareMap.as_table(), сирий
    точковий скан magic/entropy знахідок), тут — впорядкований,
    суцільний (без прогалин/перекриттів) список меж [start, end) з
    людяними лейблами, кожен або спирається на конкретний провалідований
    доказ (об'єкт/розпакований потік), або чесно позначений
    ентропійною міткою там, де доказу немає.
    """

    if not layout.regions:
        return

    print()
    print("Flash layout")
    print("-" * 70)

    for r in layout.regions:

        marker = "✓" if r.confidence == "high" else "?"

        line = f"{marker} 0x{r.start:08X} - 0x{r.end:08X}  ({r.size:>8,} bytes)  {r.label}"

        if r.detail:
            line += f"  [{r.detail}]"

        print(line)


def render_similarity(compared_with: str, result: SimilarityResult) -> None:
    """
    --compare-with: показує наскільки СИМВОЛИ SDK / capabilities / чип /
    libc цієї прошивки збігаються з раніше збереженим fingerprint іншої
    (з JSON, згенерованого попереднім прогоном --json на іншому файлі).
    Індекс Жаккара на кожному сигналі окремо + один зважений
    "overall" — навмисно з приміткою, що вага суб'єктивна, а не
    стандартна формула.
    """

    print()
    print("Similarity comparison")
    print("-" * 70)
    print(f"Compared with : {compared_with}")
    print()
    print(f"Overall similarity : {result.overall_score:.0%}  (weighted heuristic — see below, not a precise measurement)")

    if result.sdk_symbol_similarity:
        print()
        print("SDK symbols:")
        for category, sim in sorted(result.sdk_symbol_similarity.items(), key=lambda kv: -kv[1].jaccard):
            print(f"    {category:<12} {sim.jaccard:>5.0%}  ({sim.shared} shared / {sim.total} total)")

    print()
    print(
        f"Capabilities  : {result.capabilities_similarity:.0%}  "
        f"({result.capabilities_shared} shared / {result.capabilities_total} total)"
    )

    chip_line = "match" if result.chip_match else "no match / unknown"
    if result.shared_chip_models:
        chip_line += " (" + ", ".join(sorted(result.shared_chip_models)) + ")"
    print(f"Chip model    : {chip_line}")

    print(f"LibC          : {'match' if result.libc_match else 'no match / unknown'}")

    if result.shared_ecos_versions:
        print(f"eCos packages : {len(result.shared_ecos_versions)} shared version(s) — " + ", ".join(sorted(result.shared_ecos_versions)))


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

    render_flash_layout(build_flash_layout(root))

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
def render_node_features(node: FirmwareNode) -> None:

    if not node.features:
        return

    print()
    print("Detected features")
    print("-" * 70)

    for feature in node.features:

        marker = FEATURE_CONFIDENCE_MARKER.get(feature.confidence, "?")

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

                _render_metadata_value(key, value, indent="               ")


# Скільки елементів списку показувати перед "... (+N more)" — той самий
# компроміс, що вже застосований у SDK symbol profile (renderers/sdk_symbols.py
# MAX_EXAMPLES): досить, щоб дати уявлення про вміст, замало, щоб один
# об'єкт з довгим списком (напр. MBoot з 40+ змінними) не забив увесь звіт.
_METADATA_LIST_PREVIEW = 8


def _render_metadata_value(key: str, value: object, indent: str) -> None:
    """
    obj.metadata значення — довільні (str/int/bool/список/словник/None),
    бо різні аналізатори (MBoot env block, Lua header, DTB root
    properties) кладуть туди що їм потрібно. Раніше все йшло через один
    generic f"{key}: {value}" — для скалярів це нормально, але для
    list[dict] (mboot_variables), list[str] (Lua header_issues) чи
    просто dict (DTB root_properties) виходив сирий Python repr
    ("[{'name': 'Board', 'value': ...}]" / "{'model': '...', ...}"),
    який важко читати. Тут — та сама генерична обробка, лише з трьома
    додатковими формами (list[dict] / list[скаляр] / dict), а не
    спеціальний код під кожен ключ/obj.kind окремо.
    """

    if isinstance(value, (list, dict)) and not value:
        return

    if key == "fit" and isinstance(value, dict):

        # FIT (Flattened Image Tree, DTB із вузлами images/configurations)
        # — генеричний "плаский словник" формат нижче тут не підходить:
        # images/configurations самі по собі dict[ім'я -> dict властивостей],
        # подвійна вкладеність, а не пара ключ-значення.
        print(f"{indent}{key}:")

        images = value.get("images")

        if images:
            print(f"{indent}    images:")
            for name, props in images.items():
                descriptor = ", ".join(
                    str(props[k]) for k in ("type", "os", "arch", "compression") if props.get(k)
                )
                line = f"{indent}        {name}"
                if props.get("description"):
                    line += f": {props['description']}"
                if descriptor:
                    line += f" ({descriptor})"
                print(line)

        configurations = value.get("configurations")

        if configurations:
            print(f"{indent}    configurations:")
            for name, props in configurations.items():
                refs = ", ".join(
                    f"{k}={props[k]}" for k in ("kernel", "firmware", "fdt", "ramdisk") if props.get(k)
                )
                line = f"{indent}        {name}"
                if props.get("description"):
                    line += f": {props['description']}"
                if refs:
                    line += f" ({refs})"
                print(line)

        if value.get("default_configuration"):
            print(f"{indent}    default configuration: {value['default_configuration']}")

        return

    if isinstance(value, dict):

        # Плаский словник (напр. DTB root_properties: model/compatible)
        # — "ключ: значення" по одному на рядок, без Python repr фігурних
        # дужок і лапок навколо всього.
        print(f"{indent}{key}:")

        for sub_key, sub_value in value.items():
            print(f"{indent}    {sub_key}: {sub_value}")

        return

    if isinstance(value, list) and all(isinstance(item, dict) for item in value):

        # Список "записів" (mboot_variables і будь-що подібне в
        # майбутньому) — окремих аналізаторів під кожен формат не
        # заводимо, натомість: якщо є пара name/value — показуємо як
        # "name = value" (найчастіший випадок), інакше — компактний
        # key=val перелік по всіх полях запису.
        print(f"{indent}{key} ({len(value)}):")

        for item in value[:_METADATA_LIST_PREVIEW]:

            if "name" in item and "value" in item:
                extra = {k: v for k, v in item.items() if k not in ("name", "value")}
                line = f"{indent}    {item['name']} = {item['value']}"
                if extra:
                    line += "  (" + ", ".join(f"{k}={v}" for k, v in extra.items()) + ")"
                print(line)
            else:
                print(f"{indent}    " + ", ".join(f"{k}={v}" for k, v in item.items()))

        remaining = len(value) - _METADATA_LIST_PREVIEW
        if remaining > 0:
            print(f"{indent}    ... (+{remaining} more)")

        return

    if isinstance(value, list):

        # Список скалярів (Lua header_issues тощо) — маркований список
        # замість одного рядка з квадратними дужками та лапками.
        print(f"{indent}{key} ({len(value)}):")

        for item in value[:_METADATA_LIST_PREVIEW]:
            print(f"{indent}    - {item}")

        remaining = len(value) - _METADATA_LIST_PREVIEW
        if remaining > 0:
            print(f"{indent}    ... (+{remaining} more)")

        return

    print(f"{indent}{key}: {value}")