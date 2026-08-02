from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..firmware_tree import FirmwareNode


COMPRESSION_BY_NAME: dict[str, tuple[str, str]] = {
    "lzma-alone": ("LZMA", "LZMA"),
    "gzip": ("gzip", "gzip"),
    "xz": ("XZ", "XZ"),
    # BZip2Extractor.method == "bzip2" (extractors/bzip2.py) — цей запис
    # був відсутній, тож bzip2-вузли мовчки лишались БЕЗ node.format/
    # node.compression (None замість "bzip2"), на відміну від gzip/xz/
    # lzma-alone. Видно одразу в трьох місцях, що читають ці поля:
    # firmware_tree.pretty() не друкує тег "[bzip2]" у дереві,
    # json_export.py віддає null замість "bzip2", а flash_layout.py
    # підміняє лейбл на "blob stream" замість "bzip2 stream".
    "bzip2": ("bzip2", "bzip2"),
    # ZlibExtractor.method == "zlib" (extractors/zlib.py) — щойно
    # підключений до Stage 2/5 (ZlibHeuristicScanner + factory.py).
    "zlib": ("zlib", "zlib"),
}


# Maps Extractor.method -> (format, node_type, label)
# For filesystem containers. Single-stream compressors use
# COMPRESSION_BY_NAME instead.
FILESYSTEM_BY_NAME: dict[str, tuple[str, str, str]] = {
    "squashfs": ("squashfs", "filesystem", "SquashFS filesystem"),
    # Future: "ubifs": ("ubifs", "filesystem", "UBI filesystem"),
    # Future: "cramfs": ("cramfs", "filesystem", "CramFS filesystem"),
}


def _has_feature(name: str) -> Callable[[set[str], dict], bool]:
    return lambda features, analysis: name in features


def _has_analysis(key: str) -> Callable[[set[str], dict], bool]:
    return lambda features, analysis: bool(analysis.get(key))


@dataclass(frozen=True)
class ClassificationRule:
    node_type: str
    label: str
    matches: Callable[[set[str], dict], bool]


# Таблиця замість if/elif — новий тип вузла це один запис, а не ще одна
# гілка. Перше правило, що збіглося, перемагає (порядок важливий).
#
# "MStar Bootloader" -> "eCos system image (MBoot)" і "Streaming Engine"
# -> "Network/streaming module" — свідомо НЕ голі "Bootloader"/
# "Streaming Engine": в обох випадках у вузлі реально знайдено набагато
# більше, ніж сама назва натякає (весь eCos-стек з драйверами/
# OpenSSL/FFmpeg/Lua у "завантажувачі" на 33 МБ; повноцінний мережевий
# медіа-клієнт, а не лише "стрімінг", у другому — судячи з
# [NetSrv]/Download Module/g_stClientList евіденсу). Лейбл каже, ЩО
# розпізнано впевнено ПЕРШИМ, а не стверджує, що це ЄДИНИЙ вміст —
# повний перелік завжди видно у "Detected features" нижче в звіті.
CLASSIFIERS: tuple[ClassificationRule, ...] = (
    ClassificationRule(
        node_type="bootloader",
        label="eCos system image (MBoot)",
        matches=_has_feature("MStar Bootloader"),
    ),
    ClassificationRule(
        node_type="application",
        label="Network/streaming module",
        matches=_has_feature("Streaming Engine"),
    ),
    ClassificationRule(
        node_type="multimedia",
        label="FFmpeg module",
        matches=_has_analysis("ffmpeg"),
    ),
    ClassificationRule(
        node_type="library",
        label="OpenSSL library",
        matches=_has_analysis("openssl"),
    ),
)


def classify_node(node: FirmwareNode) -> None:
    """
    Populate FirmwareNode metadata.

    This module is responsible only for semantic classification.
    It never parses firmware by itself.
    """

    # -------------------------------------------------
    # Filesystem containers
    # -------------------------------------------------

    fs_info = FILESYSTEM_BY_NAME.get(node.name)

    if fs_info is not None:
        node.format, node.node_type, node.label = fs_info
        return  # Skip compression and semantic classification for containers

    # -------------------------------------------------
    # Compression
    # -------------------------------------------------

    compression = COMPRESSION_BY_NAME.get(node.name)

    if compression is not None:
        node.compression, node.format = compression

    # -------------------------------------------------
    # Default node type / label
    # -------------------------------------------------

    node.node_type = "blob"

    if node.format:
        node.label = f"{node.format} stream"
    else:
        node.label = node.name

    # -------------------------------------------------
    # Semantic classification
    # -------------------------------------------------

    feature_names = {f.name for f in node.features}
    analysis = node.analysis

    for rule in CLASSIFIERS:
        if rule.matches(feature_names, analysis):
            node.node_type = rule.node_type
            node.label = rule.label
            break
