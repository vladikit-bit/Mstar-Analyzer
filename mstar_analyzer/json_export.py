"""
JSON export.

Машиночитаний знімок усього результату аналізу — те, чого бракувало,
щоб побудувати щось поверх аналізатора (Ghidra-скрипт для перейменування
символів, HTML/web-звіт, diff між прошивками, збереження в базу) без
парсингу тексту з stdout.

Свідомо НЕ намагається серіалізувати внутрішні об'єкти реалізації
(скомпільовані regex у Signature, самі Extractor/Scanner-класи тощо) —
лише результати аналізу, які має сенс споживати ззовні.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any

from . import __version__ as SCANNER_VERSION
from .firmware_tree import FirmwareNode
from .reporting import collect_ffmpeg, collect_libpng, collect_openssl, collect_runtime

# Версія САМЕ ФОРМАТУ JSON-звіту — окрема вісь від SCANNER_VERSION
# (версії інструмента). Інструмент може випустити новий реліз, не
# змінивши структуру звіту; а зміна структури (нове поле, перейменування,
# інша форма "nodes") має піднімати саме цей номер, щоб зовнішні
# споживачі (скрипти, БД, diff-тули) могли безпечно розрізняти "той
# самий формат" від "треба оновити парсер".
SCHEMA_VERSION = 1


def _jsonify(value: Any) -> Any:
    """
    Загальний рекурсивний конвертер для "простих" dataclass'ів
    аналізаторів (OpenSSLInfo, FFmpegInfo, BusyBoxInfo, RuntimeInfo,
    SdkSymbolProfile, Finding, CodeCave, ...) — усі вони складаються
    лише зі str/int/bool/set/dict/list, тому безпечні для generic
    інтроспекції. НЕ використовується для Feature/EmbeddedObject —
    у них є поля, які або посилаються на внутрішні об'єкти (Feature.
    matched_signatures — компільовані regex), або потребують
    вибіркового відбору полів; для них є окремі явні конвертери нижче.
    """

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _jsonify(getattr(value, f.name))
            for f in dataclasses.fields(value)
        }

    if isinstance(value, set):
        return sorted(_jsonify(v) for v in value)

    if isinstance(value, dict):
        return {str(k): _jsonify(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [_jsonify(v) for v in value]

    return value


def _feature_to_dict(feature) -> dict:
    return {
        "name": feature.name,
        "score": feature.score,
        "confidence": feature.confidence,
        "evidence": feature.evidence,
    }


def _object_to_dict(obj) -> dict:
    return {
        "offset": obj.offset,
        "size": obj.size,
        "kind": obj.kind,
        "description": obj.description,
        "confidence": obj.confidence,
        "validated": obj.validated,
        "metadata": _jsonify(obj.metadata),
    }


def _finding_to_dict(finding) -> dict:
    return {
        "offset": finding.offset,
        "name": finding.name,
        "confidence": finding.confidence,
        "detail": finding.detail,
        "extraction": finding.extraction,
    }


def _cave_to_dict(cave) -> dict:
    return {
        "offset": cave.offset,
        "size": cave.size,
        "fill_byte": cave.fill_byte,
        "in_code_region": cave.in_code_region,
    }


# analysis-ключ -> (JSON-ключ у виводі); значення завжди простий
# dataclass, тому йде через загальний _jsonify().
_ANALYSIS_KEYS = ("openssl", "ffmpeg", "busybox", "runtime", "sdk_symbols")


def _node_to_dict(node: FirmwareNode) -> dict:

    entry: dict[str, Any] = {
        "name": node.name,
        "offset": node.offset,
        "size": node.size,
        "label": node.label,
        "display_path": node.display_path,
        "node_type": node.node_type,
        "format": node.format,
        "compression": node.compression,
        "features": [_feature_to_dict(f) for f in node.features],
        "objects": [_object_to_dict(o) for o in node.objects],
        "findings": [_finding_to_dict(f) for f in node.findings],
        "code_caves": [_cave_to_dict(c) for c in node.code_caves],
    }

    for key in _ANALYSIS_KEYS:
        info = node.analysis.get(key)
        entry[key] = _jsonify(info) if info is not None else None

    return entry


def _tree_to_dict(node: FirmwareNode, node_ids: dict[int, str]) -> dict:

    entry = _node_to_dict(node)
    entry["id"] = node_ids[id(node)]
    entry["children"] = [_tree_to_dict(child, node_ids) for child in node.children]

    return entry


def build_json_report(root: FirmwareNode) -> dict:
    """
    Повний знімок результату аналізу як звичайний dict, готовий для
    json.dump(). Дві форми одних і тих самих даних:

      "tree"  — ієрархія (потрібна, щоб бачити структуру: що з чого
                видобуто);
      "nodes" — той самий вміст плоским словником за монотонним "id"
                (зручніше для швидкого пошуку/lookup без обходу дерева).

    Ключ "nodes" НАВМИСНО не display_path: класифікатор (classify_node)
    призначає label за фіксованою таблицею правил ("OpenSSL library",
    "FFmpeg module", ...), тож два РІЗНІ вузли одного дерева цілком можуть
    отримати ІДЕНТИЧНИЙ display_path (напр. дві незалежні OpenSSL-бібліотеки,
    розпаковані в різних гілках, — обидві "... / OpenSSL library"). Ключ за
    display_path у такому випадку мовчки втратив би один з двох вузлів.
    display_path лишається в кожному записі як зручне ЛЮДСЬКО-читабельне
    поле, просто вже не є унікальним ідентифікатором.
    """

    node_ids: dict[int, str] = {
        id(node): f"n{index}"
        for index, node in enumerate(root.walk())
    }

    nodes: dict[str, dict] = {}

    for node in root.walk():
        node_id = node_ids[id(node)]
        entry = _node_to_dict(node)
        entry["id"] = node_id
        nodes[node_id] = entry

    runtime = collect_runtime(root)
    openssl = collect_openssl(root)
    ffmpeg = collect_ffmpeg(root)
    libpng = collect_libpng(root)

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "firmware": {
            "name": root.name,
            "size": root.size,
        },
        "tree": _tree_to_dict(root, node_ids),
        "nodes": nodes,
        "cross_tree_summary": {
            "runtime": _jsonify(runtime) if runtime is not None else None,
            "openssl": _jsonify(openssl) if openssl is not None else None,
            "ffmpeg": _jsonify(ffmpeg) if ffmpeg is not None else None,
            "libpng": _jsonify(libpng) if libpng is not None else None,
        },
    }
