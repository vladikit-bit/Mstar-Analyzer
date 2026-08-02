"""
Stage 2 — Automatic signature scan.

Scanner API не залежить від конкретних форматів і дозволяє
додавати нові типи детекторів без зміни pipeline.

Stage 2 лише знаходить кандидатів.
Підтвердження їхньої валідності виконує Stage 5.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable


# ============================================================================
# Common data structures
# ============================================================================

@dataclass(slots=True)
class Finding:
    offset: int
    name: str
    confidence: str
    detail: str = ""
    # Заповнюється ПІСЛЯ спроби реальної декомпресії (Stage 5, extract.py) —
    # "заголовок виглядав правдоподібно" і "дані справді розпакувались"
    # це різні твердження, і друге набагато цінніше.
    extraction: str | None = None


class Scanner:
    """Base class for every signature scanner."""

    name = "base"

    def scan(self, data: bytes) -> list[Finding]:
        raise NotImplementedError


# ============================================================================
# Helper
# ============================================================================

def iter_find(data: bytes, pattern: bytes) -> Iterable[int]:
    """
    Fast generator around bytes.find().
    Avoids repeating the same while-loop everywhere.
    """
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        yield idx
        start = idx + 1


# ============================================================================
# Fixed magic signatures
# ============================================================================

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (

    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),

    (b"\x27\x05\x19\x56", "uImage (U-Boot, BE)"),
    (b"\x56\x19\x05\x27", "uImage (U-Boot, LE)"),


    (b"UBI#", "UBI"),
    (b"UBI!", "UBI erase counter"),

    (b"hsqs", "SquashFS (LE)"),
    (b"sqsh", "SquashFS (BE)"),

    (b"\x45\x3d\xcd\x28", "cramfs"),

    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),

    (b"\xd0\x0d\xfe\xed", "DTB"),

    (b"\x7fELF", "ELF"),
)


class MagicScanner(Scanner):

    name = "magic"

    def scan(self, data: bytes) -> list[Finding]:

        findings: list[Finding] = []

        for magic, label in MAGIC_SIGNATURES:

            for offset in iter_find(data, magic):

                findings.append(
                    Finding(
                        offset=offset,
                        name=label,
                        confidence="high",
                    )
                )

        return findings


# ============================================================================
# Temporary ASCII scanner
#
# NOTE:
# Після появи Stage6 StringsExtractor цей Scanner можна буде
# повністю видалити без зміни інших Stage.
# ============================================================================

ASCII_MARKERS = (

    "MSTAR",
    "MStar",
    "MSTARSEMI",

    "Hello Hummingbird",

    "MBOOT",
    "MBOT-",

    "eCos",
    "eCosPro",

    "MsOS_",
    "MDrv_",
    "MApi_",

    "appZapper",
    "appPvr",
    "appDevMgr",

    "BOOTLOGO_IN_MBOOT",

    "CONFIG_HASH2_START_ADDRESS",

    "Board=",
    "Security=",
    "MBoot_IN=",
)


class AsciiMarkerScanner(Scanner):

    name = "ascii-marker"

    def scan(self, data: bytes) -> list[Finding]:

        findings: list[Finding] = []

        for marker in ASCII_MARKERS:

            encoded = marker.encode("ascii")

            for offset in iter_find(data, encoded):

                findings.append(
                    Finding(
                        offset=offset,
                        name=f"marker:{marker}",
                        confidence="medium",
                    )
                )

        return findings


# ============================================================================
# LZMA dictionary sizes
# ============================================================================

_VALID_DICT_SIZES: set[int] = set()

for n in range(31):

    _VALID_DICT_SIZES.add(1 << n)

    if n:

        _VALID_DICT_SIZES.add(
            (1 << n) + (1 << (n - 1))
        )


def _decode_properties(props: int):

    if props > 224:
        return None

    lc = props % 9

    rem = props // 9

    lp = rem % 5

    pb = rem // 5

    if pb > 4:
        return None

    if lc + lp > 4:
        return None

    return lc, lp, pb
# ============================================================================
# LZMA heuristic scanner
# ============================================================================

class LzmaHeuristicScanner(Scanner):
    """
    Пошук класичного LZMA-alone заголовка.

    Stage 2 лише знаходить кандидата.
    Остаточне підтвердження робить Stage 5
    через реальну декомпресію.
    """

    name = "lzma-heuristic"

    MIN_HEADER = 13

    def scan(self, data: bytes) -> list[Finding]:

        findings: list[Finding] = []

        n = len(data)

        if n < self.MIN_HEADER:
            return findings

        limit = n - self.MIN_HEADER + 1

        for offset in range(limit):

            decoded = _decode_properties(data[offset])

            if decoded is None:
                continue

            lc, lp, pb = decoded

            dict_size = struct.unpack_from("<I", data, offset + 1)[0]

            if dict_size == 0:
                continue

            if dict_size > (1 << 30):
                continue

            if dict_size in _VALID_DICT_SIZES:
                confidence = "medium"
            else:
                confidence = "low"

            usize = struct.unpack_from("<Q", data, offset + 5)[0]

            if usize != 0xFFFFFFFFFFFFFFFF:

                if usize == 0:
                    continue

                if usize > (1 << 30):
                    continue

            # ---------------------------------------------------------
            # Додаткова евристика.
            #
            # Після заголовка має бути хоча б кілька ненульових байтів.
            # Це різко зменшує кількість випадкових збігів.
            # ---------------------------------------------------------

            payload = data[offset + 13 : offset + 21]

            if len(payload) < 4:
                continue

            if payload == b"\x00" * len(payload):
                continue

            findings.append(
                Finding(
                    offset=offset,
                    name="lzma-alone-header",
                    confidence=confidence,
                    detail=(
                        f"lc={lc} "
                        f"lp={lp} "
                        f"pb={pb} "
                        f"dict=0x{dict_size:X} "
                        f"usize=0x{usize:X}"
                    ),
                )
            )

        return findings
    
# ============================================================================
# Zlib heuristic scanner
# ============================================================================

def _zlib_header_ok(cmf: int, flg: int) -> bool:
    """
    RFC 1950 §2.2: CMF/FLG, 2-байтний заголовок сирого zlib/deflate потоку.
    """

    if (cmf & 0x0F) != 8:
        # CM (compression method) — 8 = deflate, єдиний метод, який
        # реально трапляється (інші значення специфікація залишає
        # невизначеними). Без цього кожен другий випадковий байт
        # проходив би далі.
        return False

    cinfo = (cmf >> 4) & 0x0F

    if cinfo > 7:
        # CINFO кодує log2(window_size) - 8. RFC дозволяє й більші
        # значення для CM=8, але на практиці (zlib/miniz/vendor-порти)
        # вікно ніколи не перевищує 32 KiB (CINFO=7) — значення 8-15
        # тут майже напевно випадковий байт, що випадково пройшов
        # checksum нижче.
        return False

    if (flg >> 5) & 1:
        # FDICT: перед стисненими даними йшов би ще 4-байтний DICTID
        # (ідентифікатор preset dictionary). Прошивки цим на практиці
        # не користуються — а без реального dictionary ID перевірити
        # FDICT-кандидата все одно нічим, тож він лише додав би шуму.
        return False

    return (cmf * 256 + flg) % 31 == 0


class ZlibHeuristicScanner(Scanner):
    """
    Пошук сирого zlib/deflate потоку (RFC 1950) — на відміну від gzip/xz/
    bzip2 (MagicScanner, фіксовані 3-6-байтні magic), у zlib немає
    окремого magic number: лише 2-байтний CMF/FLG заголовок із
    контрольною сумою (cmf*256+flg) % 31 == 0.

    2 байти дають набагато вищу базову ймовірність випадкового
    структурно-валідного збігу, ніж magic-сигнатури (порядку 1/2048 на
    позицію серед CM=8/CINFO<=7 заголовків, а не ~1/2^24+ як у gzip/xz).
    Тому, так само як LzmaHeuristicScanner: викликається лише всередині
    high-entropy регіонів (firmware_map.py), а не по всьому файлу — це
    і на порядки швидше, і різко знижує кількість випадкових
    спрацювань на структурованих/малоентропійних ділянках, де справжній
    zlib-потік однаково не зустрінеться.

    ZlibExtractor (extractors/zlib.py) — сама декомпресія — існував і
    був покритий тестами задовго до цього сканера, але без Finding із
    цим ім'ям ("zlib") жоден candidate ніколи не будувався: Stage 2
    просто не мав звідки його взяти. Цей сканер закриває саме цю
    прогалину.

    Stage 2 лише знаходить кандидата. Остаточне підтвердження — реальна
    декомпресія в Stage 5 (ExtractorFactory реєструє "zlib" ->
    ZlibExtractor, extractors/factory.py).
    """

    name = "zlib-heuristic"

    MIN_HEADER = 2

    def scan(self, data: bytes) -> list[Finding]:

        findings: list[Finding] = []

        n = len(data)

        if n < self.MIN_HEADER:
            return findings

        limit = n - self.MIN_HEADER + 1

        for offset in range(limit):

            cmf = data[offset]
            flg = data[offset + 1]

            if not _zlib_header_ok(cmf, flg):
                continue

            # ---------------------------------------------------------
            # Додаткова евристика, симетрична LzmaHeuristicScanner.
            #
            # Після заголовка має бути хоча б кілька ненульових байтів —
            # відкидає найочевидніший шум (прогін заповнювача 0x00,
            # два байти якого випадково пройшли checksum: cmf=0x00
            # трапляється рідко через вимогу CM=8, але зустрічний
            # 0x08/0x?? заповнювач — цілком можливий випадковий збіг).
            # ---------------------------------------------------------

            payload = data[offset + 2 : offset + 6]

            if len(payload) < 4:
                continue

            if payload == b"\x00" * len(payload):
                continue

            cinfo = (cmf >> 4) & 0x0F
            flevel = (flg >> 6) & 0x03

            findings.append(
                Finding(
                    offset=offset,
                    name="zlib",
                    confidence="medium",
                    detail=(
                        f"cinfo={cinfo} "
                        f"(window={1 << (cinfo + 8)}) "
                        f"flevel={flevel}"
                    ),
                )
            )

        return findings

# ============================================================================
# JFFS2 Scanner
# ============================================================================

import binascii


class Jffs2Scanner(Scanner):
    """
    Пошук реальних JFFS2 node.

    На відміну від простого пошуку magic,
    перевіряє структуру заголовка.
    """

    name = "jffs2"

    HEADER_SIZE = 12

    def scan(self, data: bytes) -> list[Finding]:

        findings: list[Finding] = []

        limit = len(data) - self.HEADER_SIZE

        for offset in range(limit):

            magic = data[offset:offset + 2]

            if magic == b"\x19\x85":
                endian = "<"

            elif magic == b"\x85\x19":
                endian = ">"

            else:
                continue

            try:

                nodetype = struct.unpack_from(
                    endian + "H",
                    data,
                    offset + 2,
                )[0]

                totlen = struct.unpack_from(
                    endian + "I",
                    data,
                    offset + 4,
                )[0]

                hdr_crc = struct.unpack_from(
                    endian + "I",
                    data,
                    offset + 8,
                )[0]

            except struct.error:
                continue

            #
            # Базова перевірка довжини
            #

            if totlen < 12:
                continue

            if totlen > len(data) - offset:
                continue

            #
            # CRC першої частини заголовка
            #

            header = data[offset:offset + 8]

            calc_crc = (
                binascii.crc32(header, -1)
                ^ 0xFFFFFFFF
            ) & 0xFFFFFFFF

            if calc_crc != hdr_crc:
                continue

            findings.append(
                Finding(
                    offset=offset,
                    name="JFFS2 node",
                    confidence="high",
                    detail=(
                        f"type=0x{nodetype:04X} "
                        f"len={totlen}"
                    ),
                )
            )

        return findings

# ============================================================================
# Registry
# ============================================================================

DEFAULT_SCANNERS: tuple[Scanner, ...] = (

    MagicScanner(),

    AsciiMarkerScanner(),

    LzmaHeuristicScanner(),

    ZlibHeuristicScanner(),

    Jffs2Scanner(),
    
)


# ============================================================================
# Public API
# ============================================================================

def scan_all(
    data: bytes,
    scanners: list[Scanner] | tuple[Scanner, ...] | None = None,
) -> list[Finding]:
    """
    Запустити всі Scanner та повернути
    відсортований список Finding.
    """

    if scanners is None:
        scanners = DEFAULT_SCANNERS

    findings: list[Finding] = []

    for scanner in scanners:

        try:

            findings.extend(scanner.scan(data))

        except Exception as exc:

            findings.append(
                Finding(
                    offset=0,
                    name=f"scanner-error:{scanner.name}",
                    confidence="low",
                    detail=str(exc),
                )
            )

    findings.sort(
        key=lambda f: (
            f.offset,
            f.name,
        )
    )

    return findings
