from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding

# FourCC -> людяна назва. Свідомо не намагаємось бути повним реєстром
# (fourcc.org налічує сотні записів) — цей набір покриває реальні,
# підтверджені прошивками MStar STB/TV кодеки (DIVX/DX50/H263/H264/
# DIV3/MJPG/XVID/FMP4 — усі з фактичної таблиці в реальній прошивці) і
# найближчих родичів того самого сімейства. Розширювати за потреби,
# додаючи новий рядок — той самий принцип "нова сигнатура в списку",
# що й у detectors/features.py SIGNATURES.
#
# Ключі — завжди у ВЕРХНЬОМУ регістрі: пошук у таблиці регістронезалежний
# (.upper() перед lookup), а сам оригінальний регістр з прошивки
# зберігається окремо в CodecTableEntry.fourcc для відображення "як є"
# (деякі таблиці навмисно містять і "DIVX", і "divx" як два окремі
# записи — це ознака case-insensitive порівняння у самому C-коді
# прошивки, а не помилка нашого детектора).
FOURCC_LABELS: dict[str, str] = {
    "DIVX": "DivX (MPEG-4 ASP)",
    "DX50": "DivX 5 (MPEG-4 ASP)",
    "DIV3": "DivX 3 Low-Motion (MS MPEG-4v3 rebrand)",
    "DIV4": "DivX 4 (MPEG-4 ASP)",
    "XVID": "Xvid (MPEG-4 ASP)",
    "XVIX": "Xvid (interlaced variant)",
    "FMP4": "FFmpeg MPEG-4 (Part 2)",
    "MPG4": "MPEG-4 (generic)",
    "MP42": "Microsoft MPEG-4 v2",
    "MP43": "Microsoft MPEG-4 v3",
    "H263": "H.263",
    "H264": "H.264 / AVC",
    "AVC1": "H.264 / AVC (ISO variant)",
    "H265": "H.265 / HEVC",
    "HEVC": "H.265 / HEVC",
    "MJPG": "Motion JPEG",
    "MJPA": "Motion JPEG (Apple variant, field A)",
    "MJPB": "Motion JPEG (Apple variant, field B)",
    "WMV1": "Windows Media Video 7",
    "WMV2": "Windows Media Video 8",
    "WMV3": "Windows Media Video 9",
    "VP60": "VP6",
    "VP80": "VP8",
    "3IV2": "3ivx MPEG-4",
}

# Скільки 4-символьних блоків мінімум має розпізнатись, щоб рядок
# вважався таблицею кодеків, а не випадковим збігом одного відомого
# fourcc всередині непов'язаного тексту (той самий принцип мінімального
# порогу, що вже застосований у інших детекторах цього проєкту).
MIN_RECOGNIZED = 3

# Частка розпізнаних блоків від загальної кількості — таблиця кодеків
# складається практично ЛИШЕ з fourcc-ів, тому суцільний рядок з
# великою домішкою нерозпізнаних 4-байтних шматків це, найімовірніше,
# просто випадковий текст, а не таблиця.
MIN_RECOGNIZED_RATIO = 0.5

# Мінімальна довжина рядка-кандидата — менше не дасть навіть
# MIN_RECOGNIZED повних 4-байтних блоків.
MIN_LENGTH = MIN_RECOGNIZED * 4


@dataclass(slots=True)
class CodecTable:
    """Одна знайдена таблиця — один рядок-кандидат з прошивки."""

    offset: int
    raw: str
    codecs: list[str] = field(default_factory=list)         # розпізнані, у вихідному регістрі й порядку
    unrecognized: list[str] = field(default_factory=list)   # 4-символьні блоки поза FOURCC_LABELS
    leftover: str | None = None                              # "хвіст", що не набирає повного 4-байтного блоку

    def label_for(self, fourcc: str) -> str | None:
        return FOURCC_LABELS.get(fourcc.upper())


@dataclass(slots=True)
class CodecTableProfile:

    tables: list[CodecTable] = field(default_factory=list)

    @property
    def all_codecs(self) -> set[str]:
        return {codec.upper() for table in self.tables for codec in table.codecs}


def analyze_codec_table(strings: Iterable[StringFinding]) -> CodecTableProfile | None:

    profile = CodecTableProfile()

    for s in strings:

        text = s.text

        if len(text) < MIN_LENGTH:
            continue

        complete_len = len(text) - (len(text) % 4)
        chunks = [text[i:i + 4] for i in range(0, complete_len, 4)]

        recognized: list[str] = []
        unrecognized: list[str] = []

        for chunk in chunks:
            if chunk.upper() in FOURCC_LABELS:
                recognized.append(chunk)
            else:
                unrecognized.append(chunk)

        if len(recognized) < MIN_RECOGNIZED:
            continue

        if len(recognized) / len(chunks) < MIN_RECOGNIZED_RATIO:
            continue

        profile.tables.append(
            CodecTable(
                offset=s.offset,
                raw=text,
                codecs=recognized,
                unrecognized=unrecognized,
                leftover=text[complete_len:] or None,
            )
        )

    if not profile.tables:
        return None

    return profile
