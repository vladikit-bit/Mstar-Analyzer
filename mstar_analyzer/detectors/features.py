from __future__ import annotations

import re

from dataclasses import dataclass, field

from collections.abc import Iterable

from ..strings import StringFinding, is_signal_length


@dataclass(slots=True)
class Signature:

    feature: str

    pattern: re.Pattern[str]

    weight: int

    confidence: str = "MEDIUM"

    note: str = ""

@dataclass(slots=True)
class Feature:

    name: str

    score: int

    evidence: str

    evidences: set[str]

    best_signature: Signature | None

    matched_signatures: list[Signature] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        return score_to_confidence(self.score)

    @property
    def matched_patterns(self) -> list[str]:
        return [
            sig.pattern.pattern
            for sig in self.matched_signatures
        ]

    @property
    def evidence_confidence(self) -> str:
        if self.best_signature is None:
            return "UNKNOWN"
        return self.best_signature.confidence

    @property
    def strongest_pattern(self) -> str:
        if self.best_signature is None:
            return ""
        return self.best_signature.pattern.pattern

    @property
    def score_breakdown(self) -> list[tuple[str, int]]:
        return [
            (sig.pattern.pattern, sig.weight)
            for sig in self.matched_signatures
        ]

SIGNATURES: list[Signature] = [

    Signature(
        feature="Streaming Engine",
        pattern=re.compile(r"\bNetSrv\b", re.I),
        weight=50,
    ),

    Signature(
        feature="HLS Streaming",
        pattern=re.compile(r"application/x-mpegURL", re.I),
        weight=50,
    ),

    Signature(
        feature="FFmpeg AVIO",
        pattern=re.compile(r"\bavio_[A-Za-z0-9_]+\b", re.I),
        weight=50,
    ),

    Signature(
        feature="FFmpeg",
        pattern=re.compile(r"\bffmpeg\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Lua scripting",
        pattern=re.compile(r"\blua(_|L_|State)", re.I),
        weight=50,
    ),

    Signature(
        feature="SQLite",
        pattern=re.compile(r"\bsqlite\b", re.I),
        weight=50,
    ),

    Signature(
        feature="HTTP client",
        pattern=re.compile(r"\bcurl\b", re.I),
        weight=50,
    ),

    Signature(
        feature="OpenSSL",
        pattern=re.compile(r"\bopenssl\b", re.I),
        weight=50,
    ),

    Signature(
        feature="SSL/TLS",
        pattern=re.compile(r"\bSSL_[A-Za-z0-9_]+\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Wi-Fi",
        pattern=re.compile(r"\b(wifi|wlan)\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Ethernet",
        pattern=re.compile(r"\bethernet\b", re.I),
        weight=50,
    ),

    Signature(
        # Голе "MIU" як окреме слово трапляється і у випадкових
        # непроявлених рядках (напр. "mIu>" з ще стиснутих ділянок) —
        # тому це лише слабкий сигнал.
        feature="Memory controller",
        pattern=re.compile(r"\bMIU\b", re.I),
        weight=5,
        confidence="WEAK",
    ),
    Signature(
        # Реальні рядки з прошивки завжди мають номер контролера
        # Реальні рядки з прошивки завжди мають номер контролера
        # ("MIU0 Init Done", "Wait MIU0..."), причому номер може бути
        # багатозначним (MIU10, MIU32) — \d+, а не одна цифра.
        feature="Memory controller",
        pattern=re.compile(r"\bMIU\d+\b", re.I),
        weight=60,
        confidence="STRONG",
    ),

    Signature(
        feature="MStar Bootloader",
        pattern=re.compile(r"\bMBoot\b", re.I),
        weight=50,
    ),

    Signature(
        feature="MStar SDK",
        pattern=re.compile(r"\bMSTAR\b", re.I),
        weight=50,
    ),

    Signature(
        feature="LCD Panel",
        pattern=re.compile(r"\bpanel\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Graphics Output Processor",
        pattern=re.compile(r"\bGOP\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Graphics Engine",
        pattern=re.compile(r"\bGE\b", re.I),
        weight=5,
        confidence="WEAK",
    ),

    Signature(
        feature="Graphics Engine",
        pattern=re.compile(r"\bGE\s+init(?:ialized)?\b", re.I),
        weight=40,
        confidence="MEDIUM",
    ),

    # ПРИБРАНО: \bGE[A-Z][A-Za-z0-9_]*\b ("GE" + Велика літера, як
    # CamelCase-евристика для GEInit/GEXxx). За час розробки цей патерн
    # дав щонайменше три підтверджені false positives: "(GERD" і "GEOV"
    # (сміття з непроявлених рядків) і "GET_PARAMETER" (справжній
    # RTSP-метод — "GE" + "T" уппercase теж проходить [A-Z]). Кожен
    # підтверджений РЕАЛЬНИЙ доказ Graphics Engine (MDrv_GE_*, "driver
    # GE init ok", GE_xxx) уже покривається сильнішими патернами нижче
    # — ця "легка" евристика приносила більше шуму, ніж сигналу.

    Signature(
        # Так само без re.I — MDrv/MApi-стиль префіксів завжди у верхньому
        # регістрі ("GE_xxx"), і випадкові малі "ge_..." з шуму рядків
        # тут навряд чи бажаний сигнал.
        feature="Graphics Engine",
        pattern=re.compile(r"\bGE_[A-Za-z0-9_]+\b"),
        weight=60,
        confidence="MEDIUM",
    ),

    Signature(
        feature="Graphics Engine",
        pattern=re.compile(r"driver\s+GE", re.I),
        weight=80,
        confidence="STRONG",
    ),

    Signature(
        feature="Graphics Engine",
        pattern=re.compile(r"MDrv_GE", re.I),
        weight=100,
        confidence="STRONG",
    ),

    Signature(
        feature="Audio subsystem",
        pattern=re.compile(r"\baudio\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Video subsystem",
        pattern=re.compile(r"\bvideo\b", re.I),
        weight=50,
    ),

    Signature(
        feature="MPEG codec",
        pattern=re.compile(r"\bmpeg\b", re.I),
        weight=50,
    ),

    Signature(
        feature="H.264 decoder",
        pattern=re.compile(r"\bh264\b", re.I),
        weight=50,
    ),

    Signature(
        feature="H.265 decoder",
        pattern=re.compile(r"\bh265\b", re.I),
        weight=50,
    ),

    Signature(
        feature="JPEG support",
        pattern=re.compile(r"\bjpeg\b", re.I),
        weight=50,
    ),

    Signature(
        feature="PNG support",
        pattern=re.compile(r"\bpng\b", re.I),
        weight=50,
    ),

    Signature(
        feature="Dolby",
        pattern=re.compile(r"\bdolby\b", re.I),
        weight=50,
    ),

    Signature(
        feature="DivX",
        pattern=re.compile(r"\bdivx\b", re.I),
        weight=50,
    ),

    Signature(
        # eCosPro Objloader — динамічне завантаження/релокація/лінкування
        # об'єктних файлів прямо під час роботи системи. Для
        # реверс-інжинірингу це суттєва підказка: якщо loader є, є й
        # шлях для runtime-модифікації без перепрошивки всього образу
        # (а не тільки статичний патчинг байтів у флеші).
        feature="Dynamic ELF loader (Objloader)",
        pattern=re.compile(r"\bcyg_ldr_[A-Za-z0-9_]+\b"),
        weight=90,
        confidence="STRONG",
    ),

]

def score_to_confidence(score: int) -> str:

    if score >= 200:
        return "HIGH"

    if score >= 100:
        return "MEDIUM"

    return "LOW"


def detect_features(strings: Iterable[StringFinding]) -> list[Feature]:

    found: dict[str, Feature] = {}

    for s in strings:

        if not is_signal_length(s.text):
            continue

        for sig in SIGNATURES:

            if sig.pattern.search(s.text):

                feature = found.setdefault(
                    sig.feature,
                    Feature(
                        name=sig.feature,
                        score=0,
                        evidence="",
                        evidences=set(),
                        best_signature=None,
                    ),
                )

                if s.text not in feature.evidences:
                    feature.evidences.add(s.text)
                    feature.score += sig.weight

                if sig not in feature.matched_signatures:
                    feature.matched_signatures.append(sig)

                if (
                    feature.best_signature is None
                    or sig.weight > feature.best_signature.weight
                ):
                    feature.best_signature = sig
                    feature.evidence = s.text.strip()
    
    return sorted(
    found.values(),
    key=lambda f: f.score,
    reverse=True,
)