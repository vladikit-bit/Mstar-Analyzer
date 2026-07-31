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

    # Семантичний розподіл NetSrv за підобластями. NetSrv-рядки — це
    # debug-логи ("[NetSrv][%s][line:%d][ERROR][Download Module], ..."),
    # а не C-символи з фіксованою конвенцією іменування (як MDrv_/MApi_),
    # тому "підсистему" тут неможливо витягти самим regex-парсингом
    # префікса — натомість кожен підпункт вимагає одночасно і тег
    # "[NetSrv]", і конкретне, підтверджене реальними рядками з прошивки
    # ключове слово в тому самому рядку. Це навмисно ті самі
    # Signature/Feature класи, що й для решти фіч вище — не окремий
    # аналізатор чи механізм.
    Signature(
        feature="NetSrv: Download Module",
        pattern=re.compile(r"\[NetSrv\].*\[Download Module\]", re.I),
        weight=60,
        confidence="STRONG",
    ),

    Signature(
        feature="NetSrv: Buffering",
        pattern=re.compile(r"\[NetSrv\].*\bBuffering\b", re.I),
        weight=60,
        confidence="STRONG",
    ),

    Signature(
        # weight=50, дефолтна confidence (не STRONG, на відміну від двох
        # вище): патерн об'єднує три РІЗНІ, менш специфічні ключові
        # слова через (?:...|...|...) — це надійний сигнал наявності
        # клієнт/сесійної логіки, але не такий однозначний "бірка", як
        # буквальний "[Download Module]" чи окреме слово "Buffering".
        feature="NetSrv: Client session",
        pattern=re.compile(r"\[NetSrv\].*(?:Client_Close|ClientList|session count)", re.I),
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
        # Літеральний банер версії ("FFMPEG VERSION : 2.5.4") — набагато
        # специфічніший за голе слово "ffmpeg" вище (те може з'явитись
        # де завгодно, напр. усередині чужого --extra-cflags рядка збірки
        # OpenSSL, зібраної в тому самому SDK). weight=100 — та сама
        # логіка "STRONG сам по собі дає MEDIUM", що й для MIU/GE вище.
        feature="FFmpeg",
        pattern=re.compile(r"FFMPEG\s+VERSION\s*:", re.I),
        weight=100,
        confidence="STRONG",
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
        # Негативний lookbehind навмисно виключає "--enable-openssl" /
        # "--disable-openssl" — реальний рядок з прошивки містить
        # вбудований рядок конфігурації збірки FFmpeg
        # ("--disable-protocols --enable-openssl --enable-protocol=..."),
        # де "openssl" — це прапорець збірки FFmpeg (TLS-бекенд), а не
        # самостійний доказ окремої бібліотеки OpenSSL. Це вже точніше
        # й окремо фіксується в FFmpegSummary.uses_openssl (reporting.py)
        # — справжні шляхи пакета openssl (".../packages/net/openssl/
        # v_0_9_8o/...") тут НЕ постраждають, бо перед "openssl" там
        # "net/", а не "enable-"/"disable-".
        feature="OpenSSL",
        pattern=re.compile(r"(?<!enable-)(?<!disable-)\bopenssl\b", re.I),
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
        # ("MIU0 Init Done", "Wait MIU0..."), причому номер може бути
        # багатозначним (MIU10, MIU32) — \d+, а не одна цифра.
        #
        # weight=100 (не 60): це вже STRONG-сигнатура — один-єдиний
        # реальний збіг типу "Disable MIU1" сам по собі мав би одразу
        # дати щонайменше MEDIUM (>=100 з score_to_confidence), а не
        # лишатись у LOW разом зі слабкими WEAK-збігами вище. 100 — той
        # самий рівень, що вже усталений для MDrv_GE (теж STRONG) нижче.
        feature="Memory controller",
        pattern=re.compile(r"\bMIU\d+\b", re.I),
        weight=100,
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
        weight=100,
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
        # "Vdec:H264" — MStar-стилю runtime тег вибору відео-декодера
        # (те саме сімейство, що "Adec:MPEG" для аудіо нижче), значно
        # специфічніший за голе "h264", яке може збігтись і в шумі
        # непроявлених рядків.
        feature="H.264 decoder",
        pattern=re.compile(r"Vdec:\s*H\.?264\b", re.I),
        weight=100,
        confidence="STRONG",
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


# Візуальне представлення трьох рівнів score_to_confidence вище —
# спільне для render.py (per-node "Detected features") і
# renderers/summary.py (крос-дерева "Capabilities"), тому живе тут, а
# не в жодному з них: render.py вже імпортує з renderers/summary.py
# (render_cross_tree_summary), тож розміщення цієї мапи в render.py
# створило б циклічний імпорт, якби renderers/summary.py теж захотів
# її звідти імпортувати.
FEATURE_CONFIDENCE_MARKER = {
    "HIGH": "✓",
    "MEDIUM": "~",
    "LOW": "?",
}


def detect_features(strings: Iterable[StringFinding]) -> list[Feature]:

    found: dict[str, Feature] = {}

    # feature -> {текст рядка -> найбільша вага, вже зарахована за цей
    # рядок}. Один рядок може збігтись одразу з кількома сигнатурами
    # однієї фічі різної "сили" (напр. "driver GE init ok" відповідає
    # і слабкому \bGE\b, і сильному "driver GE") — це одна й та сама
    # доказова строка, тож зараховуємо її внесок у score РІВНО ОДИН
    # РАЗ, і саме за НАЙСИЛЬНІШОЮ сигнатурою, що збіглась, а не за
    # першою в списку SIGNATURES (без цього порядок оголошення сигнатур
    # у списку випадково впливав би на підсумковий score).
    credited: dict[str, dict[str, int]] = {}

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

                feature.evidences.add(s.text)

                already_credited = credited.setdefault(sig.feature, {})
                prior_weight = already_credited.get(s.text, 0)

                if sig.weight > prior_weight:
                    feature.score += sig.weight - prior_weight
                    already_credited[s.text] = sig.weight

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


# Групування Feature.name за категорією — для "Capabilities" зведення
# (renderers/summary.py). Навмисно окремий словник, а не поле на
# Signature: одна й та сама feature ("H.264 decoder") часто має кілька
# Signature-записів (weak/strong), а категорія в неї рівно одна.
# Якщо колись з'явиться нова feature без запису тут — вона просто
# потрапить під "Інше" (render_capabilities), а не впаде з KeyError.
FEATURE_CATEGORIES: dict[str, str] = {
    "Wi-Fi": "Networking",
    "Ethernet": "Networking",
    "HTTP client": "Networking",
    "SSL/TLS": "Networking",
    "OpenSSL": "Networking",
    "Streaming Engine": "Networking",
    "HLS Streaming": "Networking",
    "NetSrv: Download Module": "Networking",
    "NetSrv: Buffering": "Networking",
    "NetSrv: Client session": "Networking",

    "H.264 decoder": "Codecs",
    "H.265 decoder": "Codecs",
    "MPEG codec": "Codecs",
    "JPEG support": "Codecs",
    "PNG support": "Codecs",
    "DivX": "Codecs",
    "FFmpeg": "Codecs",
    "FFmpeg AVIO": "Codecs",

    "Graphics Engine": "Graphics",
    "Graphics Output Processor": "Graphics",
    "LCD Panel": "Graphics",

    "Audio subsystem": "Audio",
    "Dolby": "Audio",

    "Memory controller": "System",
    "MStar Bootloader": "System",
    "MStar SDK": "System",
    "Dynamic ELF loader (Objloader)": "System",
    "Lua scripting": "System",
    "SQLite": "System",
    "Video subsystem": "System",
}

# Порядок показу категорій у render_capabilities (renderers/summary.py) —
# фіксований, а не алфавітний, щоб звіт читався в передбачуваному
# порядку від зовнішнього (мережа) до внутрішнього (система).
FEATURE_CATEGORY_ORDER = ["Networking", "Codecs", "Graphics", "Audio", "System", "Other"]