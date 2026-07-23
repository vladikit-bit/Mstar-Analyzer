from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding, is_signal_length


COMPILER_SIGNATURES = (
    ("mipsisa32-elf-gcc", ("GCC (MIPS)", "MIPS")),
    ("mips-linux-gnu-gcc", ("GCC (MIPS)", "MIPS")),
    ("mipsel-linux-gcc", ("GCC (MIPS)", "MIPS")),

    ("arm-none-eabi-gcc", ("GCC (ARM)", "ARM")),
    ("arm-linux-gnueabi-gcc", ("GCC (ARM)", "ARM")),

    ("aarch64-linux-gnu-gcc", ("GCC (AArch64)", "AArch64")),

    ("gcc version", ("GCC", None)),
    ("clang version", ("Clang", None)),
)

ARCHITECTURE_SIGNATURES = (

    # MIPS
    ("mipsisa", "MIPS", 40),
    ("mips32", "MIPS", 30),
    ("mips64", "MIPS", 30),
    ("mipsel", "MIPS", 30),
    ("mipseb", "MIPS", 30),
    ("mips-linux", "MIPS", 50),

    # ARM
    ("arm-none-eabi", "ARM", 60),
    ("arm-linux", "ARM", 50),
    ("armv5", "ARM", 15),
    ("armv6", "ARM", 15),
    ("armv7", "ARM", 20),
    # НЕ "thumb" — цей голий підрядок збігається з "thumbnail.jpg" /
    # "thumbnail" (реально трапляється у прошивках з YouTube/picture
    # decoder рядками) і давав хибний ARM на MIPS-бінарнику. "-mthumb" —
    # це специфічний прапор GCC для ARM Thumb-режиму, такої колізії немає.
    ("-mthumb", "ARM", 10),

    # AArch64
    ("aarch64", "AArch64", 60),

    # x86
    ("x86_64", "x86-64", 60),
    ("amd64", "x86-64", 60),
    ("i686", "x86", 40),
    ("i586", "x86", 40),
    ("i486", "x86", 40),

    # PowerPC
    ("powerpc", "PowerPC", 50),
    ("ppc", "PowerPC", 30),
)

# "ppc" — той самий клас проблеми, що й "thumb" вище: голий 3-символьний
# підрядок трапляється всередині звичайних ідентифікаторів
# ("RegisterAppCallback" -> "...App{ppc}allback" в нижньому регістрі:
# "registerappcallback" містить "ppc"), і давав хибний PowerPC на
# MIPS/eCos-бінарнику. Для цих сигнатур вимагаємо, щоб з обох боків НЕ
# було буквено-цифрового символу (тобто це справді окремий токен, а не
# частина довшого слова) — на відміну від сигнатур типу "mipsisa" чи
# "armv7", які НАВМИСНЕ мають матчитись як префікс довшого identifier'а
# ("mipsisa32-elf-gcc") і тому лишаються звичайним підрядковим пошуком.
STRICT_BOUNDARY_TOKENS = frozenset({"ppc"})


def _matches(text: str, signature: str) -> bool:

    if signature not in STRICT_BOUNDARY_TOKENS:
        return signature in text

    idx = text.find(signature)

    while idx != -1:

        before_ok = idx == 0 or not text[idx - 1].isalnum()

        after = idx + len(signature)
        after_ok = after >= len(text) or not text[after].isalnum()

        if before_ok and after_ok:
            return True

        idx = text.find(signature, idx + 1)

    return False


ENDIAN_SIGNATURES = (
    ("mipsel", "little"),
    ("mipseb", "big"),

    ("-el", "little"),
    ("-eb", "big"),

    ("little endian", "little"),
    ("big endian", "big"),
)

LIBC_SIGNATURES = (

    ("glibc", "glibc"),
    ("gnu c library", "glibc"),

    ("uclibc", "uClibc"),
    ("uclibc-ng", "uClibc-ng"),

    ("musl", "musl"),

    ("newlib", "newlib"),

    ("ecos_os", "eCos"),
    ("ecospro", "eCos"),

    ("bionic", "Android Bionic"),

)

# eCos-збірки традиційно кладуть кожен пакет під шлях виду
# ".../packages/io/serial/v2_0_60/src/..." — версія пакета в самому
# шляху. Різні пакети одного релізу зазвичай мають однакову версію,
# тож зібраний набір по суті і є версією "покоління" пакетів SDK.
ECOS_PACKAGE_VERSION_RE = re.compile(r"/v(\d+)_(\d+)_(\d+)/")

# Скільки evidence-рядків тримати на категорію. Один configure-рядок на
# кілька тисяч символів (типовий випадок для FFmpeg build flags) інакше
# дублюється одразу в 4 секціях (compiler/architecture/endian/libc) і
# робить звіт нечитабельним.
MAX_EVIDENCE = 4

# Скільки символів контексту показувати навколо самої сигнатури, замість
# всього рядка цілком.
SNIPPET_WINDOW = 40


def _snippet(original: str, lower: str, signature: str, window: int = SNIPPET_WINDOW) -> str:
    """
    Замість всього (часто величезного) рядка повертає короткий фрагмент
    навколо місця, де сигнатура реально збіглася — так evidence показує
    "що саме спрацювало", а не переказує весь configure-рядок вчетверте.
    """

    idx = lower.find(signature)

    if idx == -1:
        return original[:2 * window]

    start = max(0, idx - window)
    end = min(len(original), idx + len(signature) + window)

    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(original) else ""

    return f"{prefix}{original[start:end]}{suffix}"


@dataclass(slots=True)
class RuntimeInfo:

    compiler: str | None = None
    architecture: str | None = None
    endian: str | None = None
    libc: str | None = None

    compiler_evidence: list[str] = field(default_factory=list)
    architecture_scores: dict[str, int] = field(default_factory=dict)
    architecture_evidence: dict[str, list[str]] = field(default_factory=dict)
    endian_evidence: list[str] = field(default_factory=list)
    libc_evidence: list[str] = field(default_factory=list)
    # Версії eCos-пакетів, знайдені у шляхах збірки (".../v2_0_60/...") —
    # НЕ "версія всієї ОС" (різні пакети технічно можуть мати різні
    # версії), тому зберігаємо як множину спостережень, а не єдине
    # значення.
    libc_package_versions: set[str] = field(default_factory=set)


def analyze_runtime(
    strings: Iterable[StringFinding],
) -> RuntimeInfo | None:

    info = RuntimeInfo()

    toolchain_arch_locked = False

    for s in strings:

        if not is_signal_length(s.text):
            continue

        text = s.text.lower()

        for signature, compiler_info in COMPILER_SIGNATURES:

            if signature.lower() in text:

                compiler, arch = compiler_info

                if info.compiler is None:
                    info.compiler = compiler

                # Toolchain має найвищий пріоритет
                if arch is not None and not toolchain_arch_locked:
                    info.architecture = arch
                    toolchain_arch_locked = True

                if len(info.compiler_evidence) < MAX_EVIDENCE:
                    snippet = _snippet(s.text, text, signature.lower())
                    if snippet not in info.compiler_evidence:
                        info.compiler_evidence.append(snippet)

                        if arch is not None:
                            info.architecture_evidence.setdefault(arch, [])

                break

        for signature, arch, weight in ARCHITECTURE_SIGNATURES:

            if _matches(text, signature):

                if not toolchain_arch_locked:
                    info.architecture_scores[arch] = (
                        info.architecture_scores.get(arch, 0) + weight
                   )

                bucket = info.architecture_evidence.setdefault(arch, [])

                if len(bucket) < MAX_EVIDENCE:
                    snippet = _snippet(s.text, text, signature)
                    if snippet not in bucket:
                        bucket.append(snippet)

                break

        for signature, endian in ENDIAN_SIGNATURES:

            if signature in text:

                if info.endian is None:
                    info.endian = endian

                if len(info.endian_evidence) < MAX_EVIDENCE:
                    snippet = _snippet(s.text, text, signature)
                    if snippet not in info.endian_evidence:
                        info.endian_evidence.append(snippet)

                break

        for signature, libc in LIBC_SIGNATURES:

            if signature in text:

                if info.libc is None:
                    info.libc = libc

                if len(info.libc_evidence) < MAX_EVIDENCE:
                    snippet = _snippet(s.text, text, signature)
                    if snippet not in info.libc_evidence:
                        info.libc_evidence.append(snippet)

                for major, minor, patch in ECOS_PACKAGE_VERSION_RE.findall(s.text):
                    info.libc_package_versions.add(f"{major}.{minor}.{patch}")

                break

    if (
        not toolchain_arch_locked
        and info.architecture_scores
    ):
        info.architecture = max(
            info.architecture_scores,
            key=info.architecture_scores.get,
        )

    if info.architecture is not None:
        info.architecture_evidence = {
            info.architecture: info.architecture_evidence.get(
                info.architecture,
                [],
            )
        }

    if (
        info.compiler is None
        and info.architecture is None
        and info.endian is None
        and info.libc is None
    ):
        return None

    return info
