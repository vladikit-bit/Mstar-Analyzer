from __future__ import annotations

import re
from dataclasses import dataclass


MIN_LENGTH = 4

# Окремий, вищий поріг для модулів, що роблять ВПЕВНЕНІ твердження
# (detect_features / analyze_runtime / analyze_sdk_symbols), на відміну
# від MIN_LENGTH вище, який лишається для сирого браузабельного списку
# "Strings" (де короткий фрагмент — це просто дані, а не твердження).
#
# Причина: короткі рядки, витягнуті з ще нерозпакованих / стиснутих
# ділянок прошивки, регулярно випадково збігаються з короткими
# сигнатурами ("(GERD" -> Graphics Engine, "-eB=" -> big endian, "geLF"
# -> Graphics Engine, "mIu>" -> Memory controller).
MIN_SIGNAL_LENGTH = 8

# Довжина сама по собі не рятує: "GE`s%[qS" — рівно 8 символів і теж
# сміття (жодного справжнього слова всередині, лише випадкові байти,
# що збіглися по довжині). Реальні докази — і фрази ("driver GE init
# ok"), і ідентифікатори ("MDrv_GE_SetStrBltSckType") — завжди мають
# хоча б один прогін літер такої довжини; голий шум з непроявлених
# ділянок — майже ніколи.
MIN_LETTER_RUN = 4

_LETTER_RUN_RE = re.compile(rf"[A-Za-z]{{{MIN_LETTER_RUN},}}")


def is_signal_quality(text: str) -> bool:
    """
    Чи достатньо цей рядок "виглядає як реальний текст/ідентифікатор",
    щоб на нього можна було спиратись у features/runtime/sdk_symbols
    (на відміну від сирого браузабельного списку "Strings", де показуємо
    все без розбору).
    """

    if len(text) < MIN_SIGNAL_LENGTH:
        return False

    return _LETTER_RUN_RE.search(text) is not None


# Стара назва лишається як псевдонім — модулі, що вже її імпортують,
# продовжують працювати без змін.
is_signal_length = is_signal_quality


@dataclass(slots=True)
class StringFinding:
    offset: int
    text: str


def extract_ascii_strings(
    data: bytes,
    min_length: int = MIN_LENGTH,
) -> list[StringFinding]:

    result: list[StringFinding] = []

    start = None

    for i, b in enumerate(data):

        if 32 <= b <= 126:

            if start is None:
                start = i

            continue

        if start is not None:

            if i - start >= min_length:

                text = data[start:i].decode(
                    "ascii",
                    errors="ignore",
                )

                if sum(ch.isalpha() for ch in text) >= 2:

                    result.append(
                        StringFinding(
                            offset=start,
                            text=text,
                        )
                    )

            start = None

    if start is not None:

        if len(data) - start >= min_length:

            text = data[start:].decode(
                "ascii",
                errors="ignore",
            )

            if sum(ch.isalpha() for ch in text) >= 2:

                result.append(
                    StringFinding(
                        offset=start,
                        text=text,
                    )
                )

    return result