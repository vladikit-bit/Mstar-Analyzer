from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..strings import StringFinding

# Немає жодної публічно задокументованої специфікації "MStar SoC
# board-string формату" — так само, як не було для MDrv_/MApi_/HAL_
# конвенцій іменування символів (sdk_symbols.py) до того, як їх
# реконструювали з реальних рядків прошивки. Той самий принцип тут:
# не вигадуємо структуру, а фіксуємо ЩО КОНКРЕТНО підтверджено прямим
# доказом із реальної прошивки користувача versus що спирається лише
# на загальновідому (але не перевіреному саме на цих даних) іменуванні
# серій MStar.
#
# ПІДТВЕРДЖЕНО реальним доказом (report.txt цього проєкту, MBoot
# Board variable): "K5AP_BD_MST297B_D01A" -> модель чипа "MST297B".
# Префікс "MST" — єдиний, для якого в нас є ПРЯМИЙ доказ. MSO/MSD/MSC —
# інші відомі серії SoC від MStar Semiconductor (загальновідома, а не
# вигадана назва виробника), додані для повноти, але БЕЗ прямого
# підтвердження в даних цього конкретного користувача — тому окремо
# позначені нижче як "unconfirmed_prefix", а не змішані з підтвердженим
# "MST" без розрізнення.
CONFIRMED_CHIP_PREFIXES = ("MST",)
KNOWN_UNCONFIRMED_CHIP_PREFIXES = ("MSO", "MSD", "MSC")

_ALL_PREFIXES = CONFIRMED_CHIP_PREFIXES + KNOWN_UNCONFIRMED_CHIP_PREFIXES

CHIP_MODEL_RE = re.compile(
    r"(?<![A-Za-z0-9])(" + "|".join(_ALL_PREFIXES) + r")(\d{2,4}[A-Z]{0,2})(?![A-Za-z0-9])"
)

# Board-рядок (як "K5AP_BD_MST297B_D01A") — кілька underscore-розділених
# сегментів, один з яких містить модель чипа. Фіксуємо ПОВНИЙ рядок як
# "board identifier" без спроби розібрати кожен сегмент (лише один
# реальний зразок — "K5AP"/"BD"/"D01A" можуть бути платформою/
# маркером-константою/ревізією плати, але це здогад, не підтверджений
# доказ, тож не привласнюємо їм лейбли).
BOARD_STRING_RE = re.compile(
    r"\b[A-Z0-9]+(?:_[A-Z0-9]+){2,}\b"
)


@dataclass(slots=True)
class ChipMatch:

    text: str            # напр. "MST297B"
    prefix: str           # напр. "MST"
    confirmed: bool        # True лише для CONFIRMED_CHIP_PREFIXES
    evidence: str          # повний рядок, де знайдено


@dataclass(slots=True)
class ChipIdentification:

    models: list[ChipMatch] = field(default_factory=list)
    board_identifiers: set[str] = field(default_factory=set)

    @property
    def confirmed_models(self) -> set[str]:
        return {m.text for m in self.models if m.confirmed}

    @property
    def unconfirmed_models(self) -> set[str]:
        return {m.text for m in self.models if not m.confirmed}


def analyze_chip_id(strings: Iterable[StringFinding]) -> ChipIdentification | None:

    result = ChipIdentification()
    seen_models: set[str] = set()

    for s in strings:

        # Не is_signal_length() тут навмисно: той фільтр вимагає прогону
        # ПОСЛІДОВНИХ літер (заточений під прозу/типові ідентифікатори)
        # і хибно відкидає щільні буквено-цифрові board-рядки на кшталт
        # "K5AP_BD_MST297B_D01A" — САМЕ те, що цей аналізатор шукає.
        # Достатньо мінімальної довжини; специфічність самих regex
        # (префікс + цифри, або 3+ underscore-сегменти) — і є фільтром
        # точності.
        if len(s.text) < 6:
            continue

        for match in CHIP_MODEL_RE.finditer(s.text):

            prefix, digits_suffix = match.group(1), match.group(2)
            model = prefix + digits_suffix

            if model not in seen_models:
                seen_models.add(model)
                result.models.append(
                    ChipMatch(
                        text=model,
                        prefix=prefix,
                        confirmed=prefix in CONFIRMED_CHIP_PREFIXES,
                        evidence=s.text.strip(),
                    )
                )

            board_match = BOARD_STRING_RE.search(s.text)

            if board_match:
                result.board_identifiers.add(board_match.group(0))

    if not result.models and not result.board_identifiers:
        return None

    return result
