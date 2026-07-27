"""
MBoot Env Block parser — аналізатор конфігураційного блоку MStar MBoot.

MBoot (MStar Boot) — видозмінений U-Boot, який використовується в прошивках
MStar Semiconductor.  Конфігураційний блок містить:

  * preamble — бінарна область (MIPS-інструкції, адреси, прапорці);
    точний формат ще не повністю зрозумілий;
  * version string — рядок виду "MBOT-1106.0.10.936a0fd.201806111716",
    завершується 0xFF (НЕ \\0 — відмінність від U-Boot);
  * env variables — key=value пари, розділені \\n, блок завершується \\0.

Формат не жорстко прив'язаний до конкретного offset чи розміру preamble —
детектор шукає маркер MBOT- і евристично визначає межі блоку.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MBootVariable:
    """
    Одна конфігураційна змінна MBoot env block.

    Dataclass замість dict[str, str], щоб зберегти offset/довжину для
    майбутнього diff між прошивками та потенційного patch-інструменту.
    """

    name: str
    value: str
    offset: int
    length: int


@dataclass(slots=True)
class MBootEnvBlockInfo:
    """
    Повна інформація про розібраний MBoot Env Block.

    Використовується внутрішньо аналізатором; не зберігається безпосередньо
    в EmbeddedObject.metadata — замість цього metadata заповнюється окремими
    ключами для JSON-сумісності.
    """

    version_string: str = ""
    preamble_offset: int = 0
    preamble_size: int = 0
    variables: list[MBootVariable] = field(default_factory=list)
    # Абсолютний offset кінця env-регіону (перший 0x00 або 0xFF після змінних).
    # Потрібен analyzer-у для обчислення obj.size = block_end - preamble_offset.
    block_end: int = 0


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_MBOT_MARKER = b"MBOT-"
_ENV_LINE_RE = re.compile(rb"^([A-Za-z_]\w*)=(.*)$")

# Максимальне вікно сканування назад від маркера MBOT- для пошуку
# початку preamble (бінарної області).
_PREAMBLE_SCAN_WINDOW = 256

# Мінімальна довжина послідовності однакових байтів (0x00 або 0xFF),
# що вважається padding між блоками.
# У MIPS-коді зустрічаються поодинокі або короткі послідовності 0xFF
# (напр. 0xFFFFFFFF = addiu $zero,$zero,-1), а реальний padding між
# блоками — щонайменше десятки або сотні байт.
_PREAMBLE_PADDING_MIN_RUN = 16

# Байти, що можуть використовуватись для заповнення padding між блоками.
_PREAMBLE_PADDING_BYTES = (0x00, 0xFF)


def _find_preamble_start(data: bytes, mbot_pos: int) -> int:
    """
    Знайти початок preamble — межу між padding та бінарними даними.

    Підходить для різних типів padding (0x00 або 0xFF) — шукає
    **найбільшу** послідовність однакових байтів серед
    ``_PREAMBLE_PADDING_BYTES`` у межах ``_PREAMBLE_SCAN_WINDOW``.

    Чому саме найбільша? Блоки MBoot можуть містити короткі вбудовені
    послідовності 0x00 або 0xFF (напр. у MIPS-коді або нульових полях
    заголовка). Специфічна для padding послідовність — най довша.

    Якщо жодної достатньої послідовності не знайдено, повертає
    ``mbot_pos`` — preamble size=0.
    """
    scan_start = max(0, mbot_pos - _PREAMBLE_SCAN_WINDOW)
    region = data[scan_start:mbot_pos]

    best_run_start = -1
    best_run_len = 0

    i = 0
    while i < len(region):
        byte_val = region[i]

        if byte_val not in _PREAMBLE_PADDING_BYTES:
            i += 1
            continue

        # Вимірюємо довжину послідовності однакових padding-байтів
        run_start = i
        while i < len(region) and region[i] == byte_val:
            i += 1
        run_len = i - run_start

        if run_len >= _PREAMBLE_PADDING_MIN_RUN and run_len > best_run_len:
            best_run_start = scan_start + run_start
            best_run_len = run_len

    if best_run_start >= 0:
        # Preamble starts AFTER the longest padding run
        return best_run_start + best_run_len

    # Межу не знайдено — preamble порожній
    return mbot_pos


def _extract_version_string(data: bytes, mbot_pos: int) -> tuple[str, int]:
    """
    Витягти version string з маркера MBOT- до першого 0xFF terminator.

    Повертає (version_string, end_offset).
    """
    n = len(data)
    end = mbot_pos

    while end < n and data[end] != 0xFF:
        end += 1

    raw = data[mbot_pos:end]
    try:
        version = raw.decode("ascii")
    except UnicodeDecodeError:
        version = raw.decode("latin1", errors="replace")

    return version, end


def _skip_ff_padding(data: bytes, pos: int, limit: int) -> int:
    """
    Пропустити 0xFF padding після version string.

    Повертає offset першого ненульового байта (або ``limit``, якщо
    весь залишок — padding).
    """
    while pos < limit and data[pos] == 0xFF:
        pos += 1
    return pos


def _extract_env_variables(
    data: bytes,
    start: int,
    limit: int,
    base_offset: int,
) -> tuple[list[MBootVariable], int]:
    """
    Розібрати env variables з області key=value, розділеної \\n.

    ``base_offset`` — абсолютний offset початку env-області у firmware
    (для коректного обчислення ``MBootVariable.offset``).

    Повертає ``(variables, block_end)``, де ``block_end`` — абсолютний offset
    першого 0x00 або 0xFF після змінних (кінець env-регіону).
    """
    variables: list[MBootVariable] = []

    # Зчитуємо до першого 0xFF або \\0 (термінатор блоку).
    end = start
    while end < limit and data[end] not in (0x00, 0xFF):
        end += 1

    env_text = data[start:end]
    lines = env_text.split(b"\n")

    cursor = start
    for line in lines:
        line_len = len(line) + 1  # +1 для \\n
        if not line:
            cursor += line_len
            continue

        m = _ENV_LINE_RE.match(line)
        if m:
            name = m.group(1).decode("ascii")
            value = m.group(2).decode("ascii").rstrip(" ")
            variables.append(
                MBootVariable(
                    name=name,
                    value=value,
                    offset=base_offset + (cursor - start),
                    length=line_len,
                )
            )

        cursor += line_len

    return variables, end


# ---------------------------------------------------------------------------
# Public API: parse_mboot_env_block
# ---------------------------------------------------------------------------


def parse_mboot_env_block(
    data: bytes,
    mbot_pos: int,
) -> MBootEnvBlockInfo:
    """
    Повністю розібрати MBoot Env Block починаючи з маркера MBOT-.

    Викликається з ``object_analyzer.analyze_mboot_env_block()``.

    Parameters
    ----------
    data : bytes
        Повні байти firmware (або parent-ноду).
    mbot_pos : int
        Offset маркера ``MBOT-`` у ``data``.

    Returns
    -------
    MBootEnvBlockInfo
        Розібрана інформація: version, preamble, variables.
    """
    n = len(data)
    info = MBootEnvBlockInfo()

    # 1. Preamble: межа від сканування назад
    preamble_start = _find_preamble_start(data, mbot_pos)
    info.preamble_offset = preamble_start
    info.preamble_size = mbot_pos - preamble_start

    # 2. Version string
    version, version_end = _extract_version_string(data, mbot_pos)
    info.version_string = version

    # 3. Env variables: пропускаємо 0xFF padding після version string,
    #    читаємо до 0xFF / \\0.
    env_start = _skip_ff_padding(data, version_end, n)
    info.variables, info.block_end = _extract_env_variables(
        data, env_start, n, env_start
    )

    return info


def compute_confidence(
    info: MBootEnvBlockInfo,
    preamble_found: bool,
) -> str:
    """
    Визначити confidence на основі розібраних даних.

    Правила (відтворювані, як у інших детекторах):

    * high  — MBOT- + ≥2 key=value + preamble знайдено
    * high  — MBOT- + ≥1 key=value + preamble знайдено
    * medium — MBOT- + 0 variables + preamble знайдено
    * medium — MBOT- + preamble boundary ambiguous (size==0)
    * low   — тільки маркер MBOT-, без структури
    """
    has_vars = len(info.variables) >= 1
    has_many_vars = len(info.variables) >= 2

    if has_many_vars and preamble_found:
        return "high"

    if has_vars and preamble_found:
        return "high"

    if not has_vars and preamble_found:
        return "medium"

    if not preamble_found:
        if has_vars:
            return "medium"
        return "low"

    return "low"
