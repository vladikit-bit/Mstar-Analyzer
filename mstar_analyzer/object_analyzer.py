from __future__ import annotations

import math
import re
import struct

from .detectors.objects import EmbeddedObject

FAKE_PNG_PREVIEW = 512

PNG_COLOR_TYPES = {
    0: "Grayscale",
    2: "RGB",
    3: "Indexed",
    4: "Gray+Alpha",
    6: "RGBA",
}

def analyze_objects(
    objects: list[EmbeddedObject],
    data: bytes,
) -> None:

    for obj in objects:

        if obj.kind == "PNG":
            analyze_png(obj, data)

        elif obj.kind == "JPEG":
            analyze_jpeg(obj, data)

        elif obj.kind == "Lua bytecode":
            analyze_lua(obj, data)

        elif obj.kind == "ELF":
            analyze_elf(obj, data)

        elif obj.kind == "MBootEnvBlock":
            analyze_mboot_env_block(obj, data)


def _compute_png_length(data: bytes, pos: int) -> int | None:
    """
    Проходить по PNG-чанках від 8-байтної сигнатури до IEND і повертає
    повний розмір файлу (включно з IEND+CRC). detect_png() у detectors/objects.py
    завжди ставить size=None — це і є "Stage 6" для PNG: підтверджуємо
    реальну довжину замість здогадки.

    Повертає None, якщо IEND не знайдено в межах доступних даних
    (типово — картинка обрізана сусіднім стиснутим блоком).
    """
    cursor = pos + 8
    n = len(data)

    while cursor + 8 <= n:
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        ctype = data[cursor + 4:cursor + 8]
        chunk_end = cursor + 8 + length + 4  # length + type + data + CRC

        if chunk_end > n:
            return None

        if ctype == b"IEND":
            return chunk_end - pos

        cursor = chunk_end

    return None


def analyze_png(
    obj: EmbeddedObject,
    data: bytes,
) -> None:

    pos = obj.offset

    chunk = data[pos + 12:pos + 16]

    if chunk != b"IHDR":

        obj.validated = False
        obj.confidence = "low"

        obj.metadata["reason"] = "invalid_png"

        obj.metadata["analysis"] = "non_png_signature"

        obj.metadata["first_chunk"] = chunk.decode(
            "latin1",
            errors="replace",
        )

        analyze_fake_png(
            obj,
            data,
        )

        return

    try:

        width = int.from_bytes(
            data[pos + 16:pos + 20],
            "big",
        )

        height = int.from_bytes(
            data[pos + 20:pos + 24],
            "big",
        )

        bit_depth = data[pos + 24]

        color_type = PNG_COLOR_TYPES.get(
            data[pos + 25],
            f"Unknown ({data[pos + 25]})",
        )

        interlace = (
            "Adam7"
            if data[pos + 28]
            else "None"
        )

        obj.metadata.update(
            {
                "width": width,
                "height": height,
                "bit_depth": bit_depth,
                "color_type": color_type,
                "interlace": interlace,
            }
        )

        png_length = _compute_png_length(data, pos)

        if png_length is not None:
            obj.size = png_length
            obj.metadata["end_offset"] = f"0x{pos + png_length:X}"
        else:
            obj.metadata["note"] = "IEND not found in available data (truncated?)"

    except Exception as e:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "png_parse_error"
        obj.metadata["exception"] = str(e)

def analyze_fake_png(
    obj: EmbeddedObject,
    data: bytes,
) -> None:

    preview = data[
        obj.offset:
        obj.offset + FAKE_PNG_PREVIEW
    ]

    analyze_ascii(
        obj,
        preview,
    )

    analyze_strings(
        obj,
        preview,
    )

    analyze_signatures(
        obj,
        preview,
    )

    classify_fake_png(obj)


def analyze_ascii(
    obj: EmbeddedObject,
    preview: bytes,
) -> None:

    if not preview:
        obj.metadata["ascii_ratio"] = 0.0
        return

    printable = 0

    for b in preview:

        if (
            32 <= b <= 126
            or b in (9, 10, 13)
        ):
            printable += 1

    ratio = printable / len(preview) * 100

    obj.metadata["ascii_ratio"] = round(
        ratio,
        1,
    )

def analyze_strings(
    obj: EmbeddedObject,
    preview: bytes,
) -> None:

    text = preview.decode(
        "latin1",
        errors="ignore",
    )

    strings = re.findall(
        r"[ -~]{4,}",
        text,
    )

    obj.metadata["strings"] = strings[:50]
    obj.metadata["evidence"] = strings[:5]

# Дослівні рядки з libpng (pngerror.c / pngmem.c) — трапляються в
# бінарнику, навіть якщо конкретно ЦЕЙ байтовий діапазон — не PNG-файл,
# а частина коду/ресурсів самої бібліотеки.
LIBPNG_ERROR_STRINGS = (
    b"Out of Memory",
    b"safe_malloc",
    b"safe_realloc",
    b"none_cached_malloc",
)

# libpng традиційно тримає свій номер версії поруч зі своїми ж
# error-рядками (напр. "1.2.12", "1.6.37") — простий X.Y.Z патерн.
LIBPNG_VERSION_RE = re.compile(rb"\b(\d\.\d{1,2}\.\d{1,2}[a-z]?)\b")


def analyze_signatures(
    obj: EmbeddedObject,
    preview: bytes,
) -> None:

    signatures = []

    table = {
        b"<?xml": "XML",
        b"<svg": "SVG",
        b"<html": "HTML",
        b"MStar": "MStar",
        b"MBOOT": "MBOOT",
        b"GIF89a": "GIF",
        b"GIF87a": "GIF",
        b"SQLite": "SQLite",
        b"PK\x03\x04": "ZIP",
        b"\x7FELF": "ELF",
        b"Lua": "Lua",
    }

    for magic, name in table.items():

        if magic in preview:
            signatures.append(name)

    # libpng вбудовує свої власні error/warning-рядки в бінарник навіть
    # там, де немає жодного справжнього PNG-файлу (сама бібліотека
    # використовується десь в іншому місці для декодування). Ці рядки
    # дослівно збігаються з pngerror.c/pngmem.c з реального проєкту
    # libpng, тому це надійна, а не евристична сигнатура.
    if any(marker in preview for marker in LIBPNG_ERROR_STRINGS):
        signatures.append("libpng")

    obj.metadata["signatures"] = signatures

    version_match = LIBPNG_VERSION_RE.search(preview)
    if version_match:
        obj.metadata["embedded_version"] = version_match.group(1).decode("ascii")


def classify_fake_png(
    obj: EmbeddedObject,
) -> None:

    ratio = obj.metadata.get(
        "ascii_ratio",
        0,
    )

    strings = obj.metadata.get(
        "strings",
        [],
    )

    signatures = obj.metadata.get(
        "signatures",
        [],
    )

    classification = "unknown"
    likely = "unknown"

    if "XML" in signatures:

        classification = "xml"
        likely = "XML document"

    elif "SVG" in signatures:

        classification = "svg"
        likely = "SVG resource"

    elif "MStar" in signatures:

        classification = "mstar_resource"
        likely = "MStar SDK resource"

    elif "libpng" in signatures:

        classification = "libpng_resource"
        version = obj.metadata.get("embedded_version")
        likely = f"libpng {version} string table" if version else "libpng string table"

    elif ratio > 60:

        classification = "text"
        likely = "ASCII text"

    elif ratio > 30 and len(strings) >= 3:

        classification = "text_resource"
        likely = "message table"

    elif ratio < 15:

        classification = "binary"
        likely = "binary blob"

    obj.metadata["classification"] = classification
    obj.metadata["likely_source"] = likely


JPEG_NO_PAYLOAD_MARKERS = {0x01} | set(range(0xD0, 0xD8))  # TEM, RST0..RST7

JPEG_SOF_MARKERS = {
    0xC0, 0xC1, 0xC2, 0xC3,
    0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB,
    0xCD, 0xCE, 0xCF,
}


def _walk_jpeg(data: bytes, pos: int):
    """
    Прохід сегментів JPEG від SOI (0xFFD8) на `pos`.

    Повертає (length, width, height):
      length  — повний розмір файлу до EOI включно, або None якщо EOI
                не знайдено в межах доступних даних (обрізаний потік —
                типово сусідній стиснутий блок "з'їдає" хвіст);
      width/height — з першого зустрінутого SOF-сегмента, або None.

    Не претендує на повну відповідність специфікації JPEG — цього
    достатньо для carving вбудованих зображень у прошивці.
    """
    n = len(data)
    cursor = pos + 2  # skip FF D8
    width = height = None

    while cursor + 1 < n:

        if data[cursor] != 0xFF:
            return None, width, height  # десинхронізація потоку маркерів

        marker = data[cursor + 1]

        # 0xFF-заповнення перед реальним маркером
        while marker == 0xFF and cursor + 2 < n:
            cursor += 1
            marker = data[cursor + 1]

        if marker == 0xD9:  # EOI
            return (cursor + 2 - pos), width, height

        if marker in JPEG_NO_PAYLOAD_MARKERS:
            cursor += 2
            continue

        if cursor + 4 > n:
            return None, width, height

        seg_len = int.from_bytes(data[cursor + 2:cursor + 4], "big")

        if seg_len < 2:
            return None, width, height

        if marker in JPEG_SOF_MARKERS and width is None and cursor + 9 <= n:
            height = int.from_bytes(data[cursor + 5:cursor + 7], "big")
            width = int.from_bytes(data[cursor + 7:cursor + 9], "big")

        if marker == 0xDA:  # SOS — далі йдуть ентропійно-кодовані дані БЕЗ поля довжини
            i = cursor + 2 + seg_len
            advanced = False

            while i + 1 < n:

                if data[i] != 0xFF:
                    i += 1
                    continue

                nxt = data[i + 1]

                if nxt == 0x00 or (0xD0 <= nxt <= 0xD7):
                    i += 2  # byte-stuffing або restart-маркер всередині скану
                    continue

                if nxt == 0xD9:
                    return (i + 2 - pos), width, height

                if nxt != 0xFF:
                    cursor = i  # наступний реальний маркер — повертаємось у зовнішній цикл
                    advanced = True
                    break

                i += 1

            if not advanced:
                return None, width, height

            continue

        cursor = cursor + 2 + seg_len

    return None, width, height


def analyze_jpeg(
    obj: EmbeddedObject,
    data: bytes,
) -> None:

    length, width, height = _walk_jpeg(data, obj.offset)

    if length is not None:
        obj.size = length
        obj.metadata["end_offset"] = f"0x{obj.offset + length:X}"
    else:
        obj.metadata["note"] = "EOI not found in available data (truncated?)"

    if width is not None and height is not None:

        # SOF з розміром 0 у будь-якому вимірі, або з абсурдно великим
        # (реальні embedded-іконки/фони в цій прошивці — сотні пікселів,
        # не десятки тисяч) означає, що це не справжній SOF-сегмент, а
        # байти 0xFFD8FF випадково зустрілись у вже стиснутих/непроявлених
        # даних і "SOF" ми знайшли на випадковому зсуві всередині шуму.
        plausible = 0 < width <= 8192 and 0 < height <= 8192

        obj.metadata["width"] = width
        obj.metadata["height"] = height

        if not plausible:
            obj.validated = False
            obj.confidence = "low"
            obj.metadata["reason"] = "implausible_dimensions"


# ============================================================================
# Lua bytecode
# ============================================================================
#
# Формат заголовка (lundump.h) однаковий за компонуванням для Lua
# 5.1 / 5.2 / 5.3 / 5.4 (12 байт): сигнатура(4) + version(1) + format(1) +
# endianness(1) + size_int(1) + size_size_t(1) + size_Instruction(1) +
# size_lua_Number(1) + integral_flag(1).
#
# Lua 5.0 (перевірено за реальним джерелом: lua.org/source/5.0/lundump.c.html,
# функція LoadHeader) використовує ІНШУ розкладку — байта LUAC_FORMAT ще не
# існувало (з'явився лише в 5.1), а замість фінального однобайтного
# "integral_flag" на диск пишеться РЕАЛЬНЕ число TEST_NUMBER (кратне π,
# sizeof(lua_Number) байт), яке приймаюча сторона звіряє під час
# завантаження. Крім того, одразу за розмірами int/size_t/Instruction йдуть
# чотири додаткові байти — розрядність полів опкоду SIZE_OP/SIZE_A/SIZE_B/
# SIZE_C, — яких у 5.1+ вже немає:
#
#   сигнатура(4) + version(1) + endianness(1) + size_int(1) +
#   size_size_t(1) + size_Instruction(1) + size_OP(1) + size_A(1) +
#   size_B(1) + size_C(1) + size_lua_Number(1) + TEST_NUMBER(size_lua_Number)
#
# Раніше файли з version=0x50 завжди розбирались за 5.1-розкладкою і
# практично гарантовано провалювали перевірку полів — тобто "implausible_
# header_fields" на СПРАВЖНІХ Lua 5.0 чанках, а не лише на випадковому шумі.
#
# Повне розбирання тіла (константи, вкладені прототипи, debug-інфо)
# свідомо НЕ реалізоване — це окремий, набагато більший модуль
# (потрібен повноцінний lundump-рідер). Тут — чесна структурна
# валідація заголовка плюс витяг імені top-level чанка, яке одразу
# за заголовком зберігається як size_size_t-байтна довжина + рядок
# (типово шлях на кшталт "@menu/main.lua" — цінна підказка про
# структуру вихідного дерева OEM).

LUA_VERSION_NAMES = {
    0x50: "5.0",
    0x51: "5.1",
    0x52: "5.2",
    0x53: "5.3",
    0x54: "5.4",
}

LUA_HEADER_SIZE = 12

# Lua 5.0-специфічні константи (lundump.h 5.0.3).
LUA50_HEADER_FIXED = 14  # усе, ОКРІМ завершального TEST_NUMBER
LUA50_TEST_NUMBER = 3.14159265358979323846E7  # "a multiple of PI" (lundump.h)


def _read_lua_chunk_name(
    data: bytes,
    pos: int,
    size_size_t: int,
    little_endian: bool,
) -> str | None:

    if size_size_t not in (4, 8):
        return None

    if pos + size_size_t > len(data):
        return None

    raw = data[pos:pos + size_size_t]
    length = int.from_bytes(raw, "little" if little_endian else "big")

    if length == 0 or length > 4096:
        return None

    start = pos + size_size_t

    if start + length > len(data):
        return None

    text = data[start:start + length].rstrip(b"\x00").decode("latin1", errors="replace")

    if not text or not text.isprintable():
        return None

    return text


def _lua50_test_number_matches(
    raw: bytes,
    size_number: int,
    little_endian: bool,
) -> bool:
    """
    lundump.c 5.0.3 LoadHeader звіряє лише ЦІЛУ частину прочитаного числа з
    TEST_NUMBER (`if ((long)x != (long)tx) ... "unknown number format"`) —
    дробову частину відкидає. Повторюємо ту саму логіку: int() у Python
    truncatе до нуля так само, як (long) у C для додатних чисел, а
    TEST_NUMBER додатний.

    raw — довільні байти з прошивки, не гарантовано валідне число: окремі
    бітові комбінації декодуються як NaN/Inf, а int(nan)/int(inf) кидають
    ValueError/OverflowError (не struct.error!). analyze_objects() не має
    try/except навколо окремих аналізаторів, тож необроблений виняток тут
    завалив би аналіз усієї прошивки, а не лише позначив один об'єкт як
    невалідний — тому ловимо їх явно.
    """

    if size_number == 4:
        fmt = "<f" if little_endian else ">f"
    elif size_number == 8:
        fmt = "<d" if little_endian else ">d"
    else:
        return False

    if len(raw) < size_number:
        return False

    try:
        (value,) = struct.unpack(fmt, raw[:size_number])

        if not math.isfinite(value):
            return False

        return int(value) == int(LUA50_TEST_NUMBER)

    except (struct.error, ValueError, OverflowError):
        return False


def _analyze_lua_5_0(
    obj: EmbeddedObject,
    data: bytes,
    pos: int,
) -> None:
    """
    Окрема гілка для version byte 0x50 — заголовок Lua 5.0 НЕ сумісний за
    розкладкою з 5.1+ (див. коментар над LUA_VERSION_NAMES). Навмисно
    дзеркалить структуру analyze_lua() (список issues, ті самі ключі
    metadata там, де є прямий відповідник — reason/header_issues/note),
    щоб рендерер і JSON-export не потребували спеціальних гілок під
    конкретну версію Lua.
    """

    fixed = data[pos:pos + LUA50_HEADER_FIXED]

    if len(fixed) < LUA50_HEADER_FIXED:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "truncated_header"
        return

    endianness = fixed[5]
    size_int = fixed[6]
    size_size_t = fixed[7]
    size_instruction = fixed[8]
    size_op = fixed[9]
    size_a = fixed[10]
    size_b = fixed[11]
    size_c = fixed[12]
    size_number = fixed[13]

    obj.metadata.update(
        {
            "endianness_raw": endianness,
            "size_int": size_int,
            "size_size_t": size_size_t,
            "size_instruction": size_instruction,
            "size_op_bits": size_op,
            "size_a_bits": size_a,
            "size_b_bits": size_b,
            "size_c_bits": size_c,
            "size_number": size_number,
        }
    )

    issues: list[str] = []

    if endianness not in (0, 1):
        issues.append(f"endianness byte 0x{endianness:02X} (очікується 0x00 або 0x01)")

    if size_int not in (2, 4, 8):
        issues.append(f"size_int={size_int} (очікується 2, 4 або 8)")

    if size_size_t not in (4, 8):
        issues.append(f"size_size_t={size_size_t} (очікується 4 або 8)")

    if size_instruction not in (4, 8):
        issues.append(f"size_instruction={size_instruction} (очікується 4 або 8)")

    if size_number not in (4, 8):
        issues.append(f"size_number={size_number} (очікується 4 або 8)")

    # Розрядність полів опкоду (SIZE_OP/A/B/C) сама по собі довільна —
    # залежить від lopcodes.h конкретної збірки, тож не звіряємо з
    # фіксованими "стандартними" 6/8/9/9. Натомість вимагаємо структурної
    # узгодженості: OP+A+B+C мають РІВНО заповнювати Instruction
    # (size_instruction*8 біт) — перевіряємо лише якщо size_instruction
    # сам по собі вже правдоподібний.
    if size_instruction in (4, 8):
        total_bits = size_op + size_a + size_b + size_c
        expected_bits = size_instruction * 8

        if 0 in (size_op, size_a, size_b, size_c) or total_bits != expected_bits:
            issues.append(
                f"OP/A/B/C bit widths {size_op}+{size_a}+{size_b}+{size_c}="
                f"{total_bits} не заповнюють Instruction ({expected_bits} біт)"
            )

    if size_number in (4, 8):
        raw_number = data[pos + LUA50_HEADER_FIXED: pos + LUA50_HEADER_FIXED + size_number]

        if len(raw_number) < size_number:
            issues.append("TEST_NUMBER: недостатньо даних для перевірки")
        elif not _lua50_test_number_matches(raw_number, size_number, little_endian=(endianness == 1)):
            issues.append(
                "TEST_NUMBER не збігається з очікуваним π·10⁷ "
                "(зіпсований заголовок або нестандартний числовий формат)"
            )

    if issues:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "implausible_header_fields"
        obj.metadata["header_issues"] = issues
        obj.metadata["note"] = (
            "версія в заголовку впізнавана (Lua 5.0, version byte 0x50) —"
            " сигнатура, ймовірно, не випадкова, але формат тіла"
            " нестандартний (кастомний/патчений дампер, зсув заголовка,"
            " або справді пошкоджені дані)"
        )
        return

    obj.metadata["endianness"] = "little" if endianness == 1 else "big"

    chunk_name = _read_lua_chunk_name(
        data,
        pos + LUA50_HEADER_FIXED + size_number,
        size_size_t,
        little_endian=(endianness == 1),
    )

    if chunk_name:
        obj.metadata["chunk_name"] = chunk_name


def analyze_lua(
    obj: EmbeddedObject,
    data: bytes,
) -> None:

    pos = obj.offset

    header = data[pos:pos + LUA_HEADER_SIZE]

    if len(header) < LUA_HEADER_SIZE:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "truncated_header"
        return

    version_byte = header[4]

    known_version = version_byte in LUA_VERSION_NAMES

    obj.metadata["lua_version"] = LUA_VERSION_NAMES.get(
        version_byte,
        f"unknown (0x{version_byte:02X})",
    )

    if version_byte == 0x50:
        # Lua 5.0 має несумісну з 5.1+ розкладку заголовка — окрема гілка
        # замість спроби впхнути в поля нижче (детальніше в коментарі над
        # LUA_VERSION_NAMES).
        _analyze_lua_5_0(obj, data, pos)
        return

    fmt = header[5]
    endianness = header[6]
    size_int = header[7]
    size_size_t = header[8]
    size_instruction = header[9]
    size_number = header[10]
    integral_flag = header[11]

    # Завжди зберігаємо сирі поля заголовка — навіть коли вони не проходять
    # перевірку правдоподібності, вони самі по собі діагностично цінні
    # (напр. version=0x50 — це РЕАЛЬНА історична версія Lua 5.0, а не
    # сміття; user може сам вирішити, чи це кастомний/патчений дампер).
    obj.metadata.update(
        {
            "format": fmt,
            "endianness_raw": endianness,
            "size_int": size_int,
            "size_size_t": size_size_t,
            "size_instruction": size_instruction,
            "size_number": size_number,
            "integral_flag": integral_flag,
        }
    )

    # Перевіряємо кожне поле окремо (а не єдиним булевим "plausible"),
    # щоб можна було сказати НЕ просто "заголовок невалідний", а
    # конкретно ЯКЕ поле й чому — це і є той "діагноз", а не бінарний
    # accept/reject.
    issues: list[str] = []

    if endianness not in (0, 1):
        issues.append(f"endianness byte 0x{endianness:02X} (очікується 0x00 або 0x01)")

    if size_int not in (2, 4, 8):
        issues.append(f"size_int={size_int} (очікується 2, 4 або 8)")

    if size_size_t not in (4, 8):
        issues.append(f"size_size_t={size_size_t} (очікується 4 або 8)")

    if size_instruction not in (4, 8):
        issues.append(f"size_instruction={size_instruction} (очікується 4 або 8)")

    if size_number not in (4, 8):
        issues.append(f"size_number={size_number} (очікується 4 або 8)")

    if integral_flag not in (0, 1):
        issues.append(f"integral_flag={integral_flag} (очікується 0 або 1)")

    if issues:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "implausible_header_fields"
        obj.metadata["header_issues"] = issues

        if known_version:
            # version-байт РЕАЛЬНИЙ (напр. 0x50 = Lua 5.0), лише решта
            # заголовка не збігається зі стандартним lundump-форматом —
            # це вагоміший сигнал за випадковий збіг 4-байтної сигнатури:
            # ймовірно кастомний/патчений дампер, а не шум.
            obj.metadata["note"] = (
                "версія в заголовку впізнавана — сигнатура, ймовірно,"
                " не випадкова, але формат тіла нестандартний"
                " (кастомний/патчений дампер, або зсув заголовка)"
            )

        return

    obj.metadata.update(
        {
            "endianness": "little" if endianness == 1 else "big",
            "numbers_are_integers": bool(integral_flag),
        }
    )

    chunk_name = _read_lua_chunk_name(
        data,
        pos + LUA_HEADER_SIZE,
        size_size_t,
        little_endian=(endianness == 1),
    )

    if chunk_name:
        obj.metadata["chunk_name"] = chunk_name


# ============================================================================
# ELF binary
# ============================================================================
#
# На відміну від PNG/JPEG/Lua, ELF — це не вбудований ресурс, а формат
# виконуваного/об'єктного файлу. Але з точки зору пайплайну "знайти у
# прошивці бінарний об'єкт і глибоко його провалідувати" він нічим не
# відрізняється: той самий патерн detect_elf → analyze_elf, та сама
# модель EmbeddedObject з validated/confidence/metadata.
#
# Інфраструктура "про запас": для поточних MStar eCos-прошивок (де
# MBoot — сирий MIPS-бінарник без ELF-обгортки) детектор нічого не
# знайде і цей код безшумно не запуститься. Але для прошивок інших
# пристроїв, вкладених файлових систем (squashfs/jffs2), окремо
# прошитих .ko модулів чи рантайм-об'єктів (objloader) — дає повну
# картину: архітектуру, entry point, сегменти й секції з адресами.
#
# Розрізняємо (патерн Lua):
#   e_shoff == 0 / e_shnum == 0  →  section table відсутня (stripped).
#   Це НЕ помилка, лише інший режим парсингу: тоді спираємось виключно
#   на program headers (PT_LOAD сегменти), а .text/.data/.bss не
#   називаємо — бо імен секцій фізично немає.

ELF_E_TYPE = {
    0: "NONE",
    1: "REL (relocatable)",
    2: "EXEC (executable)",
    3: "DYN (shared object / PIE)",
    4: "CORE",
}

ELF_E_MACHINE = {
    0: "none",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
}

ELF_P_TYPE = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
}

# Флаги сегмента — побітова маска, що формує рядок типу "RWX".
ELF_PF_BITS = (
    (4, "R"),
    (2, "W"),
    (1, "X"),
)

ELF_SHT = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
}

# Флаги секції — теж побітова маска (SHF_*), формат "AX" / "A" / "WA" ...
ELF_SHF_BITS = (
    (0x2, "A"),   # SHF_ALLOC     — розвантажується в пам'ять
    (0x1, "W"),   # SHF_WRITE
    (0x4, "X"),   # SHF_EXECINSTR
)

ELF_EHSIZE_32 = 52
ELF_EHSIZE_64 = 64
ELF_PHENTSIZE_32 = 32
ELF_PHENTSIZE_64 = 56
ELF_SHENTSIZE_32 = 40
ELF_SHENTSIZE_64 = 64

# Дивний спеціальний випадок: e_shnum/e_phnum == 0xFFFF означає, що
# справжня кількість лежить у sh_link/ph_link нульової секції/сегмента.
# Ми це повноцінно не підтримуємо — лише чесно позначаємо.
ELF_EXTENDED_NUMBER = 0xFFFF


def _flag_string(value: int, bits: tuple[tuple[int, str], ...]) -> str:
    result = []
    for mask, letter in bits:
        if value & mask:
            result.append(letter)
    return "".join(result) if result else "-"


def _read_cstr(data: bytes, start: int) -> str:
    """NUL-terminated рядок з байтів, починаючи зі start."""
    end = data.find(b"\x00", start)
    if end == -1:
        end = len(data)
    try:
        return data[start:end].decode("ascii")
    except UnicodeDecodeError:
        return data[start:end].decode("latin1", errors="replace")


def _format_segments_text(segments: list[dict]) -> str:
    if not segments:
        return ""
    lines = []
    for seg in segments:
        lines.append(
            f"      {seg['type']:<10} off={seg['offset']} "
            f"vaddr={seg['vaddr']} filesz={seg['filesize']} "
            f"memsz={seg['memsize']} flags={seg['flags']}"
        )
    return "\n".join(lines)


def _format_sections_text(sections: list[dict]) -> str:
    if not sections:
        return ""
    lines = []
    for sec in sections:
        lines.append(
            f"      [{sec['index']:>2}] {sec['name']:<16} "
            f"{sec['type']:<10} addr={sec['addr']} "
            f"size={sec['size']} flags={sec['flags']}"
        )
    return "\n".join(lines)


def _parse_elf32_header(data: bytes, endian: str, pos: int = 0) -> dict:
    # e_type(H) e_machine(H) e_version(I) e_entry(I) e_phoff(I) e_shoff(I)
    # e_flags(I) e_ehsize(H) e_phentsize(H) e_phnum(H)
    # e_shentsize(H) e_shnum(H) e_shstrndx(H)
    (
        e_type, e_machine, _e_version, e_entry,
        e_phoff, e_shoff, _e_flags, e_ehsize,
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    ) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, pos + 16)
    return {
        "type": e_type, "machine": e_machine, "entry": e_entry,
        "phoff": e_phoff, "shoff": e_shoff, "ehsize": e_ehsize,
        "phentsize": e_phentsize, "phnum": e_phnum,
        "shentsize": e_shentsize, "shnum": e_shnum, "shstrndx": e_shstrndx,
        "is64": False,
    }


def _parse_elf64_header(data: bytes, endian: str, pos: int = 0) -> dict:
    # e_type(H) e_machine(H) e_version(I) e_entry(Q) e_phoff(Q) e_shoff(Q)
    # e_flags(I) e_ehsize(H) e_phentsize(H) e_phnum(H)
    # e_shentsize(H) e_shnum(H) e_shstrndx(H)
    (
        e_type, e_machine, _e_version, e_entry,
        e_phoff, e_shoff, _e_flags, e_ehsize,
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    ) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, pos + 16)
    return {
        "type": e_type, "machine": e_machine, "entry": e_entry,
        "phoff": e_phoff, "shoff": e_shoff, "ehsize": e_ehsize,
        "phentsize": e_phentsize, "phnum": e_phnum,
        "shentsize": e_shentsize, "shnum": e_shnum, "shstrndx": e_shstrndx,
        "is64": True,
    }


def _parse_program_headers(
    data: bytes, hdr: dict, endian: str, pos: int = 0,
) -> tuple[list[dict], list[str]]:
    segments: list[dict] = []
    notes: list[str] = []

    if hdr["phnum"] == 0 or hdr["phoff"] == 0:
        return segments, notes

    if hdr["phnum"] == ELF_EXTENDED_NUMBER:
        notes.append("extended program header numbering (e_phnum=0xFFFF) — not fully parsed")
        return segments, notes

    # phoff у заголовку відносний початку ELF — додаємо pos для доступу до data.
    phoff_abs = pos + hdr["phoff"]

    total = phoff_abs + hdr["phnum"] * hdr["phentsize"]
    if total > len(data):
        notes.append("program headers truncated (table extends past available data)")
        return segments, notes

    if hdr["phentsize"] < ELF_PHENTSIZE_32:
        notes.append(f"e_phentsize={hdr['phentsize']} too small — skipping program headers")
        return segments, notes

    for i in range(hdr["phnum"]):
        base = phoff_abs + i * hdr["phentsize"]
        try:
            if hdr["is64"]:
                # p_type(I) p_flags(I) p_offset(Q) p_vaddr(Q) p_paddr(Q)
                # p_filesz(Q) p_memsz(Q) p_align(Q)
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _p_align = (
                    struct.unpack_from(endian + "IIQQQQQQ", data, base)
                )
            else:
                # p_type(I) p_offset(I) p_vaddr(I) p_paddr(I)
                # p_filesz(I) p_memsz(I) p_flags(I) p_align(I)
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _p_align = (
                    struct.unpack_from(endian + "IIIIIIII", data, base)
                )
        except struct.error:
            notes.append(f"program header {i} unreadable")
            break

        segments.append({
            "type": ELF_P_TYPE.get(p_type, f"PT_0x{p_type:X}"),
            "offset": f"0x{p_offset:X}",
            "vaddr": f"0x{p_vaddr:X}",
            "filesize": p_filesz,
            "memsize": p_memsz,
            "flags": _flag_string(p_flags, ELF_PF_BITS),
            # сирі числові значення — потрібні для обчислення obj.size
            "_type_num": p_type,
            "_offset_num": p_offset,
            "_filesz_num": p_filesz,
        })

    return segments, notes


def _parse_section_headers(
    data: bytes, hdr: dict, endian: str, pos: int = 0,
) -> tuple[list[dict], list[str]]:
    sections: list[dict] = []
    notes: list[str] = []

    if hdr["shnum"] == 0 or hdr["shoff"] == 0:
        return sections, notes

    if hdr["shnum"] == ELF_EXTENDED_NUMBER:
        notes.append("extended section header numbering (e_shnum=0xFFFF) — not fully parsed")
        return sections, notes

    # shoff у заголовку відносний початку ELF — додаємо pos для доступу до data.
    shoff_abs = pos + hdr["shoff"]

    total = shoff_abs + hdr["shnum"] * hdr["shentsize"]
    if total > len(data):
        notes.append("section headers truncated (table extends past available data)")
        return sections, notes

    if hdr["shentsize"] < ELF_SHENTSIZE_32:
        notes.append(f"e_shentsize={hdr['shentsize']} too small — skipping section headers")
        return sections, notes

    # String table для імен секцій: секція з індексом e_shstrndx.
    # sh_offset всередині секції теж відносний початку ELF.
    strtab_start = None
    strtab_end = None
    if hdr["shstrndx"] != 0 and hdr["shstrndx"] < hdr["shnum"]:
        shstr_base = shoff_abs + hdr["shstrndx"] * hdr["shentsize"]
        try:
            if hdr["is64"]:
                _sh_name, _sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, *_ = (
                    struct.unpack_from(endian + "IIQQQQQQ", data, shstr_base)
                )
            else:
                _sh_name, _sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, *_ = (
                    struct.unpack_from(endian + "IIIIIIII", data, shstr_base)
                )
            strtab_start = pos + sh_offset
            strtab_end = pos + sh_offset + sh_size
            if strtab_end > len(data):
                strtab_end = len(data)
        except struct.error:
            pass

    for i in range(hdr["shnum"]):
        base = shoff_abs + i * hdr["shentsize"]
        try:
            if hdr["is64"]:
                # sh_name(I) sh_type(I) sh_flags(Q) sh_addr(Q)
                # sh_offset(Q) sh_size(Q) sh_link(I) sh_info(I) sh_addralign(Q) sh_entsize(Q)
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, _sh_entsize = (
                    struct.unpack_from(endian + "IIQQQQQQQQ", data, base)
                ) if hdr["shentsize"] >= ELF_SHENTSIZE_64 else (0,) * 10
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, _sh_entsize = (
                    struct.unpack_from(endian + "IIIIIIIIII", data, base)
                ) if hdr["shentsize"] >= ELF_SHENTSIZE_32 else (0,) * 10
        except struct.error:
            notes.append(f"section header {i} unreadable")
            break

        # Розв'язання імені через string table
        name = f"<{i}>"
        if strtab_start is not None and sh_name < (strtab_end - strtab_start):
            name = _read_cstr(data, strtab_start + sh_name)

        sections.append({
            "index": i,
            "name": name,
            "type": ELF_SHT.get(sh_type, f"SHT_0x{sh_type:X}"),
            "addr": f"0x{sh_addr:X}",
            "offset": f"0x{sh_offset:X}",
            "size": sh_size,
            "flags": _flag_string(sh_flags, ELF_SHF_BITS),
        })

    return sections, notes


def analyze_elf(obj: EmbeddedObject, data: bytes) -> None:
    """
    Глибока структурна валідація ELF-об'єкта.

    Патерн Lua: на відміну від бінарного accept/reject, реєструємо
    КОЖНЕ проблемне поле окремо (header_issues) — щоб у звіті було
    видно не просто "невалідний", а ЯКЕ саме поле й чому очікувалось.
    """

    pos = obj.offset

    # ------------------------------------------------------------------
    # Крок 1: e_ident (перші 16 байт) — визначає class/endian/version
    # ------------------------------------------------------------------

    if pos + 16 > len(data):
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "truncated_header"
        return

    ei_class = data[pos + 4]
    ei_data = data[pos + 5]
    ei_version = data[pos + 6]

    issues: list[str] = []

    if ei_class == 1:
        is64 = False
        expected_ehsize = ELF_EHSIZE_32
    elif ei_class == 2:
        is64 = True
        expected_ehsize = ELF_EHSIZE_64
    else:
        is64 = None
        expected_ehsize = None
        issues.append(f"ei_class={ei_class} (очікується 1=32-bit або 2=64-bit)")

    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        endian = ""
        issues.append(f"ei_data={ei_data} (очікується 1=LE або 2=BE)")

    if ei_version != 1:
        issues.append(f"ei_version={ei_version} (очікується 1)")

    # Якщо class/endian невідомі — подальший парсинг безглуздий.
    if is64 is None or endian == "":
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "invalid_elf_header"
        obj.metadata["header_issues"] = issues
        return

    # ------------------------------------------------------------------
    # Крок 2: повний ELF header
    # ------------------------------------------------------------------

    if pos + expected_ehsize > len(data):
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "truncated_header"
        obj.metadata["note"] = (
            f"сигнатура ELF розпізнана (class={'64' if is64 else '32'}-bit, "
            f"endian={'LE' if endian == '<' else 'BE'}), але заголовок "
            f"обрізаний — доступно {len(data) - pos} байт, потрібно {expected_ehsize}"
        )
        return

    try:
        if is64:
            hdr = _parse_elf64_header(data, endian, pos)
        else:
            hdr = _parse_elf32_header(data, endian, pos)
    except struct.error as exc:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "header_parse_error"
        obj.metadata["exception"] = str(exc)
        return

    # ------------------------------------------------------------------
    # Крок 3: валідація полів header (накопичуємо issues)
    # ------------------------------------------------------------------

    if hdr["ehsize"] != expected_ehsize:
        issues.append(
            f"e_ehsize={hdr['ehsize']} (очікується {expected_ehsize} для "
            f"{'64' if is64 else '32'}-bit)"
        )

    # phoff/shoff: або 0 (відсутні), або мають вказувати за межі header.
    header_end = pos + expected_ehsize
    for name in ("phoff", "shoff"):
        val = hdr[name]
        if val != 0 and val < expected_ehsize:
            issues.append(
                f"e_{name}=0x{val:X} вказує всередину ELF header "
                f"(очікується 0 або >= 0x{expected_ehsize:X})"
            )

    if hdr["phnum"] > ELF_EXTENDED_NUMBER:
        issues.append("e_phnum використовує extended numbering (0xFFFF)")

    if hdr["shnum"] > ELF_EXTENDED_NUMBER:
        issues.append("e_shnum використовує extended numbering (0xFFFF)")

    # shstrndx: або 0 (SHN_UNDEF), або валідний індекс секції.
    if hdr["shstrndx"] > hdr["shnum"] and hdr["shnum"] != 0:
        issues.append(
            f"e_shstrndx={hdr['shstrndx']} перевищує e_shnum={hdr['shnum']}"
        )

    # Накопичені структурні проблеми — demote, але продовжуємо з тім,
    # що розібрати реально вдалося (як Lua з note про custom dumper).
    if issues:
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "invalid_elf_header"
        obj.metadata["header_issues"] = issues

    # ------------------------------------------------------------------
    # Крок 4-5: program headers + section headers
    # ------------------------------------------------------------------

    segments, ph_notes = _parse_program_headers(data, hdr, endian, pos)
    sections, sh_notes = _parse_section_headers(data, hdr, endian, pos)

    notes = ph_notes + sh_notes

    has_program_headers = bool(segments) or hdr["phnum"] != 0
    has_section_headers = bool(sections) or (
        hdr["shnum"] != 0 and hdr["shoff"] != 0
    )

    if not has_section_headers and hdr["shoff"] == 0:
        notes.append(
            "section table absent (e_shoff=0) — likely stripped binary; "
            "only program headers available"
        )

    # ------------------------------------------------------------------
    # Крок 6: metadata
    # ------------------------------------------------------------------

    # Очищаємо службові "_*_num" поля з segments перед тим, як їх
    # побачить звіт/JSON — це деталі реалізації, не корисна інформація.
    clean_segments = [
        {k: v for k, v in seg.items() if not k.startswith("_")}
        for seg in segments
    ]

    obj.metadata.update({
        "class": "64-bit" if is64 else "32-bit",
        "data": "little-endian" if endian == "<" else "big-endian",
        "type": ELF_E_TYPE.get(hdr["type"], f"0x{hdr['type']:X}"),
        "machine": ELF_E_MACHINE.get(hdr["machine"], f"unknown (0x{hdr['machine']:X})"),
        "entry": f"0x{hdr['entry']:X}",
        "has_program_headers": has_program_headers,
        "has_section_headers": has_section_headers,
        "segments": clean_segments,
        "sections": sections,
        "segments_text": _format_segments_text(clean_segments),
        "sections_text": _format_sections_text(sections),
    })

    if notes:
        obj.metadata["note"] = "; ".join(notes)

    # ------------------------------------------------------------------
    # Крок 7: obj.size — скільки байтів у файлі займає цей ELF
    # ------------------------------------------------------------------
    #
    # Усі офсети в ELF (p_offset, sh_offset, e_shoff) відносні початку
    # файлу, тобто початку ELF. У буфері `data` ELF лежить з офсету
    # `pos`, тож усі кінці спочатку рахуємо як "абсолютні в data", а
    # потім віднімаємо `pos`, щоб отримати розмір самого ELF-об'єкта.

    end_candidates = []

    # max(p_offset + p_filesz) серед PT_LOAD (type=1)
    for seg in segments:
        if seg.get("_type_num") == 1 and seg.get("_filesz_num"):
            # _offset_num — відносний; + pos → абсолютний у data
            end_candidates.append(pos + seg["_offset_num"] + seg["_filesz_num"])

    # end of section header table (hdr["shoff"] відносний)
    if hdr["shnum"] and hdr["shnum"] != ELF_EXTENDED_NUMBER and hdr["shoff"]:
        end_candidates.append(
            pos + hdr["shoff"] + hdr["shnum"] * hdr["shentsize"]
        )

    # max(sh_offset + sh_size) серед секцій з реальними даними (не NOBITS).
    # sh_offset/sh_size перечитуємо з section header table напряму
    # (published sections зберігають їх лише як hex-рядки).
    if hdr["shnum"] and hdr["shnum"] != ELF_EXTENDED_NUMBER and hdr["shoff"]:
        shoff_abs = pos + hdr["shoff"]
        for i in range(min(hdr["shnum"], 4096)):
            base = shoff_abs + i * hdr["shentsize"]
            try:
                if is64:
                    _sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, *_ = (
                        struct.unpack_from(endian + "IIQQQQQQ", data, base)
                    )
                else:
                    _sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, *_ = (
                        struct.unpack_from(endian + "IIIIIIII", data, base)
                    )
                if sh_type != 8 and sh_size:  # не SHT_NOBITS (.bss не займає файл)
                    end_candidates.append(pos + sh_offset + sh_size)
            except struct.error:
                break

    if end_candidates:
        obj.size = max(end_candidates) - pos

    if end_candidates:
        obj.size = max(end_candidates) - pos


# ============================================================================
# MBoot Environment Block
# ============================================================================
#
# MBoot (MStar Boot) — видозмінений U-Boot.  Конфігураційний блок містить
# preamble (бінарні дані), version string (MBOT-...) та env variables
# (key=value пари, розділені \n).
#
# Детектор detect_mboot_env_block() у detectors/objects.py знаходить блок
# за маркером MBOT- та визначає межі.  Тут — глибокий парсинг:
# розбір version string, витяг env variables, заповнення metadata.


def analyze_mboot_env_block(obj: EmbeddedObject, data: bytes) -> None:
    """
    Глибокий парсинг MBoot Env Block.

    Делегує до analyzers/mboot_env.parse_mboot_env_block(), потім
    заповнює obj.metadata структурованими ключами для подальшого
    відображення у звіті та JSON-експорті.
    """
    from .analyzers.mboot_env import parse_mboot_env_block, compute_confidence

    # obj.offset — це offset маркера MBOT- (встановлює детектор)
    marker_pos = obj.offset
    if marker_pos + 10 > len(data):
        obj.validated = False
        obj.confidence = "low"
        obj.metadata["reason"] = "MBOT- marker near end of data"
        return

    info = parse_mboot_env_block(data, marker_pos)

    # Update confidence based on full parse
    preamble_found = info.preamble_size > 0
    obj.confidence = compute_confidence(info, preamble_found=preamble_found)

    # Metadata: version
    obj.metadata["mboot_version"] = info.version_string

    # Metadata: preamble
    obj.metadata["mboot_preamble_offset"] = info.preamble_offset
    obj.metadata["mboot_preamble_size"] = info.preamble_size

    # Metadata: variables (list of dicts для JSON-сумісності)
    obj.metadata["mboot_variables"] = [
        {
            "name": v.name,
            "value": v.value,
            "offset": v.offset,
            "length": v.length,
        }
        for v in info.variables
    ]
    obj.metadata["mboot_variable_count"] = len(info.variables)

    # Size: analyzer обчислює розмір як block_end - preamble_offset
    obj.size = info.block_end - info.preamble_offset