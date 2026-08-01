from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class EmbeddedObject:

    offset: int

    size: int | None

    kind: str

    description: str

    confidence: str = "high"

    metadata: dict[str, object] = field(default_factory=dict)

    validated: bool = True


def detect_objects(data: bytes) -> list[EmbeddedObject]:
    """
    Detect embedded objects inside a firmware node.

    This module DOES NOT extract anything.

    It only reports what appears to exist.
    """

    objects: list[EmbeddedObject] = []

    for detector in DETECTORS:
        objects.extend(detector(data))

    return objects


def detect_png(data: bytes) -> list[EmbeddedObject]:

    objects: list[EmbeddedObject] = []

    pos = 0

    while True:

        pos = data.find(b"\x89PNG\r\n\x1a\n", pos)

        if pos == -1:
            break

        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="PNG",
                description="PNG image",
            )
        )

        pos += 8
        

    return objects

def detect_jpeg(data: bytes) -> list[EmbeddedObject]:

    objects: list[EmbeddedObject] = []

    pos = 0

    while True:

        pos = data.find(b"\xff\xd8\xff", pos)

        if pos == -1:
            break
        
        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="JPEG",
                description="JPEG image",
            )
        )

        pos += 3

    return objects

LUA_SIGNATURE = b"\x1bLua"


ELF_SIGNATURE = b"\x7fELF"


def detect_elf(data: bytes) -> list[EmbeddedObject]:
    """
    Пошук ELF-об'єктів (сигнатура 7F 45 4C 46).

    Як і детектори PNG/JPEG/Lua, лише фіксує кандидата за магічними
    байтами. Глибока структурна валідація (class/endian/machine/сегменти/
    секції) виконує object_analyzer.analyze_elf().

    Для поточних MStar eCos-прошивок ELF у флеші немає — детектор
    безшумно нічого не знайде. Інфраструктура "про запас": для прошивок
    інших пристроїв, вкладених файлових систем тощо.
    """

    objects: list[EmbeddedObject] = []

    pos = 0

    while True:

        pos = data.find(ELF_SIGNATURE, pos)

        if pos == -1:
            break

        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="ELF",
                description="ELF binary",
            )
        )

        pos += 4

    return objects


def detect_lua_bytecode(data: bytes) -> list[EmbeddedObject]:
    """
    Пошук скомпільованих Lua chunk'ів (сигнатура ESC 'L' 'u' 'a', далі —
    1-байтна версія: 0x51=5.1, 0x52=5.2, 0x53=5.3, 0x54=5.4).

    Це саме та "знахідка", навколо якої точилось обговорення архітектури
    проєкту: якщо GUI/меню приставки написані на Lua і зберігаються як
    прекомпільований bytecode (а не тільки викликаються з C), логіку
    можна досліджувати й патчити значно простіше, ніж машинний код MIPS.

    Глибша валідація (структура заголовка, ім'я чанка) — у
    object_analyzer.analyze_lua().
    """

    objects: list[EmbeddedObject] = []

    pos = 0

    while True:

        pos = data.find(LUA_SIGNATURE, pos)

        if pos == -1:
            break

        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="Lua bytecode",
                description="Compiled Lua chunk",
            )
        )

        pos += 4

    return objects


def detect_mboot_env_block(data: bytes) -> list[EmbeddedObject]:
    """
    Пошук MBoot Env Block (MStar Boot environment configuration).

    Шукає маркер ``MBOT-`` — початок version string в блоці конфігурації
    MBoot (видозмінений U-Boot).  Детектор НЕ розбирає внутрішню структуру —
    лише фіксує кандидат.  Глибокий парсинг (preamble, version string, env
    variables, size, confidence) виконує
    ``object_analyzer.analyze_mboot_env_block()``.

    Підтримує декілька MBoot-блоків в одному файлі (кожен маркер —
    окремий EmbeddedObject).
    """
    objects: list[EmbeddedObject] = []
    n = len(data)
    pos = 0

    while True:
        pos = data.find(b"MBOT-", pos)
        if pos == -1:
            break

        # Базова валідація: маркер має бути не на самому кінці файлу
        if pos + 10 > n:
            pos += 1
            continue

        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="MBootEnvBlock",
                description="MBoot environment block",
                confidence="low",
            )
        )

        pos += 5  # пропустити "MBOT-"

    return objects


DTB_SIGNATURE = b"\xd0\x0d\xfe\xed"


def detect_dtb(data: bytes) -> list[EmbeddedObject]:
    """
    Пошук Flattened Device Tree (сигнатура 0xD00DFEED, big-endian,
    Devicetree Specification §5.2). Той самий magic вже фігурував у
    Stage 2 MagicScanner (signatures.py) як плоский Finding — тут він
    стає повноцінним EmbeddedObject з подальшим структурним розбором
    заголовка через object_analyzer.analyze_dtb() (за тим самим
    принципом, що ELF/Lua/MBoot вище: детектор лише фіксує кандидата
    за magic bytes, глибоку валідацію виконує окрема функція).
    """

    objects: list[EmbeddedObject] = []

    pos = 0

    while True:

        pos = data.find(DTB_SIGNATURE, pos)

        if pos == -1:
            break

        objects.append(
            EmbeddedObject(
                offset=pos,
                size=None,
                kind="DTB",
                description="Flattened Device Tree",
            )
        )

        pos += 4

    return objects


UIMAGE_MAGIC_BE = b"\x27\x05\x19\x56"

# Той самий magic, але побайтово перевернутий — нестандартний варіант,
# якого офіційна специфікація U-Boot не передбачає (заголовок ЗАВЖДИ
# мережевого порядку байтів незалежно від архітектури цілі), але який
# MagicScanner (signatures.py) вже ловив окремим записом "uImage (LE)"
# до цього — тож детектор і далі розпізнає обидва варіанти, а
# object_analyzer.analyze_uimage() визначає порядок байтів решти полів
# за тим, яка саме сигнатура збіглась.
UIMAGE_MAGIC_LE = b"\x56\x19\x05\x27"


def detect_uimage(data: bytes) -> list[EmbeddedObject]:
    """
    U-Boot legacy image header (IH_MAGIC = 0x27051956, image.h у
    вихідному коді U-Boot). MStar MBoot — задокументований у коментарях
    цього проєкту як "видозмінений U-Boot" — тож той самий формат
    заголовка цілком може трапитись у прошивці окремо від власне
    MBoot-специфічного env-блоку (детектор/аналізатор якого вже є).
    """

    objects: list[EmbeddedObject] = []

    for magic in (UIMAGE_MAGIC_BE, UIMAGE_MAGIC_LE):

        pos = 0

        while True:

            pos = data.find(magic, pos)

            if pos == -1:
                break

            objects.append(
                EmbeddedObject(
                    offset=pos,
                    size=None,
                    kind="uImage",
                    description="U-Boot legacy image header",
                )
            )

            pos += 4

    return objects


DETECTORS = (
    detect_png,
    detect_jpeg,
    detect_lua_bytecode,
    detect_elf,
    detect_mboot_env_block,
    detect_dtb,
    detect_uimage,
)