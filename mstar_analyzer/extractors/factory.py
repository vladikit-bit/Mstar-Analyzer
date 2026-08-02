from __future__ import annotations

from .base import Extractor
from .lzma import LZMAExtractor
from .gzip import GZipExtractor
from .xz import XZExtractor
from .zlib import ZlibExtractor
from .bzip2 import BZip2Extractor
from .squashfs import SquashFsExtractor
from ..signatures import Finding


# --------------------------------------------------------------------------
# Finding.name -> Extractor (той самий принцип, що DEFAULT_SCANNERS у Stage 2,
# тільки тут це явний реєстр, а не список — за порадою "прибрати DEFAULT_SCANNERS
# і зробити явну реєстрацію")
# --------------------------------------------------------------------------

_EXTRACTOR_BY_NAME: dict[str, type[Extractor]] = {
    "lzma-alone-header": LZMAExtractor,
    "gzip": GZipExtractor,
    "xz": XZExtractor,
    "bzip2": BZip2Extractor,
    # ZlibExtractor сам по собі існував і був покритий тестами
    # (tests/test_stream_extractors.py) задовго до цього запису — але
    # без нього ExtractorFactory.for_finding() ніколи не знаходив
    # extractor для Finding.name="zlib" (ZlibHeuristicScanner,
    # signatures.py), тож жоден candidate для сирого zlib-потоку
    # ніколи не будувався.
    "zlib": ZlibExtractor,
    "SquashFS (LE)": SquashFsExtractor,
    "SquashFS (BE)": SquashFsExtractor,
}

# НЕ додавайте сюди generic "raw"-фолбек за замовчуванням. Раніше в
# проєкті був RawExtractor, зареєстрований лише "про запас" і фактично
# ніколи не використовувався — жодного Finding.name, що потребував би
# такого фолбека (напр. LZO), Stage 2 ще не породжує. А `Finding` тут —
# це НЕ лише кандидати на розпакування: MagicScanner так само віддає
# "PNG"/"JPEG"/"ELF"/"UBI#"/"SquashFS (LE)"/"cramfs"/"DTB", а
# AsciiMarkerScanner — десятки "marker:*" на кожен збіг. Generic
# фолбек тут почав би "розпаковувати" (сирим копіюванням) геть усе це
# теж — PNG/ELF мають власний, набагато кращий шлях аналізу через
# object_analyzer, а не мають дублюватись сюди. Коли з'явиться реальний
# Finding без stdlib-декомпресора (LZO), заводьте extractor і
# реєструйте його явно під ТОЧНЕ ім'я цього Finding — так само, як
# зроблено для решти записів у цьому словнику.


class ExtractorFactory:
    """Реєстр Finding.name -> Extractor. Нові методи додаються через register(), pipeline не міняється."""

    def __init__(self):
        self._by_name = dict(_EXTRACTOR_BY_NAME)

    def register(self, finding_name: str, extractor_cls: type[Extractor]) -> None:
        self._by_name[finding_name] = extractor_cls

    def for_finding(self, finding: Finding) -> Extractor | None:
        cls = self._by_name.get(finding.name)
        return cls() if cls else None


DEFAULT_FACTORY = ExtractorFactory()
