from __future__ import annotations

from .base import Extractor
from .lzma import LZMAExtractor
from .gzip import GZipExtractor
from .xz import XZExtractor
from .bzip2 import BZip2Extractor
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
}


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
