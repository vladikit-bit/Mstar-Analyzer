"""
Stage 5 — Розпакування кандидатів без зовнішніх утиліт.

Бере Finding-и, знайдені сканерами Stage 2/4 (передусім
LzmaHeuristicScanner, а також MagicScanner для gzip/xz), і намагається
реально розпакувати дані — лише стандартною бібліотекою (`lzma`, `zlib`),
без binwalk/7z/unlzma/xz у PATH.

Ключовий інсайт: LzmaHeuristicScanner шукає саме "класичний" .lzma-alone
заголовок (1 байт properties + 4 байти dict size LE + 8 байт
uncompressed size LE) — це РІВНО те, що очікує
`lzma.LZMADecompressor(format=FORMAT_ALONE)` зі стандартної бібліотеки.
Тобто Stage 2 і Stage 5 domовились про формат ще на етапі детектування,
зовнішній unlzma тут в принципі не потрібен.

Успішна декомпресія — це і є остаточне підтвердження гіпотези Stage 2:
заголовок міг збігтися випадково (false positive), а ось конкретний потік
байтів, що коректно розпаковується до кінця — вже ні.
"""

from __future__ import annotations

import lzma
import zlib
from dataclasses import dataclass, field

from .signatures import Finding

DEFAULT_CHUNK = 1 << 16          # 64 KiB за один "ковток" декомпресора
DEFAULT_MAX_OUTPUT = 64 << 20    # запобіжник: не більше 64 MiB на один candidate


@dataclass(slots=True)
class ExtractResult:
    offset: int
    method: str
    success: bool

    data: bytes | None = None
    consumed: int = 0
    output_size: int = 0
    error: str | None = None
    finding: Finding | None = None

    def __repr__(self) -> str:
        if self.success:
            return (f"<ExtractResult 0x{self.offset:08X} {self.method} "
                     f"OK out={self.output_size}B consumed={self.consumed}B>")
        return f"<ExtractResult 0x{self.offset:08X} {self.method} FAILED: {self.error}>"


class Extractor:
    """Базовий клас будь-якого розпаковувача (Stage 5 plugin API, симетрично Scanner у Stage 2)."""

    method = "base"

    def extract(self, data: bytes, offset: int,
                max_output: int = DEFAULT_MAX_OUTPUT,
                chunk_size: int = DEFAULT_CHUNK) -> ExtractResult:
        raise NotImplementedError


class _StreamExtractorMixin:
    """
    Спільна логіка для потокового decompressor-а stdlib
    (lzma.LZMADecompressor / zlib.decompressobj): годуємо його файлом
    шматками, доки він сам не скаже "я скінчився".
    """

    def _run(
        self,
        make_decompressor,
        data: bytes,
        offset: int,
        max_output: int,
        chunk_size: int,
    ) -> ExtractResult:

        dec = make_decompressor()
        out = bytearray()

        pos = offset
        n = len(data)
        consumed = 0

        try:
            while pos < n:

                chunk = data[pos:pos + chunk_size]
                out += dec.decompress(chunk)

                unused = getattr(dec, "unused_data", b"") or b""
                eof = getattr(dec, "eof", bool(unused))

                if eof:
                    consumed = (pos - offset) + (len(chunk) - len(unused))
                    break

                pos += len(chunk)

                if len(out) > max_output:
                    return ExtractResult(
                        offset=offset,
                        method=self.method,
                        success=False,
                        error=(
                            f"output exceeded {max_output} byte cap "
                            f"before end-of-stream"
                        ),
                    )

            else:
                return ExtractResult(
                    offset=offset,
                    method=self.method,
                    success=False,
                    error="reached end of file before end-of-stream marker",
                )

        except (lzma.LZMAError, zlib.error, EOFError) as exc:
            return ExtractResult(
                offset=offset,
                method=self.method,
                success=False,
                error=str(exc),
            )

        return ExtractResult(
            offset=offset,
            method=self.method,
            success=True,
            data=bytes(out),
            consumed=consumed,
            output_size=len(out),
        )


class LZMAExtractor(Extractor, _StreamExtractorMixin):
    """
    "Класичний" .lzma (alone) формат — точно те, що знаходить
    LzmaHeuristicScanner. Формат сам містить lc/lp/pb, dict size та
    (опційно) uncompressed size, тож stdlib розпаковує його без
    додаткових filters — не треба передавати їх вручну.
    """

    method = "lzma-alone"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE),
            data, offset, max_output, chunk_size,
        )


class XZExtractor(Extractor, _StreamExtractorMixin):
    """Контейнер .xz (magic FD 37 7A 58 5A 00) — про запас, якщо новіші прошивки перейдуть на нього."""

    method = "xz"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ),
            data, offset, max_output, chunk_size,
        )


class GZipExtractor(Extractor, _StreamExtractorMixin):
    """gzip (1F 8B 08) — zlib з wbits=MAX_WBITS|16 (авто-детект gzip-заголовка)."""

    method = "gzip"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: zlib.decompressobj(zlib.MAX_WBITS | 16),
            data, offset, max_output, chunk_size,
        )


class ZlibExtractor(Extractor, _StreamExtractorMixin):
    """Сирий zlib/deflate потік — рідше трапляється, але буває у ресурсних блоках."""

    method = "zlib"

    def extract(self, data, offset, max_output=DEFAULT_MAX_OUTPUT, chunk_size=DEFAULT_CHUNK):
        return self._run(
            lambda: zlib.decompressobj(),
            data, offset, max_output, chunk_size,
        )


class RawExtractor(Extractor):
    """
    Фолбек для методів без stdlib-реалізації (напр. LZO) або для
    нестиснутих блоків: просто копіює до max_output байт "as is",
    щоб було що подати далі у Stage 6 (Strings) без падіння пайплайну.
    """

    method = "raw"

    def extract(
        self,
        data,
        offset,
        max_output=DEFAULT_MAX_OUTPUT,
        chunk_size=DEFAULT_CHUNK,
    ):
        chunk = data[offset: offset + max_output]

        return ExtractResult(
            offset=offset,
            method=self.method,
            success=True,
            data=chunk,
            consumed=len(chunk),
            output_size=len(chunk),
        )


# --------------------------------------------------------------------------
# Finding.name -> Extractor (той самий принцип, що DEFAULT_SCANNERS у Stage 2,
# тільки тут це явний реєстр, а не список — за порадою "прибрати DEFAULT_SCANNERS
# і зробити явну реєстрацію")
# --------------------------------------------------------------------------

_EXTRACTOR_BY_NAME: dict[str, type[Extractor]] = {
    "lzma-alone-header": LZMAExtractor,
    "gzip": GZipExtractor,
    "xz": XZExtractor,
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


_CONFIDENCE_PRIORITY = {"high": 0, "medium": 1, "low": 2}


@dataclass(order=True)
class Candidate:
    """Finding + призначений Extractor + пріоритет спроби."""

    priority: int
    offset: int
    finding: Finding = field(compare=False)
    extractor: Extractor = field(compare=False)

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        factory: ExtractorFactory = DEFAULT_FACTORY,
    ) -> "Candidate | None":

        extractor = factory.for_finding(finding)

        if extractor is None:
            return None

        return cls(
            priority=_CONFIDENCE_PRIORITY.get(
                finding.confidence,
                9,
            ),
            offset=finding.offset,
            finding=finding,
            extractor=extractor,
        )

    def extract(
        self,
        data: bytes,
        **kwargs,
    ) -> ExtractResult:

        result = self.extractor.extract(
            data,
            self.offset,
            **kwargs,
        )

        result.finding = self.finding

        return result


def build_candidates(
    findings: list[Finding],
    factory: ExtractorFactory = DEFAULT_FACTORY,
) -> list[Candidate]:

    candidates: list[Candidate] = []

    for finding in findings:
        candidate = Candidate.from_finding(
            finding,
            factory,
        )

        if candidate is not None:
            candidates.append(candidate)

    candidates.sort()

    return candidates


def extract_all(
    data: bytes,
    findings: list[Finding],
    factory: ExtractorFactory = DEFAULT_FACTORY,
    max_output: int = DEFAULT_MAX_OUTPUT,
    chunk_size: int = DEFAULT_CHUNK,
    skip_covered: bool = True,
) -> list[ExtractResult]:
    """
    for candidate in candidates: candidate.extract() — без гілкувань по типу.

    Якщо skip_covered=True: успішно розпакований діапазон
    [offset, offset+consumed) "накриває" всі інші кандидати всередині себе.
    Це типово хибні спрацювання LzmaHeuristicScanner всередині вже
    підтвердженого потоку — їх повторно не намагаємось розпаковувати.
    """
    results: list[ExtractResult] = []
    covered: list[tuple[int, int]] = []

    for candidate in build_candidates(findings, factory):
        if skip_covered and any(start <= candidate.offset < end for start, end in covered):
            continue

        result = candidate.extract(data, max_output=max_output, chunk_size=chunk_size)
        results.append(result)

        if result.success:
            covered.append((candidate.offset, candidate.offset + max(result.consumed, 1)))

    return results
