from __future__ import annotations

from dataclasses import dataclass, field

from .base import Extractor, ExtractResult, DEFAULT_CHUNK, DEFAULT_MAX_OUTPUT
from .factory import ExtractorFactory, DEFAULT_FACTORY
from ..signatures import Finding


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
