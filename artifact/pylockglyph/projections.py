"""Baseline projections used for admission-contract separation."""
from __future__ import annotations

from .model import EvidenceType, ParsedSubject

PROJECTION_REQUIREMENTS: dict[str, frozenset[EvidenceType]] = {
    "parser": frozenset(),
    "inventory": frozenset({EvidenceType.IDENTITY, EvidenceType.VERSION}),
    "metadata": frozenset({EvidenceType.MANAGER_METADATA}),
    "integrity": frozenset({EvidenceType.INTEGRITY}),
    "manifest_subset": frozenset({EvidenceType.MANIFEST_AGREEMENT}),
    "source_identity": frozenset({EvidenceType.IDENTITY, EvidenceType.VERSION, EvidenceType.SOURCE}),
    "resolver_metadata": frozenset({EvidenceType.RESOLVER_EPOCH, EvidenceType.MANAGER_METADATA}),
    "sbom_minimal": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.MANAGER_METADATA,
    }),
    "vulnerability_graph": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.DEPENDENCY_EDGE,
    }),
    "reproducible_lock": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.INTEGRITY,
        EvidenceType.RESOLVER_EPOCH,
    }),
}

PROJECTION_LABELS: dict[str, str] = {
    "parser": "Parser succeeds",
    "inventory": "Name/version inventory",
    "metadata": "Manager metadata",
    "integrity": "Integrity evidence",
    "manifest_subset": "Manifest subset",
    "source_identity": "Source+identity",
    "resolver_metadata": "Resolver metadata",
    "sbom_minimal": "SBOM-minimal proxy",
    "vulnerability_graph": "Vulnerability-graph proxy",
    "reproducible_lock": "Reproducible-lock proxy",
}

PROJECTIONS: tuple[str, ...] = tuple(PROJECTION_REQUIREMENTS)


def accepts(parsed: ParsedSubject, projection: str) -> bool:
    if projection not in PROJECTION_REQUIREMENTS:
        raise KeyError(projection)
    if parsed.parser_status != "parsed" or not parsed.packages:
        return False
    return PROJECTION_REQUIREMENTS[projection].issubset(parsed.evidence.support())
