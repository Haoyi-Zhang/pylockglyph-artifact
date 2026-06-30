"""Profile-indexed admission predicate."""
from __future__ import annotations

from dataclasses import dataclass
from .model import CertificateDecision, EvidenceType, EvidenceVector, ParsedSubject


PROFILES: dict[str, frozenset[EvidenceType]] = {
    "inventory": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.INTEGRITY,
        EvidenceType.RESOLVER_EPOCH,
        EvidenceType.MANAGER_METADATA,
        EvidenceType.MANIFEST_AGREEMENT,
    }),
    "dependency_graph": frozenset(EvidenceType),
}


def decide_vector(subject_id: str, parser_status: str, evidence: EvidenceVector, profile: str) -> CertificateDecision:
    if profile not in PROFILES:
        raise KeyError(f"unknown consumer profile: {profile}")
    missing = evidence.missing(PROFILES[profile])
    eligible = parser_status == "parsed" and not missing
    return CertificateDecision(subject_id, profile, eligible, missing, evidence, parser_status)


def decide(parsed: ParsedSubject, profile: str) -> CertificateDecision:
    return decide_vector(parsed.subject.subject_id, parsed.parser_status, parsed.evidence, profile)
