"""Finite replay of the admission algebra."""
from __future__ import annotations

from itertools import combinations
from .certificate import PROFILES, decide_vector
from .model import EVIDENCE_TYPES, EvidenceType, EvidenceVector, MANAGERS
from .projections import PROJECTION_REQUIREMENTS, PROJECTIONS


def vector(mask: int) -> EvidenceVector:
    return EvidenceVector({evidence_type: bool(mask & (1 << index)) for index, evidence_type in enumerate(EVIDENCE_TYPES)})


def projection_accepts_vector(evidence: EvidenceVector, projection: str) -> bool:
    if projection not in PROJECTION_REQUIREMENTS:
        raise KeyError(projection)
    return PROJECTION_REQUIREMENTS[projection].issubset(evidence.support())


def exhaustive_replay() -> tuple[list[dict[str, object]], dict[str, object]]:
    rows: list[dict[str, object]] = []
    definition_failures = 0
    monotonicity_failures = 0
    refinement_failures = 0
    substitution_failures = 0
    vectors = [vector(mask) for mask in range(1 << len(EVIDENCE_TYPES))]
    for manager in MANAGERS:
        for profile, required in PROFILES.items():
            for mask, evidence in enumerate(vectors):
                decision = decide_vector(f"v{mask}", "parsed", evidence, profile)
                expected = required.issubset(evidence.support())
                if decision.eligible != expected:
                    definition_failures += 1
                rows.append({"manager_family": manager, "profile": profile, "mask": mask, **evidence.as_dict(), "eligible": decision.eligible})
                if not decision.eligible:
                    for evidence_type in EVIDENCE_TYPES:
                        if not evidence.has(evidence_type):
                            continue
                        weaker = EvidenceVector({item: evidence.has(item) and item != evidence_type for item in EVIDENCE_TYPES})
                        if decide_vector("weaker", "parsed", weaker, profile).eligible:
                            monotonicity_failures += 1
            if profile == "dependency_graph":
                for evidence in vectors:
                    graph = decide_vector("g", "parsed", evidence, "dependency_graph").eligible
                    inventory = decide_vector("i", "parsed", evidence, "inventory").eligible
                    if graph and not inventory:
                        refinement_failures += 1
            for required_type in required:
                full = {item: item in required for item in EVIDENCE_TYPES}
                full[required_type] = False
                missing = EvidenceVector(full)
                if decide_vector("non-substitution", "parsed", missing, profile).eligible:
                    substitution_failures += 1
    summary = {
        "evidence_types": len(EVIDENCE_TYPES),
        "managers": len(MANAGERS),
        "profiles": len(PROFILES),
        "vectors_per_cell": 1 << len(EVIDENCE_TYPES),
        "decisions": len(rows),
        "definition_failures": definition_failures,
        "monotonicity_failures": monotonicity_failures,
        "profile_refinement_failures": refinement_failures,
        "typed_non_substitution_failures": substitution_failures,
        "status": "pass" if not any((definition_failures, monotonicity_failures, refinement_failures, substitution_failures)) else "fail",
    }
    return rows, summary


def separation_witnesses() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    supports = PROJECTION_REQUIREMENTS
    for manager in MANAGERS:
        for profile, required in PROFILES.items():
            for projection in PROJECTIONS:
                support = set(supports[projection])
                missing_candidates = [item for item in required if item not in support]
                missing = sorted(missing_candidates, key=lambda item: item.value)[0]
                # Add every projected requirement, leave at least one certificate requirement absent.
                evidence = EvidenceVector({item: item in support for item in EVIDENCE_TYPES})
                projection_accepts = projection_accepts_vector(evidence, projection)
                certificate_accepts = decide_vector("witness", "parsed", evidence, profile).eligible
                rows.append({
                    "manager_family": manager,
                    "profile": profile,
                    "projection": projection,
                    "projection_accepts": projection_accepts,
                    "certificate_accepts": certificate_accepts,
                    "missing_certificate_type": missing.value,
                    "support": ";".join(sorted(item.value for item in evidence.support())),
                    "status": "pass" if projection_accepts and not certificate_accepts else "fail",
                })
    return rows
