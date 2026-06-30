"""Deterministic study replay and result materialization."""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .certificate import PROFILES, decide
from .controls import adversarial_cases, file_removal_cases, formatting_cases, metamorphic_cases, mutation_cases, parser_agreement_cases
from .corpus import audit_capsule, load_subjects, manager_counts
from .io import read_csv, write_csv, write_json
from .model import EVIDENCE_TYPES, EvidenceType, MANAGERS, ParsedSubject
from .parsers import parse_all
from .projections import PROJECTION_LABELS, PROJECTIONS, accepts as projection_accepts
from .theory import exhaustive_replay, separation_witnesses


def _profile_rows(parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        for profile in PROFILES:
            rows.append({"manager_family": parsed.subject.manager_family, **decide(parsed, profile).as_dict()})
    return rows


def _manager_profile_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    totals = Counter(str(row["manager_family"]) for row in rows if row["profile"] == "inventory")
    eligible = Counter((str(row["manager_family"]), str(row["profile"])) for row in rows if row["eligible"])
    result = []
    for manager in MANAGERS:
        result.append({
            "manager_family": manager,
            "pairs": totals[manager],
            "inventory_eligible": eligible[(manager, "inventory")],
            "dependency_graph_eligible": eligible[(manager, "dependency_graph")],
        })
    result.append({
        "manager_family": "Total",
        "pairs": sum(totals.values()),
        "inventory_eligible": sum(eligible[(manager, "inventory")] for manager in MANAGERS),
        "dependency_graph_eligible": sum(eligible[(manager, "dependency_graph")] for manager in MANAGERS),
    })
    return result


def _missing_summary(parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows = []
    for manager in MANAGERS:
        subjects = [parsed for parsed in parsed_subjects if parsed.subject.manager_family == manager]
        row: dict[str, object] = {"manager_family": manager, "pairs": len(subjects)}
        for evidence_type in EVIDENCE_TYPES:
            row[evidence_type.value] = sum(not parsed.evidence.has(evidence_type) for parsed in subjects)
        rows.append(row)
    return rows


def _package_rows(parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows = []
    for parsed in parsed_subjects:
        for package in parsed.packages:
            rows.append({
                "subject_id": parsed.subject.subject_id,
                "manager_family": parsed.subject.manager_family,
                "name": package.name,
                "version": package.version,
                "hash_count": len(package.hashes),
                "source_anchor": package.source_anchor,
                "integrity_witness": package.integrity_witness,
                "dependency_count": len(package.dependencies),
                "groups": ";".join(package.groups),
                "marker": package.marker,
            })
    return rows


def _projection_rows(parsed_subjects: tuple[ParsedSubject, ...]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        for profile in PROFILES:
            certificate = decide(parsed, profile)
            for projection in PROJECTIONS:
                projected = projection_accepts(parsed, projection)
                rows.append({
                    "subject_id": parsed.subject.subject_id,
                    "manager_family": parsed.subject.manager_family,
                    "profile": profile,
                    "projection": projection,
                    "projection_accepts": projected,
                    "certificate_accepts": certificate.eligible,
                    "projection_over_admits": projected and not certificate.eligible,
                    "missing_certificate_types": ";".join(item.value for item in certificate.missing),
                })
    summary = []
    for projection in PROJECTIONS:
        selected = [row for row in rows if row["projection"] == projection]
        summary.append({
            "projection": projection,
            "decisions": len(selected),
            "projection_accepts": sum(bool(row["projection_accepts"]) for row in selected),
            "certificate_accepts": sum(bool(row["certificate_accepts"]) for row in selected),
            "projection_over_admits": sum(bool(row["projection_over_admits"]) for row in selected),
        })
    return rows, summary


DOWNSTREAM_CONSUMERS: dict[str, frozenset[EvidenceType]] = {
    "sbom_inventory": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.MANAGER_METADATA,
        EvidenceType.MANIFEST_AGREEMENT,
    }),
    "vulnerability_matching": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.DEPENDENCY_EDGE,
        EvidenceType.MANAGER_METADATA,
        EvidenceType.MANIFEST_AGREEMENT,
    }),
    "reproducible_input": frozenset({
        EvidenceType.IDENTITY,
        EvidenceType.VERSION,
        EvidenceType.SOURCE,
        EvidenceType.INTEGRITY,
        EvidenceType.RESOLVER_EPOCH,
        EvidenceType.MANAGER_METADATA,
        EvidenceType.MANIFEST_AGREEMENT,
    }),
    "full_dependency_graph": frozenset(EVIDENCE_TYPES),
}


def _consumer_accepts(parsed: ParsedSubject, consumer: str) -> bool:
    required = DOWNSTREAM_CONSUMERS[consumer]
    return parsed.parser_status == "parsed" and bool(parsed.packages) and required.issubset(parsed.evidence.support())


def _consumer_baseline_rows(parsed_subjects: tuple[ParsedSubject, ...]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        for consumer in DOWNSTREAM_CONSUMERS:
            consumer_accepts = _consumer_accepts(parsed, consumer)
            missing = [
                item.value
                for item in EVIDENCE_TYPES
                if item in DOWNSTREAM_CONSUMERS[consumer] and not parsed.evidence.has(item)
            ]
            for projection in PROJECTIONS:
                baseline_accepts = projection_accepts(parsed, projection)
                rows.append({
                    "subject_id": parsed.subject.subject_id,
                    "manager_family": parsed.subject.manager_family,
                    "consumer": consumer,
                    "projection": projection,
                    "projection_label": PROJECTION_LABELS[projection],
                    "baseline_accepts": baseline_accepts,
                    "consumer_accepts": consumer_accepts,
                    "baseline_over_admits": baseline_accepts and not consumer_accepts,
                    "baseline_under_admits": consumer_accepts and not baseline_accepts,
                    "missing_consumer_evidence": ";".join(missing),
                })
    summary: list[dict[str, object]] = []
    for consumer in DOWNSTREAM_CONSUMERS:
        for projection in PROJECTIONS:
            selected = [row for row in rows if row["consumer"] == consumer and row["projection"] == projection]
            summary.append({
                "consumer": consumer,
                "projection": projection,
                "projection_label": PROJECTION_LABELS[projection],
                "decisions": len(selected),
                "baseline_accepts": sum(bool(row["baseline_accepts"]) for row in selected),
                "consumer_accepts": sum(bool(row["consumer_accepts"]) for row in selected),
                "baseline_over_admits": sum(bool(row["baseline_over_admits"]) for row in selected),
                "baseline_under_admits": sum(bool(row["baseline_under_admits"]) for row in selected),
            })
    return rows, summary


def _timing(artifact_root: Path, rounds: int = 3) -> dict[str, object]:
    subjects = load_subjects(artifact_root)
    per_round = []
    per_subject_ms: list[float] = []
    for _ in range(rounds):
        start = time.perf_counter()
        for subject in subjects:
            subject_start = time.perf_counter()
            parse_all(artifact_root, (subject,))
            per_subject_ms.append((time.perf_counter() - subject_start) * 1000)
        per_round.append(time.perf_counter() - start)
    per_subject_ms.sort()
    median = per_subject_ms[len(per_subject_ms) // 2]
    p95 = per_subject_ms[min(len(per_subject_ms) - 1, int(len(per_subject_ms) * 0.95))]
    total_seconds = sum(per_round)
    return {
        "rounds": rounds,
        "subject_parses": rounds * len(subjects),
        "elapsed_seconds": round(total_seconds, 6),
        "subjects_per_second": round((rounds * len(subjects)) / total_seconds, 2) if total_seconds else None,
        "median_subject_ms": round(median, 4),
        "p95_subject_ms": round(p95, 4),
    }


def run_study(artifact_root: Path, output_dir: Path) -> dict[str, object]:
    """Run the local study while materializing each evidence family eagerly.

    The evidence tables are intentionally written as soon as their row family is
    produced. This keeps the replay memory envelope small enough for constrained
    artifact-evaluation containers and prevents a late write from being masked by
    a previous successful replay.
    """
    import gc

    output_dir.mkdir(parents=True, exist_ok=True)
    subjects = load_subjects(artifact_root)
    parsed = parse_all(artifact_root, subjects)

    profile_rows = _profile_rows(parsed)
    manager_summary = _manager_profile_summary(profile_rows)
    inventory_total = sum(bool(row["eligible"]) for row in profile_rows if row["profile"] == "inventory")
    graph_total = sum(bool(row["eligible"]) for row in profile_rows if row["profile"] == "dependency_graph")
    write_csv(output_dir / "profile_outcomes.csv", profile_rows)
    write_csv(output_dir / "manager_profile_summary.csv", manager_summary)

    missing = _missing_summary(parsed)
    write_csv(output_dir / "missing_obligations.csv", missing)

    package_rows = _package_rows(parsed)
    package_count = len(package_rows)
    write_csv(output_dir / "package_records.csv", package_rows)
    del package_rows
    gc.collect()

    projection_rows, projection_summary = _projection_rows(parsed)
    projection_count = len(projection_rows)
    projection_over = sum(bool(row["projection_over_admits"]) for row in projection_rows)
    write_csv(output_dir / "projection_disagreement.csv", projection_rows)
    write_csv(output_dir / "projection_summary.csv", projection_summary)
    del projection_rows
    gc.collect()

    consumer_rows, consumer_summary = _consumer_baseline_rows(parsed)
    consumer_count = len(consumer_rows)
    consumer_over = sum(bool(row["baseline_over_admits"]) for row in consumer_rows)
    consumer_under = sum(bool(row["baseline_under_admits"]) for row in consumer_rows)
    write_csv(output_dir / "consumer_baseline_matrix.csv", consumer_rows)
    write_csv(output_dir / "consumer_baseline_summary.csv", consumer_summary)
    del consumer_rows
    gc.collect()

    capsule_rows = audit_capsule(artifact_root, subjects)
    all_capsules_pass = all(row["status"] == "pass" for row in capsule_rows)
    write_csv(output_dir / "corpus_capsule_audit.csv", capsule_rows)

    truth_rows, proof_summary = exhaustive_replay()
    write_csv(output_dir / "certificate_truth_table.csv", truth_rows)
    write_json(output_dir / "proof_obligations.json", proof_summary)
    del truth_rows
    gc.collect()

    witnesses = separation_witnesses()
    witness_count = len(witnesses)
    write_csv(output_dir / "projection_separation_witnesses.csv", witnesses)

    # Measure the unmodified parser before mutation suites allocate controls.
    timing = _timing(artifact_root)
    write_json(output_dir / "timing_summary.json", timing)

    file_rows = file_removal_cases(artifact_root, parsed)
    file_pass = sum(row["status"] == "pass" for row in file_rows)
    write_csv(output_dir / "file_removals.csv", file_rows)

    adversarial = adversarial_cases(parsed)
    adversarial_pass = sum(row["status"] == "pass" for row in adversarial)
    adversarial_count = len(adversarial)
    write_csv(output_dir / "adversarial_vectors.csv", adversarial)
    del adversarial
    gc.collect()

    mutations = mutation_cases(parsed, file_rows)
    mutation_pass = sum(row["status"] == "pass" for row in mutations)
    mutation_count = len(mutations)
    write_csv(output_dir / "executable_mutations.csv", mutations)
    del mutations
    gc.collect()

    metamorphic = metamorphic_cases(parsed, file_rows)
    metamorphic_pass = sum(row["status"] == "pass" for row in metamorphic)
    metamorphic_count = len(metamorphic)
    write_csv(output_dir / "metamorphic_cases.csv", metamorphic)
    del metamorphic
    gc.collect()

    formatting = formatting_cases(artifact_root, parsed)
    formatting_pass = sum(row["status"] == "pass" for row in formatting)
    formatting_count = len(formatting)
    write_csv(output_dir / "formatting_cases.csv", formatting)
    del formatting
    gc.collect()

    parser_agreement = parser_agreement_cases(artifact_root, parsed)
    parser_pass = sum(row["status"] == "pass" for row in parser_agreement)
    parser_count = len(parser_agreement)
    write_csv(output_dir / "independent_parser_audit.csv", parser_agreement)
    del parser_agreement
    gc.collect()

    controlled = [
        {"suite": "file_removals", "cases": len(file_rows), "pass": file_pass},
        {"suite": "adversarial_vectors", "cases": adversarial_count, "pass": adversarial_pass},
        {"suite": "metamorphic", "cases": metamorphic_count, "pass": metamorphic_pass},
        {"suite": "mutations", "cases": mutation_count, "pass": mutation_pass},
        {"suite": "formatting", "cases": formatting_count, "pass": formatting_pass},
        {"suite": "parser_agreement", "cases": parser_count, "pass": parser_pass},
    ]
    write_csv(output_dir / "controlled_outcomes.csv", controlled)
    del file_rows

    screening = read_csv(artifact_root / "data" / "corpus" / "screening_log.csv")
    excluded = [row for row in screening if row["included"] != "true"]
    all_control_pass = all(row["cases"] == row["pass"] for row in controlled)
    status = "pass" if len(subjects) == 41 and package_count == 2050 and inventory_total == 13 and graph_total == 8 and proof_summary["status"] == "pass" and all_control_pass and all_capsules_pass else "fail"
    summary: dict[str, Any] = {
        "status": status,
        "subjects": len(subjects),
        "screened_rows": len(screening),
        "excluded_rows": len(excluded),
        "manager_counts": manager_counts(subjects),
        "package_records": package_count,
        "profiles": {"inventory": inventory_total, "dependency_graph": graph_total},
        "projection_decisions": projection_count,
        "projection_over_admissions": projection_over,
        "downstream_consumers": len(DOWNSTREAM_CONSUMERS),
        "consumer_baseline_decisions": consumer_count,
        "consumer_baseline_over_admissions": consumer_over,
        "consumer_baseline_under_admissions": consumer_under,
        "controlled_cases": sum(row["cases"] for row in controlled),
        "controlled_outcomes": controlled,
        "proof_decisions": proof_summary["decisions"],
        "separation_witnesses": witness_count,
    }
    write_json(output_dir / "study_summary.json", summary)
    return summary
