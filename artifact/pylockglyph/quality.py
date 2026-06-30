"""Reviewer-facing artifact quality gates."""
from __future__ import annotations

import ast
import csv
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .corpus import load_subjects, manager_counts
from .io import read_csv, write_json
from .model import EVIDENCE_TYPES, EvidenceType, MANAGERS
from .projections import PROJECTION_LABELS, PROJECTION_REQUIREMENTS, PROJECTIONS
from .study import DOWNSTREAM_CONSUMERS


def _write(output: Path | None, summary: dict[str, Any]) -> dict[str, Any]:
    if output is not None:
        write_json(output, summary)
    return summary


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _control_obligation(value: str) -> str:
    if value.startswith("remove:"):
        return value.split(":", 1)[1].split("+", 1)[0]
    if value.startswith("remove_"):
        return value.split("remove_", 1)[1]
    if value.startswith("weaken_"):
        return value.split("weaken_", 1)[1]
    return ""


def _negative_control_digest(artifact_root: Path) -> dict[str, Any]:
    evidence_root = artifact_root / "evidence"
    summary_path = evidence_root / "negative_control_summary.json"
    if summary_path.is_file():
        return json.loads(summary_path.read_text(encoding="utf-8"))
    file_rows = _csv_rows(evidence_root / "file_removals.csv")
    adversarial_rows = _csv_rows(evidence_root / "adversarial_vectors.csv")
    mutation_rows = _csv_rows(evidence_root / "executable_mutations.csv")
    metamorphic_rows = _csv_rows(evidence_root / "metamorphic_cases.csv")
    covered: set[str] = set()
    false_accepts = 0
    for row in file_rows:
        if row.get("removed_type"):
            covered.add(str(row["removed_type"]))
        if str(row.get("observed_eligible", "")).lower() == "true" or row.get("status") != "pass":
            false_accepts += 1
    for row in adversarial_rows:
        obligation = _control_obligation(str(row.get("attack", "")))
        if obligation:
            covered.add(obligation)
        if str(row.get("observed_eligible", "")).lower() == "true" or row.get("status") != "pass":
            false_accepts += 1
    for row in mutation_rows:
        obligation = _control_obligation(str(row.get("family", "")))
        if obligation:
            covered.add(obligation)
        if row.get("status") != "pass":
            false_accepts += 1
    weaken_rows = [row for row in metamorphic_rows if str(row.get("relation", "")).startswith("weaken_")]
    for row in weaken_rows:
        obligation = _control_obligation(str(row.get("relation", "")))
        if obligation:
            covered.add(obligation)
        if row.get("status") != "pass":
            false_accepts += 1
    return {
        "expected_reject_cases": len(file_rows) + len(adversarial_rows) + len(mutation_rows) + len(weaken_rows),
        "false_accepts": false_accepts,
        "obligations_covered": sorted(covered),
    }


def audit_corpus_diversity(artifact_root: Path, output: Path | None = None) -> dict[str, Any]:
    """Quantify the corpus concentration boundary used by the benchmark."""
    subjects = load_subjects(artifact_root)
    screening = read_csv(artifact_root / "data" / "corpus" / "screening_log.csv")
    included = [row for row in screening if row.get("included", "").lower() == "true"]
    excluded = [row for row in screening if row.get("included", "").lower() != "true"]
    counts = manager_counts(subjects)
    total = len(subjects)
    shares = {manager: (counts[manager] / total if total else 0.0) for manager in MANAGERS}
    hhi = sum(value * value for value in shares.values())
    entropy = -sum(value * math.log2(value) for value in shares.values() if value > 0)
    effective = 2 ** entropy if entropy else 0.0
    max_manager = max(shares, key=shares.get) if shares else ""
    duplicate_commits = [
        key
        for key, value in Counter((subject.repository, subject.commit) for subject in subjects).items()
        if value > 1
    ]
    repositories = {subject.repository for subject in subjects}
    license_files = []
    for subject in subjects:
        directory = subject.directory(artifact_root)
        license_like = sorted(
            path.name
            for path in directory.iterdir()
            if path.is_file() and path.name.lower().startswith(("license", "copying"))
        )
        license_files.append({"subject_id": subject.subject_id, "license_files": ";".join(license_like)})
    missing_license = [row["subject_id"] for row in license_files if not row["license_files"]]
    findings: list[dict[str, str]] = []
    if total != 41:
        findings.append({"severity": "P1", "check": "subject_count", "detail": str(total)})
    if len(included) != total:
        findings.append({"severity": "P1", "check": "screening_inclusion", "detail": f"included={len(included)} subjects={total}"})
    if len(excluded) != 16:
        findings.append({"severity": "P1", "check": "screening_exclusions", "detail": str(len(excluded))})
    if len([manager for manager, count in counts.items() if count > 0]) != len(MANAGERS):
        findings.append({"severity": "P1", "check": "manager_coverage", "detail": json.dumps(counts, sort_keys=True)})
    if shares and shares[max_manager] > 0.40:
        findings.append({"severity": "P1", "check": "manager_concentration", "detail": f"{max_manager}={shares[max_manager]:.3f}"})
    if hhi > 0.30:
        findings.append({"severity": "P1", "check": "hhi_concentration", "detail": f"{hhi:.3f}"})
    if duplicate_commits:
        findings.append({"severity": "P1", "check": "duplicate_repository_commit", "detail": str(duplicate_commits[:5])})
    if missing_license:
        findings.append({"severity": "P0", "check": "license_evidence", "detail": ";".join(missing_license[:10])})
    summary: dict[str, Any] = {
        "status": "pass" if not findings else "fail",
        "subjects": total,
        "screened_rows": len(screening),
        "included_rows": len(included),
        "excluded_rows": len(excluded),
        "manager_counts": counts,
        "manager_shares": {key: round(value, 6) for key, value in shares.items()},
        "max_manager": max_manager,
        "max_manager_share": round(shares[max_manager], 6) if shares else 0,
        "hhi": round(hhi, 6),
        "entropy_bits": round(entropy, 6),
        "effective_manager_count": round(effective, 6),
        "unique_repositories": len(repositories),
        "manager_project_subjects": sum(1 for subject in subjects if subject.manager_project),
        "license_evidence_rows": len(license_files),
        "findings": findings,
    }
    return _write(output, summary)


def audit_baseline_contract(artifact_root: Path, output: Path | None = None) -> dict[str, Any]:
    """Check that projection baselines are explicit, reproducible, and not tuned."""
    subjects = load_subjects(artifact_root)
    evidence_root = artifact_root / "evidence"
    consumer_summary = _csv_rows(evidence_root / "consumer_baseline_summary.csv")
    consumer_matrix = _csv_rows(evidence_root / "consumer_baseline_matrix.csv")
    projection_summary = _csv_rows(evidence_root / "projection_summary.csv")
    evidence_set = set(EVIDENCE_TYPES)
    findings: list[dict[str, str]] = []
    for projection, required in PROJECTION_REQUIREMENTS.items():
        if not required.issubset(evidence_set):
            findings.append({"severity": "P0", "check": "projection_unknown_evidence", "detail": projection})
        if projection not in PROJECTION_LABELS:
            findings.append({"severity": "P1", "check": "projection_label", "detail": projection})
    for consumer, required in DOWNSTREAM_CONSUMERS.items():
        if not required:
            findings.append({"severity": "P1", "check": "consumer_empty_requirement", "detail": consumer})
        if not required.issubset(evidence_set):
            findings.append({"severity": "P0", "check": "consumer_unknown_evidence", "detail": consumer})
    expected_summary_rows = len(DOWNSTREAM_CONSUMERS) * len(PROJECTIONS)
    expected_matrix_rows = len(subjects) * expected_summary_rows
    if len(consumer_summary) != expected_summary_rows:
        findings.append({"severity": "P1", "check": "consumer_summary_rows", "detail": str(len(consumer_summary))})
    if len(consumer_matrix) != expected_matrix_rows:
        findings.append({"severity": "P1", "check": "consumer_matrix_rows", "detail": str(len(consumer_matrix))})
    if len(projection_summary) != len(PROJECTIONS):
        findings.append({"severity": "P1", "check": "projection_summary_rows", "detail": str(len(projection_summary))})
    bad_decisions = [
        row for row in consumer_summary
        if row.get("decisions") and int(row["decisions"]) != len(subjects)
    ]
    if bad_decisions:
        findings.append({"severity": "P1", "check": "decision_denominator", "detail": str(bad_decisions[:3])})
    over = sum(int(row.get("baseline_over_admits", "0") or 0) for row in consumer_summary)
    under = sum(int(row.get("baseline_under_admits", "0") or 0) for row in consumer_summary)
    if over <= 0:
        findings.append({"severity": "P1", "check": "baseline_over_admission_signal", "detail": str(over)})
    if under <= 0:
        findings.append({"severity": "P2", "check": "baseline_under_admission_signal", "detail": str(under)})
    labels = {row.get("projection"): row.get("projection_label") for row in consumer_summary}
    for projection in PROJECTIONS:
        if labels.get(projection) != PROJECTION_LABELS[projection]:
            findings.append({"severity": "P1", "check": "projection_label_sync", "detail": projection})
    projection_support = {
        projection: sorted(item.value for item in PROJECTION_REQUIREMENTS[projection])
        for projection in PROJECTIONS
    }
    consumer_support = {
        consumer: sorted(item.value for item in DOWNSTREAM_CONSUMERS[consumer])
        for consumer in DOWNSTREAM_CONSUMERS
    }
    summary: dict[str, Any] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "subjects": len(subjects),
        "projections": len(PROJECTIONS),
        "downstream_consumers": len(DOWNSTREAM_CONSUMERS),
        "consumer_summary_rows": len(consumer_summary),
        "consumer_matrix_rows": len(consumer_matrix),
        "projection_summary_rows": len(projection_summary),
        "baseline_over_admissions": over,
        "baseline_under_admissions": under,
        "projection_support": projection_support,
        "consumer_support": consumer_support,
        "findings": findings,
    }
    return _write(output, summary)


def _method_files(artifact_root: Path) -> Iterable[Path]:
    names = {
        "certificate.py",
        "compat_toml.py",
        "controls.py",
        "io.py",
        "model.py",
        "parsers.py",
        "projections.py",
        "secondary.py",
        "study.py",
        "theory.py",
        "toml_writer.py",
    }
    for path in sorted((artifact_root / "pylockglyph").glob("*.py")):
        if path.name in names:
            yield path


def _branch_mentions_subject_fields(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []
    fields = ("subject_id", "repository", "commit", "local_path", "license_status")
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Match)):
            text = ast.unparse(node)
            if any(field in text for field in fields):
                hits.append(f"{path.name}:{getattr(node, 'lineno', '?')}")
    return hits


def audit_overfitting_sentinel(artifact_root: Path, output: Path | None = None) -> dict[str, Any]:
    """Detect subject-specific code paths and suspicious result-score framing."""
    subjects = load_subjects(artifact_root)
    subject_ids = {subject.subject_id for subject in subjects}
    repositories = {subject.repository for subject in subjects}
    commits = {subject.commit for subject in subjects if len(subject.commit) >= 12}
    source_hits: list[dict[str, str]] = []
    branch_hits: list[str] = []
    for path in _method_files(artifact_root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        relative = path.relative_to(artifact_root).as_posix()
        for token in sorted(subject_ids):
            if token in text:
                source_hits.append({"file": relative, "token_type": "subject_id", "token": token})
        for token in sorted(repositories):
            if token in text:
                source_hits.append({"file": relative, "token_type": "repository", "token": token})
        for token in sorted(commits):
            if token in text:
                source_hits.append({"file": relative, "token_type": "commit", "token": token[:12]})
        branch_hits.extend(_branch_mentions_subject_fields(path))
    score_headers: list[str] = []
    for csv_path in sorted((artifact_root / "evidence").glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
        for column in header:
            lowered = column.lower()
            if lowered in {"accuracy", "precision", "recall", "f1", "auc", "score"}:
                score_headers.append(f"{csv_path.name}:{column}")
    controlled = _csv_rows(artifact_root / "evidence" / "controlled_outcomes.csv")
    suites = {row.get("suite", "") for row in controlled}
    perfect_contract_suites = [
        row for row in controlled
        if row.get("cases") and row.get("pass") and row["cases"] == row["pass"]
    ]
    negative = _negative_control_digest(artifact_root)
    findings: list[dict[str, str]] = []
    if source_hits:
        findings.append({"severity": "P0", "check": "subject_specific_literals", "detail": json.dumps(source_hits[:10], sort_keys=True)})
    if branch_hits:
        findings.append({"severity": "P0", "check": "subject_specific_branch", "detail": ";".join(branch_hits[:10])})
    if score_headers:
        findings.append({"severity": "P1", "check": "accuracy_score_framing", "detail": ";".join(score_headers[:10])})
    if len(suites) < 6 or len(perfect_contract_suites) != len(controlled):
        findings.append({"severity": "P1", "check": "controlled_suite_shape", "detail": f"suites={len(suites)} perfect={len(perfect_contract_suites)}"})
    if not negative:
        findings.append({"severity": "P1", "check": "negative_control_summary", "detail": "missing"})
    else:
        covered = set(negative.get("obligations_covered", []))
        expected = {item.value for item in EVIDENCE_TYPES}
        if covered != expected:
            findings.append({"severity": "P1", "check": "negative_obligation_coverage", "detail": ";".join(sorted(expected - covered))})
        if int(negative.get("expected_reject_cases", 0)) <= 0:
            findings.append({"severity": "P1", "check": "expected_reject_cases", "detail": str(negative.get("expected_reject_cases"))})
        if int(negative.get("false_accepts", 0)) != 0:
            findings.append({"severity": "P1", "check": "negative_false_accepts", "detail": str(negative.get("false_accepts"))})
    summary: dict[str, Any] = {
        "status": "pass" if not findings else "fail",
        "method_files_scanned": len(list(_method_files(artifact_root))),
        "subjects": len(subjects),
        "subject_specific_literal_hits": source_hits,
        "subject_specific_branch_hits": branch_hits,
        "accuracy_style_score_headers": score_headers,
        "controlled_suites": sorted(suites),
        "controlled_suite_count": len(suites),
        "controlled_cases": sum(int(row.get("cases", "0") or 0) for row in controlled),
        "perfect_contract_suites": len(perfect_contract_suites),
        "expected_reject_cases": negative.get("expected_reject_cases"),
        "negative_false_accepts": negative.get("false_accepts"),
        "negative_obligations_covered": negative.get("obligations_covered", []),
        "findings": findings,
    }
    return _write(output, summary)


def audit_benchmark_scope_contract(artifact_root: Path, output: Path | None = None) -> dict[str, Any]:
    """Check that benchmark scope boundaries are executable facts."""
    spec_root = artifact_root / "spec"
    consumer_spec = json.loads((spec_root / "downstream_consumers.json").read_text(encoding="utf-8"))
    benchmark_spec = json.loads((spec_root / "benchmark_role.json").read_text(encoding="utf-8"))
    findings: list[dict[str, str]] = []
    consumer_rows = consumer_spec.get("consumers", [])
    observed = {
        row.get("consumer"): frozenset(EvidenceType(item) for item in row.get("required_evidence", []))
        for row in consumer_rows
    }
    if observed != DOWNSTREAM_CONSUMERS:
        findings.append({"severity": "P0", "check": "consumer_contract_sync", "detail": "spec does not match executable consumer requirements"})
    if consumer_spec.get("contract") != "formal evidence-obligation proxy":
        findings.append({"severity": "P1", "check": "consumer_contract_label", "detail": str(consumer_spec.get("contract"))})
    if consumer_spec.get("external_tool_execution_claim") is not False:
        findings.append({"severity": "P1", "check": "external_tool_claim", "detail": str(consumer_spec.get("external_tool_execution_claim"))})
    if "not an external tool execution baseline" not in str(consumer_spec.get("non_goal", "")).lower():
        findings.append({"severity": "P1", "check": "consumer_non_goal", "detail": str(consumer_spec.get("non_goal", ""))})
    reference_count = 0
    for row in consumer_rows:
        consumer = str(row.get("consumer", ""))
        required = [str(item) for item in row.get("required_evidence", [])]
        rationale = row.get("obligation_rationale", {})
        references = row.get("references", [])
        reference_count += len(references) if isinstance(references, list) else 0
        missing_rationale = [item for item in required if item not in rationale]
        if missing_rationale:
            findings.append({"severity": "P1", "check": "consumer_rationale", "detail": f"{consumer}:{','.join(missing_rationale)}"})
        if not isinstance(references, list) or not references:
            findings.append({"severity": "P2", "check": "consumer_external_references", "detail": consumer})
    study = json.loads((artifact_root / "evidence" / "study_summary.json").read_text(encoding="utf-8"))
    diversity_path = artifact_root / "evidence" / "corpus_diversity_summary.json"
    diversity = (
        json.loads(diversity_path.read_text(encoding="utf-8"))
        if diversity_path.is_file()
        else audit_corpus_diversity(artifact_root)
    )
    role = benchmark_spec.get("benchmark_role")
    if role != "construct_validation":
        findings.append({"severity": "P1", "check": "benchmark_role", "detail": str(role)})
    not_claims = set(benchmark_spec.get("not_claims", []))
    required_not_claims = {"ecosystem_prevalence", "manager_ranking", "random_sample", "comprehensive_ecosystem_coverage", "external_tool_success_rate"}
    if not required_not_claims.issubset(not_claims):
        findings.append({"severity": "P1", "check": "benchmark_not_claims", "detail": ",".join(sorted(required_not_claims - not_claims))})
    if int(study.get("subjects", 0)) < int(benchmark_spec.get("minimum_subjects", 0)):
        findings.append({"severity": "P1", "check": "minimum_subjects", "detail": str(study.get("subjects"))})
    if int(study.get("controlled_cases", 0)) < int(benchmark_spec.get("minimum_controlled_cases", 0)):
        findings.append({"severity": "P1", "check": "minimum_controlled_cases", "detail": str(study.get("controlled_cases"))})
    if int(study.get("proof_decisions", 0)) < int(benchmark_spec.get("minimum_proof_decisions", 0)):
        findings.append({"severity": "P1", "check": "minimum_proof_decisions", "detail": str(study.get("proof_decisions"))})
    if len([count for count in diversity.get("manager_counts", {}).values() if int(count) > 0]) < int(benchmark_spec.get("minimum_manager_families", 0)):
        findings.append({"severity": "P1", "check": "minimum_manager_families", "detail": json.dumps(diversity.get("manager_counts", {}), sort_keys=True)})
    if float(diversity.get("max_manager_share", 1.0)) > float(benchmark_spec.get("maximum_manager_share", 1.0)):
        findings.append({"severity": "P1", "check": "maximum_manager_share", "detail": str(diversity.get("max_manager_share"))})
    docs = "\n".join(
        (artifact_root / name).read_text(encoding="utf-8", errors="ignore")
        for name in ("README.md", "METHOD.md", "BENCHMARK.md", "REPLAY.md")
    ).lower()
    for phrase in (
        "formal evidence-obligation proxy",
        "not an external tool execution baseline",
        "construct-validation benchmark",
        "not a random sample",
    ):
        if phrase not in docs:
            findings.append({"severity": "P1", "check": "documentation_boundary_phrase", "detail": phrase})
    summary: dict[str, Any] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "consumer_contract": consumer_spec.get("contract"),
        "external_tool_execution_claim": consumer_spec.get("external_tool_execution_claim"),
        "consumer_contracts": len(consumer_rows),
        "consumer_reference_count": reference_count,
        "benchmark_role": role,
        "not_claims": sorted(not_claims),
        "subjects": study.get("subjects"),
        "controlled_cases": study.get("controlled_cases"),
        "proof_decisions": study.get("proof_decisions"),
        "max_manager_share": diversity.get("max_manager_share"),
        "findings": findings,
    }
    return _write(output, summary)
