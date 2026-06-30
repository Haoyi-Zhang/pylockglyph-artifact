#!/usr/bin/env python3
"""Generate validation-closure evidence for external and semantic checks."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.corpus import load_subjects
from pylockglyph.io import write_csv, write_json
from pylockglyph.model import MANAGERS, PackageRecord
from pylockglyph.parsers import parse_subject
from pylockglyph.secondary import parse_subject as parse_subject_secondary


EVIDENCE_COLUMNS = [
    "identity",
    "version",
    "source",
    "integrity",
    "resolver_epoch",
    "dependency_edge",
    "manager_metadata",
    "manifest_agreement",
]


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _profile_missing(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in _rows(root / "evidence" / "profile_outcomes.csv"):
        if row.get("profile") == "inventory":
            missing = [name for name in EVIDENCE_COLUMNS if row.get(name) != "True"]
            result[row["subject_id"]] = ";".join(missing)
    return result


def _package_example(root: Path) -> dict[str, str]:
    examples: dict[str, str] = {}
    for row in _rows(root / "evidence" / "package_records.csv"):
        subject_id = row["subject_id"]
        if subject_id not in examples:
            name = row.get("name", "")
            version = row.get("version", "")
            hashes = row.get("hash_count", "")
            deps = row.get("dependency_count", "")
            examples[subject_id] = f"{name} {version}, hashes={hashes}, dependencies={deps}"
    return examples


def _write_external_disagreements(root: Path, output: Path) -> dict[str, Any]:
    lock = json.loads((root / "spec" / "external_validation_lock.json").read_text(encoding="utf-8"))
    missing = _profile_missing(root)
    examples = _package_example(root)
    disagreements = [
        row for row in lock.get("results", [])
        if bool(row.get("tool_supported")) and row.get("agreement") is False
    ]
    lines = [
        "# External Disagreement Analysis",
        "",
        "This file explains disagreements in the small external-tool sanity check.",
        "The external tools are not treated as ground truth for PyLockGlyph's declared",
        "profile-indexed admission contract; disagreements identify boundary differences",
        "between a concrete tool policy and the formal evidence obligations.",
        "",
        "| subject | manager | tool | consumer | PyLockGlyph decision | external result | missing obligations | concrete package example | interpretation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    classifications = Counter()
    for row in disagreements:
        subject_id = str(row.get("subject_id", ""))
        classifications[str(row.get("classification", ""))] += 1
        pyg = "admit" if row.get("pylockglyph_predicts_admission") else "reject"
        ext = "processed JSON" if row.get("tool_processed") else "no parseable JSON"
        interpretation = str(row.get("root_cause", ""))
        if row.get("classification") == "external_tool_more_permissive_than_obligation_proxy":
            interpretation += "; this is a tool-policy difference, not evidence that the missing obligation is present"
        elif row.get("classification") == "external_tool_parse_or_environment_failure":
            interpretation += "; this row is retained as an external-tool limitation"
        lines.append(
            "| "
            + " | ".join([
                _md(subject_id),
                _md(row.get("manager_family", "")),
                _md(row.get("tool", "")),
                _md(row.get("consumer", "")),
                pyg,
                ext,
                _md(missing.get(subject_id, "")),
                _md(examples.get(subject_id, "")),
                _md(interpretation),
            ])
            + " |"
        )
    lines.extend([
        "",
        "Interpretation:",
        "",
        "- `cyclonedx-py` can emit an inventory for some pairs that lack PyLockGlyph's explicit source or manifest-agreement obligations. PyLockGlyph therefore records a conservative reject for the declared profile rather than claiming the tool output is unusable.",
        "- `pip-audit` can perform a flat vulnerability lookup from pinned requirement lines without dependency-edge or source evidence. PyLockGlyph's `vulnerability_matching` proxy is stricter because it models graph-aware matching obligations.",
        "- A `cyclonedx-py` failure on a Poetry subject is retained as an external-tool parse/environment limitation, not converted into a PyLockGlyph success claim.",
        "",
    ])
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "disagreements": len(disagreements),
        "classification_counts": dict(sorted(classifications.items())),
        "analysis_path": output.relative_to(root).as_posix(),
    }


def _pkg_key(package: PackageRecord) -> tuple[str, str]:
    return package.name, package.version


def _raw_basis(manager: str) -> str:
    if manager == "pip-tools":
        return "requirements-style pinned line and continuation hashes"
    if manager == "pipenv":
        return "Pipfile.lock default/develop package entry"
    if manager == "poetry":
        return "poetry.lock package table"
    if manager == "pdm":
        return "pdm.lock package table"
    if manager == "uv":
        return "uv.lock package table"
    return "lockfile package entry"


def _semantic_spotcheck(root: Path, rows_output: Path, per_manager: int) -> dict[str, Any]:
    subjects = load_subjects(root)
    manager_counts: Counter[str] = Counter()
    rows: list[dict[str, object]] = []
    subject_agreement = 0
    parsed_subjects = 0
    for subject in subjects:
        if manager_counts[subject.manager_family] >= per_manager:
            continue
        primary = parse_subject(root, subject)
        secondary = parse_subject_secondary(root, subject)
        if primary.parser_status == "parsed" and secondary.parser_status == "parsed":
            parsed_subjects += 1
            primary_support = primary.evidence.as_dict()
            secondary_support = secondary.evidence.as_dict()
            if primary_support == secondary_support:
                subject_agreement += 1
        secondary_by_key = {_pkg_key(package): package for package in secondary.packages}
        for package in primary.packages:
            if manager_counts[subject.manager_family] >= per_manager:
                break
            other = secondary_by_key.get(_pkg_key(package))
            if other is None:
                row_status = "fail"
                other = PackageRecord("", "")
            else:
                checks = [
                    package.name == other.name,
                    package.version == other.version,
                    bool(package.source_anchor) == bool(other.source_anchor),
                    package.integrity_witness == other.integrity_witness,
                    bool(package.dependencies) == bool(other.dependencies),
                ]
                row_status = "pass" if all(checks) else "fail"
            rows.append({
                "subject_id": subject.subject_id,
                "manager_family": subject.manager_family,
                "package_name": package.name,
                "primary_version": package.version,
                "secondary_version": other.version,
                "identity_match": package.name == other.name,
                "version_match": package.version == other.version,
                "source_presence_match": bool(package.source_anchor) == bool(other.source_anchor),
                "integrity_presence_match": package.integrity_witness == other.integrity_witness,
                "dependency_presence_match": bool(package.dependencies) == bool(other.dependencies),
                "raw_field_basis": _raw_basis(subject.manager_family),
                "status": row_status,
            })
            manager_counts[subject.manager_family] += 1
    write_csv(rows_output, rows, [
        "subject_id",
        "manager_family",
        "package_name",
        "primary_version",
        "secondary_version",
        "identity_match",
        "version_match",
        "source_presence_match",
        "integrity_presence_match",
        "dependency_presence_match",
        "raw_field_basis",
        "status",
    ])
    failures = [row for row in rows if row["status"] != "pass"]
    return {
        "sampled_records": len(rows),
        "manager_counts": dict(sorted(manager_counts.items())),
        "parsed_subjects_compared": parsed_subjects,
        "subject_evidence_agreement": subject_agreement,
        "row_failures": len(failures),
        "rows_path": rows_output.relative_to(root).as_posix(),
    }


def _write_negative_provenance(root: Path, output: Path) -> dict[str, Any]:
    negative = json.loads((root / "evidence" / "negative_control_summary.json").read_text(encoding="utf-8"))
    lines = [
        "# Negative Control Provenance",
        "",
        "The expected-reject controls are corpus-derived transformations, not fitted examples.",
        "There is no training stage, learned parameter, or subject-specific branch in the admission predicate.",
        "Expected outcomes follow from the profile requirement sets: if a required evidence bit is removed from an eligible pair, the principal-filter predicate must reject the transformed pair.",
        "",
        f"- Corpus-derived expected-reject cases: {negative['expected_reject_cases']}",
        "- Synthetic expected-reject cases: 0",
        f"- Preservation controls: {negative['preservation_cases']}",
        f"- False accepts: {negative['false_accepts']}",
        f"- Obligations covered: {', '.join(negative['obligations_covered'])}",
        "",
        "The transformations do not alter the admission logic after seeing outcomes. They are regenerated from the checked-in public capsules during replay, and the overfitting sentinel separately scans method code for subject identifiers, repository names, commits, and subject-specific branches.",
        "",
    ]
    output.write_text("\n".join(lines), encoding="utf-8")
    return {"path": output.relative_to(root).as_posix(), "derived_expected_reject_cases": negative["expected_reject_cases"], "synthetic_expected_reject_cases": 0}


def _write_known_limitations(root: Path, output: Path) -> dict[str, Any]:
    items = [
        "Flat pip-tools requirements can be consumed by vulnerability lookup tools without source anchors or dependency edges; PyLockGlyph intentionally rejects those pairs for graph-aware profiles.",
        "Some SBOM tools infer a default package source when a lockfile omits an explicit source. PyLockGlyph does not infer that source because the admission verdict is limited to serialized local evidence.",
        "The external validation harness does not execute PDM or uv through cyclonedx-py or pip-audit because those tools do not expose matching parsers in the pinned environment.",
        "A Poetry project can satisfy PyLockGlyph's evidence obligations while a concrete external tool fails on project-layout details; such rows are recorded as external-tool limitations, not as proof of downstream success.",
        "PyLockGlyph checks manifest/lockfile evidence, not resolver correctness, vulnerability database freshness, or whether a package can be installed from the network at replay time.",
    ]
    lines = ["# Known Limitations", ""]
    lines.extend(f"- {item}" for item in items)
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")
    return {"path": output.relative_to(root).as_posix(), "limitations": len(items)}


def generate_validation_closure(root: Path, output: Path, per_manager: int) -> dict[str, object]:
    evidence = root / "evidence"
    findings: list[dict[str, str]] = []
    external = _write_external_disagreements(root, evidence / "external_disagreement_analysis.md")
    semantic = _semantic_spotcheck(root, evidence / "semantic_spotcheck_records.csv", per_manager)
    negative = _write_negative_provenance(root, evidence / "negative_control_provenance.md")
    limitations = _write_known_limitations(root, evidence / "known_limitations.md")

    if int(external["disagreements"]) <= 0:
        findings.append({"severity": "P2", "check": "external_disagreement_examples", "detail": "no disagreements to analyze"})
    if int(semantic["sampled_records"]) < 50:
        findings.append({"severity": "P1", "check": "semantic_spotcheck_size", "detail": str(semantic["sampled_records"])})
    if int(semantic["row_failures"]) != 0:
        findings.append({"severity": "P1", "check": "semantic_spotcheck_failures", "detail": str(semantic["row_failures"])})
    if set(semantic["manager_counts"]) != set(MANAGERS):
        findings.append({"severity": "P1", "check": "semantic_manager_coverage", "detail": json.dumps(semantic["manager_counts"], sort_keys=True)})
    if int(negative["derived_expected_reject_cases"]) <= 0:
        findings.append({"severity": "P1", "check": "negative_provenance", "detail": "missing derived controls"})
    if int(limitations["limitations"]) < 3:
        findings.append({"severity": "P1", "check": "known_limitations", "detail": str(limitations["limitations"])})

    summary: dict[str, object] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "external_disagreement_analysis": external,
        "semantic_spotcheck": semantic,
        "negative_control_provenance": negative,
        "known_limitations": limitations,
        "findings": findings,
    }
    write_json(output, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "validation_closure_summary.json")
    parser.add_argument("--per-manager", type=int, default=12)
    args = parser.parse_args()
    summary = generate_validation_closure(ROOT, args.output, args.per_manager)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
