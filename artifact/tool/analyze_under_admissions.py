#!/usr/bin/env python3
"""Explain projection baseline under-admissions against consumer proxies."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.io import write_csv, write_json
from pylockglyph.model import EVIDENCE_TYPES, EvidenceType
from pylockglyph.projections import PROJECTION_REQUIREMENTS
from pylockglyph.study import DOWNSTREAM_CONSUMERS


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _support_by_subject(rows: list[dict[str, str]]) -> dict[str, frozenset[EvidenceType]]:
    support: dict[str, frozenset[EvidenceType]] = {}
    for row in rows:
        if row.get("profile") != "inventory":
            continue
        present = {
            evidence_type
            for evidence_type in EVIDENCE_TYPES
            if _truth(row.get(evidence_type.value))
        }
        support[str(row["subject_id"])] = frozenset(present)
    return support


def analyze_under_admissions(root: Path, rows_output: Path, summary_output: Path) -> dict[str, object]:
    evidence_root = root / "evidence"
    matrix = _rows(evidence_root / "consumer_baseline_matrix.csv")
    profile_rows = _rows(evidence_root / "profile_outcomes.csv")
    support = _support_by_subject(profile_rows)
    findings: list[dict[str, str]] = []
    rows: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    unexplained: list[str] = []

    for row in matrix:
        if not _truth(row.get("baseline_under_admits")):
            continue
        subject_id = str(row["subject_id"])
        consumer = str(row["consumer"])
        projection = str(row["projection"])
        consumer_required = DOWNSTREAM_CONSUMERS[consumer]
        projection_required = PROJECTION_REQUIREMENTS[projection]
        present = support.get(subject_id, frozenset())
        missing_projection = projection_required - present
        projection_only_missing = missing_projection - consumer_required
        if projection_only_missing and not (missing_projection & consumer_required):
            classification = "projection_requires_nonconsumer_evidence"
        elif not missing_projection:
            classification = "matrix_inconsistency"
        else:
            classification = "consumer_projection_requirement_conflict"
        counts[classification] += 1
        if classification != "projection_requires_nonconsumer_evidence":
            unexplained.append(f"{subject_id}:{consumer}:{projection}")
        rows.append({
            "subject_id": subject_id,
            "manager_family": row["manager_family"],
            "consumer": consumer,
            "projection": projection,
            "consumer_required_evidence": ";".join(item.value for item in sorted(consumer_required, key=lambda item: item.value)),
            "projection_required_evidence": ";".join(item.value for item in sorted(projection_required, key=lambda item: item.value)),
            "missing_projection_evidence": ";".join(item.value for item in sorted(missing_projection, key=lambda item: item.value)),
            "classification": classification,
        })

    if unexplained:
        findings.append({
            "severity": "P1",
            "check": "unexplained_under_admission",
            "detail": ";".join(unexplained[:20]),
        })
    if not rows:
        findings.append({
            "severity": "P2",
            "check": "under_admission_signal",
            "detail": "no baseline under-admissions were present to classify",
        })

    write_csv(rows_output, rows, [
        "subject_id",
        "manager_family",
        "consumer",
        "projection",
        "consumer_required_evidence",
        "projection_required_evidence",
        "missing_projection_evidence",
        "classification",
    ])
    summary: dict[str, object] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "under_admission_rows": len(rows),
        "classification_counts": dict(sorted(counts.items())),
        "false_negative_tool_cases": 0,
        "interpretation": "rows are projection-baseline comparisons against formal consumer proxies, not external tool false negatives",
        "findings": findings,
    }
    write_json(summary_output, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows-output", type=Path, default=ROOT / "evidence" / "under_admission_analysis.csv")
    parser.add_argument("--summary-output", type=Path, default=ROOT / "evidence" / "under_admission_summary.json")
    args = parser.parse_args()
    summary = analyze_under_admissions(ROOT, args.rows_output, args.summary_output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
