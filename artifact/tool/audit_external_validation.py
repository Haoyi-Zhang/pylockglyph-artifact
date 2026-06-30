#!/usr/bin/env python3
"""Audit the frozen small-sample external-tool validation lock."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.corpus import load_subjects
from pylockglyph.io import sha256_file, write_csv, write_json
from pylockglyph.parsers import parse_all
from pylockglyph.study import DOWNSTREAM_CONSUMERS


def _truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _predict_by_subject(root: Path, subject_ids: set[str]) -> dict[tuple[str, str], bool]:
    selected = tuple(subject for subject in load_subjects(root) if subject.subject_id in subject_ids)
    parsed = parse_all(root, selected)
    predictions: dict[tuple[str, str], bool] = {}
    for item in parsed:
        support = item.evidence.support()
        for consumer, required in DOWNSTREAM_CONSUMERS.items():
            predictions[(item.subject.subject_id, consumer)] = (
                item.parser_status == "parsed" and bool(item.packages) and required.issubset(support)
            )
    return predictions


def audit_external_validation(root: Path, lock_path: Path, rows_output: Path, summary_output: Path) -> dict[str, object]:
    findings: list[dict[str, str]] = []
    if not lock_path.is_file():
        findings.append({"severity": "P1", "check": "external_validation_lock", "detail": "missing"})
        summary = {"status": "fail", "findings": findings}
        write_json(summary_output, summary)
        return summary

    lock: dict[str, Any] = json.loads(lock_path.read_text(encoding="utf-8"))
    results = list(lock.get("results", []))
    selected_subjects = list(lock.get("selected_subjects", []))
    subject_ids = {str(row.get("subject_id", "")) for row in selected_subjects}
    managers = {str(row.get("manager_family", "")) for row in selected_subjects}
    tools = {str(row.get("tool", "")) for row in results}
    supported = [row for row in results if bool(row.get("tool_supported"))]
    processed = [row for row in supported if bool(row.get("tool_processed"))]
    disagreements = [row for row in supported if row.get("agreement") is False]
    unsupported = [row for row in results if not bool(row.get("tool_supported"))]

    if lock.get("schema_version") != 1:
        findings.append({"severity": "P0", "check": "schema_version", "detail": str(lock.get("schema_version"))})
    if len(subject_ids) < 15:
        findings.append({"severity": "P1", "check": "subject_sample", "detail": str(len(subject_ids))})
    if len(managers) < 5:
        findings.append({"severity": "P1", "check": "manager_family_coverage", "detail": ";".join(sorted(managers))})
    if len(tools) < 2:
        findings.append({"severity": "P1", "check": "tool_count", "detail": str(len(tools))})
    if len(supported) < 10:
        findings.append({"severity": "P1", "check": "supported_run_attempts", "detail": str(len(supported))})
    if len(processed) < 3:
        findings.append({"severity": "P1", "check": "processed_external_runs", "detail": str(len(processed))})

    missing_classification = [
        f"{row.get('subject_id')}:{row.get('tool')}"
        for row in disagreements + [row for row in supported if not bool(row.get("tool_processed"))]
        if not str(row.get("classification", "")).strip() or not str(row.get("root_cause", "")).strip()
    ]
    if missing_classification:
        findings.append({
            "severity": "P1",
            "check": "disagreement_root_cause",
            "detail": ";".join(missing_classification[:20]),
        })
    environment_path_leaks = [
        f"{row.get('subject_id')}:{row.get('tool')}"
        for row in results
        for stderr_tail in [str(row.get("stderr_tail", "")).replace("\\", "/")]
        if any(marker in stderr_tail for marker in ("/data/", "/home/", "/tmp/", "/Users/"))
    ]
    if environment_path_leaks:
        findings.append({
            "severity": "P1",
            "check": "external_validation_log_hygiene",
            "detail": ";".join(environment_path_leaks[:20]),
        })

    predictions = _predict_by_subject(root, subject_ids)
    drift: list[str] = []
    rows: list[dict[str, object]] = []
    for row in results:
        subject_id = str(row.get("subject_id", ""))
        consumer = str(row.get("consumer", ""))
        current = predictions.get((subject_id, consumer))
        locked = bool(row.get("pylockglyph_predicts_admission"))
        if current is not None and current != locked:
            drift.append(f"{subject_id}:{consumer}")
        rows.append({
            "subject_id": subject_id,
            "manager_family": row.get("manager_family", ""),
            "tool": row.get("tool", ""),
            "consumer": consumer,
            "tool_supported": bool(row.get("tool_supported")),
            "tool_processed": bool(row.get("tool_processed")),
            "pylockglyph_predicts_admission": locked,
            "agreement": row.get("agreement"),
            "classification": row.get("classification", ""),
            "root_cause": row.get("root_cause", ""),
            "returncode": row.get("returncode", ""),
            "output_sha256": row.get("output_sha256", ""),
        })
    if drift:
        findings.append({"severity": "P0", "check": "locked_prediction_drift", "detail": ";".join(sorted(set(drift))[:20])})

    unsupported_managers = {str(row.get("manager_family", "")) for row in unsupported}
    if not {"pdm", "uv"}.issubset(unsupported_managers):
        findings.append({
            "severity": "P2",
            "check": "unsupported_manager_boundary",
            "detail": ";".join(sorted(unsupported_managers)),
        })

    write_csv(rows_output, rows, [
        "subject_id",
        "manager_family",
        "tool",
        "consumer",
        "tool_supported",
        "tool_processed",
        "pylockglyph_predicts_admission",
        "agreement",
        "classification",
        "root_cause",
        "returncode",
        "output_sha256",
    ])

    classification_counts = Counter(str(row.get("classification", "")) for row in results)
    agreement_denominator = len(supported)
    agreement_numerator = sum(1 for row in supported if row.get("agreement") is True)
    summary: dict[str, object] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "lock_sha256": sha256_file(lock_path),
        "selected_subjects": len(subject_ids),
        "manager_families": len(managers),
        "tools": len(tools),
        "result_rows": len(results),
        "supported_run_attempts": len(supported),
        "processed_external_runs": len(processed),
        "unsupported_runs": len(unsupported),
        "disagreements": len(disagreements),
        "agreement_rate": round(agreement_numerator / agreement_denominator, 6) if agreement_denominator else None,
        "classification_counts": dict(sorted(classification_counts.items())),
        "prediction_drifts": len(drift),
        "findings": findings,
    }
    write_json(summary_output, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=ROOT / "spec" / "external_validation_lock.json")
    parser.add_argument("--rows-output", type=Path, default=ROOT / "evidence" / "external_validation_results.csv")
    parser.add_argument("--summary-output", type=Path, default=ROOT / "evidence" / "external_validation_summary.json")
    args = parser.parse_args()
    summary = audit_external_validation(ROOT, args.lock, args.rows_output, args.summary_output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
