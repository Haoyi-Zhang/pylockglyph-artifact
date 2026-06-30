#!/usr/bin/env python3
"""Summarize expected-reject controls and preservation controls."""
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

from pylockglyph.io import write_json
from pylockglyph.model import EVIDENCE_TYPES


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _attack_obligation(value: str) -> str:
    if value.startswith("remove:"):
        return value.split(":", 1)[1].split("+", 1)[0]
    if value.startswith("remove_"):
        return value.split("remove_", 1)[1]
    return ""


def summarize_negative_controls(root: Path, output: Path) -> dict[str, object]:
    evidence_root = root / "evidence"
    file_rows = _rows(evidence_root / "file_removals.csv")
    adversarial_rows = _rows(evidence_root / "adversarial_vectors.csv")
    mutation_rows = _rows(evidence_root / "executable_mutations.csv")
    metamorphic_rows = _rows(evidence_root / "metamorphic_cases.csv")
    formatting_rows = _rows(evidence_root / "formatting_cases.csv")
    parser_rows = _rows(evidence_root / "independent_parser_audit.csv")

    findings: list[dict[str, str]] = []
    expected = {item.value for item in EVIDENCE_TYPES}
    covered: set[str] = set()
    file_false_accepts: list[str] = []
    diagnostic_rows = 0
    for row in file_rows:
        removed = str(row.get("removed_type", ""))
        if removed:
            covered.add(removed)
        if _truth(row.get("observed_eligible")):
            file_false_accepts.append(str(row.get("case_id", "")))
        if str(row.get("observed_missing", "")).strip():
            diagnostic_rows += 1

    adversarial_false_accepts: list[str] = []
    adversarial_counter: Counter[str] = Counter()
    for row in adversarial_rows:
        obligation = _attack_obligation(str(row.get("attack", "")))
        if obligation:
            covered.add(obligation)
            adversarial_counter[obligation] += 1
        if _truth(row.get("observed_eligible")) or row.get("status") != "pass":
            adversarial_false_accepts.append(str(row.get("case_id", "")))

    mutation_counter: Counter[str] = Counter()
    mutation_failures = []
    for row in mutation_rows:
        family = str(row.get("family", ""))
        mutation_counter[family] += 1
        obligation = _attack_obligation(family)
        if obligation:
            covered.add(obligation)
        if row.get("status") != "pass":
            mutation_failures.append(str(row.get("case_id", "")))

    weakening_rows = [row for row in metamorphic_rows if str(row.get("relation", "")).startswith("weaken_")]
    preservation_rows = [row for row in metamorphic_rows if str(row.get("relation", "")).startswith("preserve_")]
    preservation_failures = [
        str(row.get("case_id", ""))
        for row in preservation_rows + formatting_rows + parser_rows
        if row.get("status") != "pass"
    ]
    weakening_failures = [str(row.get("case_id", "")) for row in weakening_rows if row.get("status") != "pass"]

    missing_obligations = sorted(expected - covered)
    false_accepts = file_false_accepts + adversarial_false_accepts + mutation_failures + weakening_failures
    if missing_obligations:
        findings.append({
            "severity": "P1",
            "check": "obligation_coverage",
            "detail": ";".join(missing_obligations),
        })
    if false_accepts:
        findings.append({
            "severity": "P1",
            "check": "expected_reject_false_accept",
            "detail": ";".join(false_accepts[:20]),
        })
    if diagnostic_rows < len(file_rows):
        findings.append({
            "severity": "P2",
            "check": "reject_diagnostics",
            "detail": f"{diagnostic_rows}/{len(file_rows)} file-removal rows include missing-obligation diagnostics",
        })
    if preservation_failures:
        findings.append({
            "severity": "P1",
            "check": "preservation_controls",
            "detail": ";".join(preservation_failures[:20]),
        })

    summary: dict[str, object] = {
        "status": "pass" if not any(item["severity"] in {"P0", "P1"} for item in findings) else "fail",
        "expected_reject_cases": len(file_rows) + len(adversarial_rows) + len(mutation_rows) + len(weakening_rows),
        "false_accepts": len(false_accepts),
        "file_removal_cases": len(file_rows),
        "file_removal_diagnostic_rows": diagnostic_rows,
        "adversarial_cases": len(adversarial_rows),
        "mutation_cases": len(mutation_rows),
        "metamorphic_weaken_cases": len(weakening_rows),
        "preservation_cases": len(preservation_rows) + len(formatting_rows) + len(parser_rows),
        "obligations_covered": sorted(covered),
        "obligation_count": len(expected),
        "adversarial_by_obligation": dict(sorted(adversarial_counter.items())),
        "mutation_families": dict(sorted(mutation_counter.items())),
        "findings": findings,
    }
    write_json(output, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "negative_control_summary.json")
    args = parser.parse_args()
    summary = summarize_negative_controls(ROOT, args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
