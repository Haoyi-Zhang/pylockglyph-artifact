"""Integrated evidence-materialization contracts."""
from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path

from pylockglyph.study import run_study

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"


def _ensure_evidence(name: str) -> None:
    if not (EVIDENCE / name).is_file():
        run_study(ROOT, EVIDENCE)


def _rows(name: str) -> list[dict[str, str]]:
    _ensure_evidence(name)
    with (EVIDENCE / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class StudyContractTests(unittest.TestCase):
    def test_study_summary(self) -> None:
        _ensure_evidence("study_summary.json")
        summary = json.loads((EVIDENCE / "study_summary.json").read_text())
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["subjects"], 41)
        self.assertEqual(summary["package_records"], 2050)
        self.assertEqual(summary["profiles"], {"inventory": 13, "dependency_graph": 8})
        self.assertEqual(summary["projection_decisions"], 820)
        self.assertGreater(summary["projection_over_admissions"], 265)
        self.assertEqual(summary["downstream_consumers"], 4)
        self.assertEqual(summary["consumer_baseline_decisions"], 1640)
        self.assertGreater(summary["consumer_baseline_over_admissions"], 0)
        self.assertEqual(summary["controlled_cases"], 971)

    def test_file_removal_suite(self) -> None:
        rows = _rows("file_removals.csv")
        self.assertEqual(len(rows), 155)
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_adversarial_suite(self) -> None:
        rows = _rows("adversarial_vectors.csv")
        self.assertEqual(len(rows), 176)
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_mutation_suite(self) -> None:
        rows = _rows("executable_mutations.csv")
        self.assertEqual(len(rows), 239)
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_metamorphic_suite(self) -> None:
        rows = _rows("metamorphic_cases.csv")
        self.assertEqual(len(rows), 319)
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_formatting_suite(self) -> None:
        rows = _rows("formatting_cases.csv")
        self.assertEqual(len(rows), 41)
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    def test_parser_agreement_suite(self) -> None:
        rows = _rows("independent_parser_audit.csv")
        self.assertEqual(len(rows), 41)
        self.assertTrue(all(row["status"] == "pass" for row in rows))
