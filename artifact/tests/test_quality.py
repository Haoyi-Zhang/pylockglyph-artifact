"""Submission quality-gate tests."""
from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from pylockglyph.quality import audit_baseline_contract, audit_benchmark_scope_contract, audit_corpus_diversity, audit_overfitting_sentinel
from pylockglyph.toml_writer import dumps

ROOT = Path(__file__).resolve().parents[1]


class QualityGateTests(unittest.TestCase):
    def test_baseline_contract_is_explicit_and_nontrivial(self) -> None:
        summary = audit_baseline_contract(ROOT)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["projections"], 10)
        self.assertEqual(summary["downstream_consumers"], 4)
        self.assertGreater(summary["baseline_over_admissions"], 0)
        self.assertGreater(summary["baseline_under_admissions"], 0)

    def test_corpus_diversity_contract_is_bounded(self) -> None:
        summary = audit_corpus_diversity(ROOT)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["subjects"], 41)
        self.assertEqual(summary["excluded_rows"], 16)
        self.assertLessEqual(summary["max_manager_share"], 0.40)
        self.assertLessEqual(summary["hhi"], 0.30)

    def test_overfitting_sentinel_has_no_subject_specific_method_hits(self) -> None:
        summary = audit_overfitting_sentinel(ROOT)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["subject_specific_literal_hits"], [])
        self.assertEqual(summary["subject_specific_branch_hits"], [])
        self.assertGreaterEqual(summary["controlled_suite_count"], 6)

    def test_benchmark_scope_contract_bounds_proxy_and_sample_claims(self) -> None:
        summary = audit_benchmark_scope_contract(ROOT)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["consumer_contract"], "formal evidence-obligation proxy")
        self.assertFalse(summary["external_tool_execution_claim"])
        self.assertIn("comprehensive_ecosystem_coverage", summary["not_claims"])
        self.assertEqual(summary["benchmark_role"], "construct_validation")

    def test_consumer_baseline_named_rows_are_locked(self) -> None:
        import csv
        with (ROOT / "evidence" / "consumer_baseline_summary.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(sum(int(row["baseline_over_admits"]) for row in rows), 682)
        self.assertEqual(sum(int(row["baseline_under_admits"]) for row in rows), 10)
        by_key = {(row["consumer"], row["projection"]): row for row in rows}
        self.assertEqual(by_key[("sbom_inventory", "parser")]["baseline_over_admits"], "28")
        self.assertEqual(by_key[("vulnerability_matching", "vulnerability_graph")]["baseline_over_admits"], "0")
        self.assertEqual(by_key[("vulnerability_matching", "vulnerability_graph")]["baseline_under_admits"], "0")

    def test_quality_gates_write_json_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "baseline.json"
            audit_baseline_contract(ROOT, target)
            self.assertIn('"status": "pass"', target.read_text(encoding="utf-8"))


class TomlWriterTests(unittest.TestCase):
    def test_nested_tables_arrays_and_quoted_keys(self) -> None:
        text = dumps({
            "project": {"name": "demo", "dependencies": ["a>=1", "b"]},
            "tool": {"py.lock": {"flag": True, "date": date(2024, 1, 2)}},
            "package": [{"name": "a", "version": "1.0"}, {"name": "b", "version": "2.0"}],
        })
        self.assertIn("[project]", text)
        self.assertIn('"py.lock"', text)
        self.assertIn("[[package]]", text)
        self.assertIn("date = 2024-01-02", text)

    def test_escaping_and_type_rejection(self) -> None:
        self.assertIn('text = "a\\\\\\\\b\\"c\\\\n"', dumps({"text": 'a\\\\b"c\\n'}))
        with self.assertRaises(TypeError):
            dumps({"unsupported": object()})
