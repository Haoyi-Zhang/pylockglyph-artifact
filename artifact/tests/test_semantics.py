"""Admission algebra and profile semantics."""
from __future__ import annotations

import unittest
from pathlib import Path

from pylockglyph.certificate import PROFILES, decide, decide_vector
from pylockglyph.corpus import load_subjects
from pylockglyph.model import EVIDENCE_TYPES, EvidenceType, EvidenceVector
from pylockglyph.parsers import parse_all
from pylockglyph.projections import PROJECTIONS
from pylockglyph.theory import exhaustive_replay, separation_witnesses, vector

ROOT = Path(__file__).resolve().parents[1]
PARSED = parse_all(ROOT, load_subjects(ROOT))


class AdmissionSemanticsTests(unittest.TestCase):
    def test_eight_typed_obligations(self) -> None:
        self.assertEqual(len(EVIDENCE_TYPES), 8)
        self.assertEqual(set(EVIDENCE_TYPES), set(EvidenceType))

    def test_graph_profile_strictly_refines_inventory(self) -> None:
        self.assertLess(PROFILES["inventory"], PROFILES["dependency_graph"])
        self.assertEqual(
            PROFILES["dependency_graph"] - PROFILES["inventory"],
            {EvidenceType.DEPENDENCY_EDGE},
        )

    def test_full_vector_is_admitted_by_both_profiles(self) -> None:
        full = EvidenceVector({item: True for item in EVIDENCE_TYPES})
        self.assertTrue(decide_vector("full", "parsed", full, "inventory").eligible)
        self.assertTrue(decide_vector("full", "parsed", full, "dependency_graph").eligible)

    def test_parser_error_is_fail_closed(self) -> None:
        full = EvidenceVector({item: True for item in EVIDENCE_TYPES})
        self.assertFalse(decide_vector("error", "error", full, "inventory").eligible)

    def test_every_inventory_obligation_is_non_substitutable(self) -> None:
        for missing in PROFILES["inventory"]:
            values = {item: item in PROFILES["inventory"] for item in EVIDENCE_TYPES}
            values[missing] = False
            decision = decide_vector("missing", "parsed", EvidenceVector(values), "inventory")
            self.assertFalse(decision.eligible, missing.value)
            self.assertIn(missing, decision.missing)

    def test_every_graph_obligation_is_non_substitutable(self) -> None:
        for missing in PROFILES["dependency_graph"]:
            values = {item: True for item in EVIDENCE_TYPES}
            values[missing] = False
            decision = decide_vector("missing", "parsed", EvidenceVector(values), "dependency_graph")
            self.assertFalse(decision.eligible, missing.value)
            self.assertIn(missing, decision.missing)

    def test_exhaustive_truth_table(self) -> None:
        rows, summary = exhaustive_replay()
        self.assertEqual(len(rows), 2560)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["definition_failures"], 0)

    def test_profile_refinement_for_all_vectors(self) -> None:
        for mask in range(1 << len(EVIDENCE_TYPES)):
            evidence = vector(mask)
            graph = decide_vector("g", "parsed", evidence, "dependency_graph")
            inventory = decide_vector("i", "parsed", evidence, "inventory")
            self.assertFalse(graph.eligible and not inventory.eligible)

    def test_constructive_projection_separation(self) -> None:
        rows = separation_witnesses()
        self.assertEqual(len(rows), 100)
        self.assertTrue(all(row["status"] == "pass" for row in rows))
        self.assertEqual({row["projection"] for row in rows}, set(PROJECTIONS))

    def test_observed_profile_counts(self) -> None:
        inventory = sum(decide(item, "inventory").eligible for item in PARSED)
        graph = sum(decide(item, "dependency_graph").eligible for item in PARSED)
        self.assertEqual((inventory, graph), (13, 8))

    def test_graph_admission_implies_inventory_admission_in_corpus(self) -> None:
        for parsed in PARSED:
            if decide(parsed, "dependency_graph").eligible:
                self.assertTrue(decide(parsed, "inventory").eligible)

    def test_package_record_count(self) -> None:
        self.assertEqual(sum(len(item.packages) for item in PARSED), 2050)

    def test_explicit_source_is_not_inferred_from_format(self) -> None:
        missing = [item for item in PARSED if not item.evidence.has(EvidenceType.SOURCE)]
        self.assertEqual(len(missing), 28)
        self.assertTrue(any(item.subject.manager_family == "poetry" for item in missing))
        self.assertTrue(any(item.subject.manager_family == "pip-tools" for item in missing))

    def test_integrity_requires_package_coverage(self) -> None:
        missing = [item for item in PARSED if not item.evidence.has(EvidenceType.INTEGRITY)]
        self.assertEqual(len(missing), 16)

    def test_pipenv_edges_are_not_invented(self) -> None:
        pipenv = [item for item in PARSED if item.subject.manager_family == "pipenv"]
        self.assertEqual(len(pipenv), 5)
        self.assertTrue(all(not item.evidence.has(EvidenceType.DEPENDENCY_EDGE) for item in pipenv))
