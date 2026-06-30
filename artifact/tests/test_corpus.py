"""Corpus-level primary and differential parser checks."""
from __future__ import annotations

import unittest
from pathlib import Path

from pylockglyph.corpus import audit_capsule, load_subjects, manager_counts
from pylockglyph.parsers import parse_subject
from pylockglyph.secondary import parse_subject as parse_subject_secondary

ROOT = Path(__file__).resolve().parents[1]
SUBJECTS = load_subjects(ROOT)


class CorpusStructureTests(unittest.TestCase):
    def test_subject_count(self) -> None:
        self.assertEqual(len(SUBJECTS), 41)

    def test_manager_balance_recorded(self) -> None:
        self.assertEqual(
            manager_counts(SUBJECTS),
            {"pdm": 5, "pip-tools": 15, "pipenv": 5, "poetry": 10, "uv": 6},
        )

    def test_capsules_are_byte_complete(self) -> None:
        rows = audit_capsule(ROOT, SUBJECTS)
        self.assertEqual(len(rows), 41)
        self.assertTrue(all(row["status"] == "pass" for row in rows))


def _primary_test(subject):
    def test(self: unittest.TestCase) -> None:
        parsed = parse_subject(ROOT, subject)
        self.assertEqual(parsed.parser_status, "parsed")
        self.assertGreater(len(parsed.packages), 0)
        self.assertTrue(all(package.name and package.version for package in parsed.packages))
    return test


def _differential_test(subject):
    def test(self: unittest.TestCase) -> None:
        primary = parse_subject(ROOT, subject)
        secondary = parse_subject_secondary(ROOT, subject)
        primary_inventory = [(p.name, p.version) for p in primary.packages]
        secondary_inventory = [(p.name, p.version) for p in secondary.packages]
        self.assertEqual(primary_inventory, secondary_inventory)
        self.assertEqual(primary.evidence.as_dict(), secondary.evidence.as_dict())
    return test


class PrimaryParserSubjectTests(unittest.TestCase):
    """One independent test per public subject."""


class DifferentialParserSubjectTests(unittest.TestCase):
    """One independent triangulation test per public subject."""


for _subject in SUBJECTS:
    _safe = "".join(ch if ch.isalnum() else "_" for ch in _subject.subject_id)
    setattr(PrimaryParserSubjectTests, f"test_primary_{_safe}", _primary_test(_subject))
    setattr(DifferentialParserSubjectTests, f"test_differential_{_safe}", _differential_test(_subject))
