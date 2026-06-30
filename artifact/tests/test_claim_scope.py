"""Claim-scope boundary checks."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from pylockglyph.scope import audit_claim_scope

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent


class ClaimScopeTests(unittest.TestCase):
    def test_current_paper_has_bounded_empirical_claims(self) -> None:
        summary = audit_claim_scope(REPOSITORY)
        self.assertEqual(summary["status"], "pass", summary.get("findings"))

    def test_unbounded_accuracy_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            shutil.copytree(REPOSITORY / "paper", target / "paper")
            tex = target / "paper" / "main.tex"
            text = tex.read_text(encoding="utf-8") + "\nThis method achieves accuracy across the Python ecosystem.\n"
            tex.write_text(text, encoding="utf-8")
            summary = audit_claim_scope(target)
            self.assertEqual(summary["status"], "fail")
            self.assertTrue(any(item["check"] == "unbounded_empirical_claim" for item in summary["findings"]))

    def test_process_trace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            shutil.copytree(REPOSITORY / "paper", target / "paper")
            tex = target / "paper" / "main.tex"
            tex.write_text(
                tex.read_text(encoding="utf-8") + "\nThe " + "strong" + " accept process liked it.\n",
                encoding="utf-8",
            )
            summary = audit_claim_scope(target)
            self.assertEqual(summary["status"], "fail")
            self.assertTrue(any(item["check"] == "process_or_ai_trace" for item in summary["findings"]))
