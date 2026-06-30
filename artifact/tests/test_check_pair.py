"""One-pair command contract for external evaluator use."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CheckPairCommandTests(unittest.TestCase):
    def test_existing_uv_pair_can_be_checked_without_ledger_mutation(self) -> None:
        subject = ROOT / "data" / "corpus" / "subjects" / "uv_astral_sh_uv_3cdf50e"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tool" / "check_pair.py"),
                "--manager",
                "uv",
                "--manifest",
                str(subject / "pyproject.toml"),
                "--lockfile",
                str(subject / "uv.lock"),
                "--subject-id",
                "uv_cli_contract",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["subject_id"], "uv_cli_contract")
        self.assertGreater(payload["package_records"], 0)
        self.assertIn("inventory", payload["decisions"])
        self.assertIn("dependency_graph", payload["decisions"])
