"""Reviewer-facing command surface contracts."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pylockglyph.surface import audit_command_surface

ROOT = Path(__file__).resolve().parents[1]


class CommandSurfaceTests(unittest.TestCase):
    def test_all_public_tools_show_help_without_pythonpath(self) -> None:
        summary = audit_command_surface(ROOT)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["tools"], len(list((ROOT / "tool").glob("*.py"))))
        self.assertGreaterEqual(summary["tools"], 8)
        self.assertFalse(summary["failures"])

    def test_failed_help_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool_dir = root / "tool"
            tool_dir.mkdir(parents=True)
            script = tool_dir / "bad.py"
            script.write_text('import sys\nraise SystemExit(3)\n', encoding="utf-8")
            summary = audit_command_surface(root)
            self.assertEqual(summary["status"], "fail")
            self.assertEqual(summary["failures"], ["bad.py"])
