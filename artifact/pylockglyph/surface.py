"""Public command-surface checks for artifact commands."""
from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .io import write_json


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _check_tool(tool: Path, artifact_root: Path, env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(tool), "--help"],
        cwd=artifact_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    help_text = (result.stdout + result.stderr).lower()
    ok = result.returncode == 0 and "usage:" in help_text
    return {
        "tool": tool.name,
        "returncode": result.returncode,
        "stdout_bytes": len(result.stdout.encode("utf-8")),
        "stderr_bytes": len(result.stderr.encode("utf-8")),
        "status": "pass" if ok else "fail",
    }


def audit_command_surface(artifact_root: Path, output: Path | None = None) -> dict[str, object]:
    """Execute every public Python command with ``--help``.

    The check uses a clean environment without ``PYTHONPATH`` so commands can run
    directly from the unpacked archive. ``run_replay.sh`` is checked by repository
    syntax audit rather than executed here because it performs the complete workflow.
    """
    tools = sorted((artifact_root / "tool").glob("*.py"))
    env = _clean_env()
    if tools:
        with ThreadPoolExecutor(max_workers=min(len(tools), os.cpu_count() or 4)) as pool:
            rows = list(pool.map(lambda tool: _check_tool(tool, artifact_root, env), tools))
    else:
        rows = []
    failures = [str(row["tool"]) for row in rows if row["status"] != "pass"]
    summary: dict[str, object] = {
        "status": "pass" if not failures else "fail",
        "tools": len(tools),
        "failures": failures,
        "results": rows,
    }
    if output is not None:
        write_json(output, summary)
    return summary
