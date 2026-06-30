#!/usr/bin/env python3
"""Create the frozen small-sample external-tool validation lock."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.corpus import load_subjects
from pylockglyph.io import sha256_file, write_json
from pylockglyph.model import MANAGERS, CorpusSubject
from pylockglyph.parsers import parse_all
from pylockglyph.study import DOWNSTREAM_CONSUMERS


def _tool(name: str, tool_bin: Path | None) -> str:
    candidates = []
    if tool_bin is not None:
        candidates.append(str(tool_bin / name))
    found = shutil.which(name)
    if found:
        candidates.append(found)
    for candidate in candidates:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(name)


def _version(command: str) -> str:
    try:
        result = subprocess.run(
            [command, "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return f"unavailable:{type(exc).__name__}"
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0] if text else f"returncode:{result.returncode}"


def _sample(subjects: tuple[CorpusSubject, ...], per_manager: int) -> tuple[CorpusSubject, ...]:
    by_manager: dict[str, list[CorpusSubject]] = defaultdict(list)
    for subject in subjects:
        by_manager[subject.manager_family].append(subject)
    selected: list[CorpusSubject] = []
    for manager in MANAGERS:
        selected.extend(by_manager[manager][:per_manager])
    return tuple(selected)


def _predict(root: Path, subjects: tuple[CorpusSubject, ...]) -> dict[tuple[str, str], bool]:
    parsed = parse_all(root, subjects)
    predictions: dict[tuple[str, str], bool] = {}
    for item in parsed:
        support = item.evidence.support()
        for consumer, required in DOWNSTREAM_CONSUMERS.items():
            predictions[(item.subject.subject_id, consumer)] = (
                item.parser_status == "parsed" and bool(item.packages) and required.issubset(support)
            )
    return predictions


def _run(command: list[str], cwd: Path | None, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr = (stderr + f"\ntimeout after {timeout} seconds").strip()
        return subprocess.CompletedProcess(command, 124, stdout, stderr)


def _json_output(path: Path) -> tuple[bool, str]:
    if not path.is_file() or path.stat().st_size == 0:
        return False, ""
    try:
        json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return False, sha256_file(path)
    return True, sha256_file(path)


def _record_unsupported(subject: CorpusSubject, tool_name: str, consumer: str, prediction: bool) -> dict[str, object]:
    return {
        "subject_id": subject.subject_id,
        "manager_family": subject.manager_family,
        "tool": tool_name,
        "consumer": consumer,
        "tool_supported": False,
        "tool_processed": False,
        "pylockglyph_predicts_admission": prediction,
        "agreement": None,
        "returncode": "",
        "output_sha256": "",
        "stderr_tail": "",
        "classification": "unsupported_manager_format",
        "root_cause": f"{tool_name} does not expose a parser for {subject.manager_family} lockfiles in this validation harness",
    }


def _record_result(
    subject: CorpusSubject,
    tool_name: str,
    consumer: str,
    prediction: bool,
    completed: subprocess.CompletedProcess[str],
    output: Path,
    ok_returncodes: set[int],
) -> dict[str, object]:
    json_ok, digest = _json_output(output)
    processed = completed.returncode in ok_returncodes and json_ok
    if processed and prediction:
        classification = "tool_processed_predicted_admissible_pair"
        root_cause = "external tool produced parseable JSON for a pair whose consumer obligations are present"
    elif processed and not prediction:
        classification = "external_tool_more_permissive_than_obligation_proxy"
        root_cause = "external tool emitted output even though the formal consumer obligation set is incomplete"
    elif (not processed) and prediction:
        classification = "external_tool_parse_or_environment_failure"
        root_cause = "the formal obligations are present, but the external command did not produce parseable JSON"
    else:
        classification = "tool_rejected_predicted_inadmissible_pair"
        root_cause = "external command failed to process a pair whose formal consumer obligations are incomplete"
    return {
        "subject_id": subject.subject_id,
        "manager_family": subject.manager_family,
        "tool": tool_name,
        "consumer": consumer,
        "tool_supported": True,
        "tool_processed": processed,
        "pylockglyph_predicts_admission": prediction,
        "agreement": processed == prediction,
        "returncode": completed.returncode,
        "output_sha256": digest,
        "stderr_tail": completed.stderr[-500:],
        "classification": classification,
        "root_cause": root_cause,
    }


def build_lock(root: Path, output: Path, tool_bin: Path | None, per_manager: int, timeout: int) -> dict[str, Any]:
    subjects = _sample(load_subjects(root), per_manager)
    predictions = _predict(root, subjects)
    cyclonedx = _tool("cyclonedx-py", tool_bin)
    pip_audit = _tool("pip-audit", tool_bin)
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="pylockglyph-ext-") as temp_name:
        temp = Path(temp_name)
        for subject in subjects:
            directory = subject.directory(root)
            cdx_prediction = predictions[(subject.subject_id, "sbom_inventory")]
            cdx_output = temp / f"{subject.subject_id}.cdx.json"
            if subject.manager_family == "pip-tools":
                command = [
                    cyclonedx,
                    "requirements",
                    str(directory / subject.lockfile_path),
                    "--output-reproducible",
                    "--of",
                    "JSON",
                    "-o",
                    str(cdx_output),
                ]
                completed = _run(command, directory, timeout)
                results.append(_record_result(subject, "cyclonedx-py", "sbom_inventory", cdx_prediction, completed, cdx_output, {0}))
            elif subject.manager_family in {"poetry", "pipenv"}:
                subcommand = subject.manager_family
                command = [
                    cyclonedx,
                    subcommand,
                    str(directory),
                    "--output-reproducible",
                    "--of",
                    "JSON",
                    "-o",
                    str(cdx_output),
                ]
                completed = _run(command, directory, timeout)
                results.append(_record_result(subject, "cyclonedx-py", "sbom_inventory", cdx_prediction, completed, cdx_output, {0}))
            else:
                results.append(_record_unsupported(subject, "cyclonedx-py", "sbom_inventory", cdx_prediction))

            audit_prediction = predictions[(subject.subject_id, "vulnerability_matching")]
            audit_output = temp / f"{subject.subject_id}.pip-audit.json"
            if subject.manager_family == "pip-tools":
                command = [
                    pip_audit,
                    "-r",
                    str(directory / subject.lockfile_path),
                    "--progress-spinner",
                    "off",
                    "--format",
                    "json",
                    "--timeout",
                    str(timeout),
                    "-o",
                    str(audit_output),
                ]
                completed = _run(command, directory, timeout + 20)
                results.append(_record_result(subject, "pip-audit", "vulnerability_matching", audit_prediction, completed, audit_output, {0, 1}))
            else:
                results.append(_record_unsupported(subject, "pip-audit", "vulnerability_matching", audit_prediction))

    supported = [row for row in results if bool(row["tool_supported"])]
    processed = [row for row in supported if bool(row["tool_processed"])]
    agreements = [row for row in supported if row["agreement"] is True]
    lock: dict[str, Any] = {
        "schema_version": 1,
        "purpose": "small-sample external-tool sanity check for the formal evidence-obligation proxy",
        "tools": {
            "cyclonedx-py": _version(cyclonedx),
            "pip-audit": _version(pip_audit),
        },
        "selection": {
            "per_manager": per_manager,
            "manager_families": sorted({subject.manager_family for subject in subjects}),
        },
        "selected_subjects": [
            {
                "subject_id": subject.subject_id,
                "manager_family": subject.manager_family,
                "repository": subject.repository,
                "commit": subject.commit,
            }
            for subject in subjects
        ],
        "summary": {
            "selected_subjects": len(subjects),
            "manager_families": len({subject.manager_family for subject in subjects}),
            "tools": 2,
            "result_rows": len(results),
            "supported_run_attempts": len(supported),
            "processed_external_runs": len(processed),
            "unsupported_runs": len(results) - len(supported),
            "disagreements": sum(1 for row in supported if row["agreement"] is False),
            "agreement_rate": round(len(agreements) / len(supported), 6) if supported else None,
        },
        "results": results,
    }
    write_json(output, lock)
    return lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "spec" / "external_validation_lock.json")
    parser.add_argument("--tool-bin", type=Path, default=Path(os.environ["PYLOCKGLYPH_EXTERNAL_TOOL_BIN"]) if os.environ.get("PYLOCKGLYPH_EXTERNAL_TOOL_BIN") else None)
    parser.add_argument("--per-manager", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()
    lock = build_lock(ROOT, args.output, args.tool_bin, args.per_manager, args.timeout)
    print(json.dumps(lock["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
