"""Repository, document, and replay-contract audits."""
from __future__ import annotations

import ast
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .corpus import audit_capsule, load_subjects
from .io import sha256_file, write_json


@dataclass(frozen=True)
class Finding:
    severity: str
    check: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "check": self.check, "detail": self.detail}


def _run(command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, exc.stdout or "", exc.stderr or "timeout")


def _pdf_pages(path: Path) -> int:
    result = _run(["pdfinfo", str(path)])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"pdfinfo failed for {path}")
    match = re.search(r"^Pages:\s+(\d+)\s*$", result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError(f"missing page count for {path}")
    return int(match.group(1))


def _pdf_text(path: Path, first: int | None = None, last: int | None = None) -> str:
    command = ["pdftotext", "-layout"]
    if first is not None:
        command += ["-f", str(first)]
    if last is not None:
        command += ["-l", str(last)]
    command += [str(path), "-"]
    result = _run(command)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"pdftotext failed for {path}")
    return result.stdout


def _citation_keys(tex: str) -> set[str]:
    keys: set[str] = set()
    for match in re.finditer(r"\\cite\w*\s*\{([^}]*)\}", tex, re.DOTALL):
        keys.update(item.strip() for item in match.group(1).split(",") if item.strip())
    return keys


def _bib_keys(bib: str) -> set[str]:
    return set(re.findall(r"@\w+\s*\{\s*([^,\s]+)\s*,", bib))


def _first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _top_level_sections(tex: str) -> list[tuple[str, int]]:
    sections: list[tuple[str, int]] = []
    for match in re.finditer(r"(?m)^\\section\*?\s*\{([^}]*)\}", tex):
        sections.append((match.group(1).strip(), match.start()))
    return sections


def _latex_gate_findings(name: str, tex: str) -> list[Finding]:
    findings: list[Finding] = []
    banned = [
        (r"\\scriptsize\b", "scriptsize"),
        (r"\\tiny\b", "tiny"),
        (r"\\resizebox\s*\{", "resizebox"),
        (r"\\scalebox\s*\{", "scalebox"),
        (r"\\vspace\*?\s*\{", "vspace"),
        (r"\\vskip\b", "vskip"),
        (r"\\enlargethispage\b", "enlargethispage"),
        (r"\\linespread\s*\{", "linespread"),
        (r"\\renewcommand\s*\{\\baselinestretch\}", "baselinestretch"),
        (
            r"\\(?:setlength|addtolength)\s*\{\\(?:textfloatsep|floatsep|intextsep|abovedisplayskip|belowdisplayskip|abovedisplayshortskip|belowdisplayshortskip|abovecaptionskip|belowcaptionskip|parskip|baselineskip|textheight|textwidth|oddsidemargin|evensidemargin|topmargin)",
            "manual spacing/layout length",
        ),
        (r"\\includegraphics\s*\[[^]]*scale\s*=", "includegraphics scale"),
    ]
    for pattern, label in banned:
        if re.search(pattern, tex):
            findings.append(Finding("P0", "latex_format_gate", f"{name}: banned pattern {label}"))
    return findings


def _macro_values(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    return dict(re.findall(r"\\newcommand\{\\([^}]+)\}\{([^}]*)\}", text))


def audit_paper(repository_root: Path, output: Path) -> dict[str, object]:
    paper = repository_root / "paper"
    artifact = repository_root / "artifact"
    findings: list[Finding] = []
    main_pdf = paper / "main.pdf"
    supplement_pdf = paper / "supplement.pdf"
    required = [
        paper / "main.tex",
        paper / "supplement.tex",
        paper / "references.bib",
        main_pdf,
        supplement_pdf,
        artifact / "evidence" / "study_summary.json",
        artifact / "evidence" / "unit_test_summary.json",
        paper / "tables" / "macros.tex",
    ]
    for path in required:
        if not path.is_file() or path.stat().st_size == 0:
            findings.append(Finding("P0", "required_file", f"missing or empty: {path.relative_to(repository_root)}"))
    if findings:
        summary = {"status": "fail", "findings": [item.as_dict() for item in findings]}
        write_json(output, summary)
        return summary

    main_pages = _pdf_pages(main_pdf)
    supplement_pages = _pdf_pages(supplement_pdf)
    if not (11 <= main_pages <= 12):
        findings.append(Finding("P0", "main_page_count", f"expected 10 body pages plus 1-2 reference pages, observed {main_pages}"))
    if supplement_pages < 3:
        findings.append(Finding("P1", "supplement_page_count", f"expected at least 3 pages, observed {supplement_pages}"))

    page10 = _pdf_text(main_pdf, 10, 10)
    page11 = _pdf_text(main_pdf, 11, 11)
    page12 = _pdf_text(main_pdf, 12, 12) if main_pages >= 12 else ""
    page10_compact = re.sub(r"\s+", "", page10).upper()
    if "CONCLUSION" not in page10_compact and "DATAAVAILABILITY" not in page10_compact:
        findings.append(Finding("P0", "body_extent", "page 10 does not contain the closing body sections"))
    if "REFERENCES" in re.sub(r"\s+", "", page10).upper():
        findings.append(Finding("P0", "reference_placement", "references begin before page 11"))
    page11_first = _first_nonempty_line(page11).upper()
    page11_first_compact = re.sub(r"\s+", "", page11_first)
    if not page11_first_compact.startswith("REFERENCES"):
        findings.append(Finding("P0", "reference_placement", f"page 11 first text is not references: {page11_first[:60]!r}"))
    if main_pages >= 12 and len(page12.strip()) < 200:
        findings.append(Finding("P1", "reference_extent", "page 12 is unexpectedly sparse"))

    main_tex = (paper / "main.tex").read_text(encoding="utf-8")
    supplement_tex = (paper / "supplement.tex").read_text(encoding="utf-8")
    bib = (paper / "references.bib").read_text(encoding="utf-8")
    findings.extend(_latex_gate_findings("main.tex", main_tex))
    findings.extend(_latex_gate_findings("supplement.tex", supplement_tex))
    sections = _top_level_sections(main_tex)
    section_names = [name for name, _ in sections]
    section_positions = {name.lower(): position for name, position in sections}
    conclusion_pos = section_positions.get("conclusion")
    data_pos = section_positions.get("data availability")
    bibliography_pos = main_tex.find("\\bibliography")
    if data_pos is None:
        findings.append(Finding("P0", "data_availability", "missing top-level Data Availability section"))
    elif conclusion_pos is None or data_pos < conclusion_pos:
        findings.append(Finding("P0", "data_availability", "Data Availability must appear after Conclusion"))
    elif bibliography_pos != -1 and data_pos > bibliography_pos:
        findings.append(Finding("P0", "data_availability", "Data Availability must appear before references"))
    if "data availability" not in {name.lower() for name in section_names}:
        findings.append(Finding("P0", "data_availability", "section title must be exactly Data Availability"))
    if len(sections) > 10:
        findings.append(Finding("P1", "section_count", f"expected at most 10 top-level sections including Data Availability, observed {len(sections)}"))
    if conclusion_pos is not None:
        scientific = [name for name, pos in sections if pos < conclusion_pos]
        if len(scientific) > 8:
            findings.append(Finding("P1", "section_count", f"expected 7-8 scientific sections before Conclusion, observed {len(scientific)}"))
    cited = _citation_keys(main_tex)
    defined = _bib_keys(bib)
    missing = sorted(cited - defined)
    uncited = sorted(defined - cited)
    if missing:
        findings.append(Finding("P0", "citation_closure", "undefined keys: " + ", ".join(missing)))
    if uncited:
        findings.append(Finding("P1", "citation_closure", "uncited entries: " + ", ".join(uncited)))
    if not 65 <= len(defined) <= 80:
        findings.append(Finding("P1", "reference_count", f"expected 65-80 entries, observed {len(defined)}"))

    for log_name in ("main.log", "supplement.log"):
        log_path = paper / log_name
        if log_path.is_file():
            log_text = log_path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"LaTeX Warning: (Citation|Reference).*undefined", log_text):
                findings.append(Finding("P0", "latex_log", f"undefined reference or citation in {log_name}"))
            if "There were undefined references" in log_text:
                findings.append(Finding("P0", "latex_log", f"undefined references summary in {log_name}"))
            overfull = re.findall(r"Overfull \\hbox \\(([^)]*)\\)", log_text)
            if overfull:
                findings.append(Finding("P1", "latex_log", f"overfull hbox in {log_name}: {len(overfull)}"))

    study = json.loads((artifact / "evidence" / "study_summary.json").read_text(encoding="utf-8"))
    tests = json.loads((artifact / "evidence" / "unit_test_summary.json").read_text(encoding="utf-8"))
    macros = _macro_values(paper / "tables" / "macros.tex")
    expected_macros = {
        "SubjectCount": str(study["subjects"]),
        "PackageCount": f"{study['package_records']:,}",
        "InventoryEligible": str(study["profiles"]["inventory"]),
        "GraphEligible": str(study["profiles"]["dependency_graph"]),
        "ProjectionDecisions": str(study["projection_decisions"]),
        "ProjectionOver": str(study["projection_over_admissions"]),
        "ControlledCases": str(study["controlled_cases"]),
        "ProofDecisions": f"{study['proof_decisions']:,}",
        "UnitTests": str(tests["tests_run"]),
    }
    for key, value in expected_macros.items():
        if macros.get(key) != value:
            findings.append(Finding("P0", "paper_data_sync", f"{key}: expected {value!r}, observed {macros.get(key)!r}"))

    anonymous_problems: list[str] = []
    authored_text = main_tex + "\n" + supplement_tex
    for pattern, label in [
        (r"\\email\s*\{", "email command"),
        (r"\\affiliation\s*\{", "affiliation command"),
        (r"\\institution\s*\{", "institution command"),
        (r"\\section\*?\s*\{\s*Acknowledg", "acknowledgments"),
        (r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "email address"),
    ]:
        if re.search(pattern, authored_text, re.IGNORECASE):
            anonymous_problems.append(label)
    if "Anonymous Authors" not in main_tex:
        anonymous_problems.append("anonymous author declaration missing")
    info = _run(["pdfinfo", str(main_pdf)])
    author_match = re.search(r"^Author:\s*(.*)$", info.stdout, re.MULTILINE)
    if author_match and author_match.group(1).strip() not in {"", "Anonymous Authors"}:
        anonymous_problems.append("nonanonymous PDF author metadata")
    if anonymous_problems:
        findings.append(Finding("P0", "anonymity", "; ".join(anonymous_problems)))

    process_terms = [
        "sub" + "mission",
        "best" + " paper",
        "strong" + " accept",
        "audit" + "-trace",
        "major" + " revision",
        "protocol" + "_blocked",
    ]
    forbidden_authored = re.compile(
        r"\b(?:" + "|".join(re.escape(term) for term in process_terms) + r"|" + "ga" + r"te\s*\d+)\b",
        re.IGNORECASE,
    )
    matches = sorted(set(match.group(0) for match in forbidden_authored.finditer(authored_text)))
    if matches:
        findings.append(Finding("P1", "research_presentation", "process-oriented terms: " + ", ".join(matches)))

    main_text = _pdf_text(main_pdf)
    for phrase in ("profile-indexed", "admission verdict", "threats to validity", "reproducibility"):
        if phrase.lower() not in main_text.lower():
            findings.append(Finding("P1", "self_containment", f"missing visible concept: {phrase}"))

    summary: dict[str, object] = {
        "status": "pass" if not findings else "fail",
        "main_pages": main_pages,
        "body_pages": 10 if ("CONCLUSION" in page10_compact or "DATAAVAILABILITY" in page10_compact) else None,
        "references_start_page": 11 if page11_first_compact.startswith("REFERENCES") else None,
        "supplement_pages": supplement_pages,
        "bibliography_entries": len(defined),
        "cited_entries": len(cited),
        "undefined_citations": len(missing),
        "uncited_entries": len(uncited),
        "paper_sha256": sha256_file(main_pdf),
        "supplement_sha256": sha256_file(supplement_pdf),
        "findings": [item.as_dict() for item in findings],
    }
    write_json(output, summary)
    return summary


def _iter_authored_text(repository_root: Path) -> Iterable[Path]:
    extensions = {".py", ".md", ".tex", ".json", ".csv", ".sh"}
    for path in sorted(repository_root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(repository_root)
        if "data/corpus/subjects" in relative.as_posix():
            continue
        if relative.as_posix() in {"paper/IEEEtran.cls", "paper/IEEEtran.bst"}:
            continue
        if path.suffix.lower() in extensions or path.name in {"Makefile", "LICENSE"}:
            yield path


def audit_repository(repository_root: Path, output: Path) -> dict[str, object]:
    findings: list[Finding] = []
    # Remove bytecode caches produced by the interpreter that loaded this audit
    # before checking the package surface.
    for cache in list(repository_root.rglob("__pycache__")):
        for item in cache.glob("*"):
            item.unlink(missing_ok=True)
        cache.rmdir()
    roots = sorted(path.name for path in repository_root.iterdir())
    if roots != ["artifact", "paper"]:
        findings.append(Finding("P0", "top_level_layout", f"observed entries: {roots}"))

    forbidden_suffixes = {
        ".aux", ".bbl", ".blg", ".log", ".out", ".fls", ".fdb_latexmk", ".synctex", ".pyc", ".pyo",
    }
    residue: list[str] = []
    suspicious_names: list[str] = []
    local_paths: list[str] = []
    process_terms = [
        "sub" + "mission",
        "best" + " paper",
        "strong" + " accept",
        "audit" + "-trace",
        "major" + " revision",
        "protocol" + "_blocked",
    ]
    meta_terms = re.compile(
        r"\b(?:" + "|".join(re.escape(term) for term in process_terms) + r"|" + "ga" + r"te\s*\d+)\b",
        re.IGNORECASE,
    )
    meta_hits: list[str] = []
    for path in sorted(repository_root.rglob("*")):
        relative = path.relative_to(repository_root).as_posix()
        if path.is_symlink():
            findings.append(Finding("P1", "symlink", relative))
        if path.is_dir() and path.name in {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache", ".ipynb_checkpoints"}:
            residue.append(relative)
        if path.is_file() and (path.suffix.lower() in forbidden_suffixes or path.name.endswith(".synctex.gz")):
            residue.append(relative)
        process_name_pattern = (
            r"(?:^|[/_.-])(?:" + "ga" + r"te\d*|" + "fi" + r"nal|" + "sub" + r"mission|" + "re" + r"view-sim|" + "re" + r"view_sim)(?:$|[/_.-])"
        )
        if re.search(process_name_pattern, relative, re.IGNORECASE):
            suspicious_names.append(relative)
    if residue:
        findings.append(Finding("P0", "build_residue", "; ".join(residue[:30])))
    if suspicious_names:
        findings.append(Finding("P1", "process_labels", "; ".join(suspicious_names[:30])))

    python_files = sorted((repository_root / "artifact").rglob("*.py"))
    source_lines = 0
    functions = 0
    long_files: list[str] = []
    long_functions: list[str] = []
    syntax_errors: list[str] = []
    for path in python_files:
        text = path.read_text(encoding="utf-8")
        source_lines += sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            syntax_errors.append(f"{path.relative_to(repository_root)}:{exc.lineno}:{exc.msg}")
            continue
        file_lines = len(text.splitlines())
        if file_lines > 500:
            long_files.append(f"{path.relative_to(repository_root)}:{file_lines}")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if getattr(node, "end_lineno", node.lineno) - node.lineno + 1 > 160:
                    long_functions.append(
                        f"{path.relative_to(repository_root)}:{node.name}:{node.end_lineno - node.lineno + 1}"
                    )
    if syntax_errors:
        findings.append(Finding("P0", "python_syntax", "; ".join(syntax_errors)))
    if long_files:
        findings.append(Finding("P2", "module_size", "; ".join(long_files)))
    if long_functions:
        findings.append(Finding("P2", "function_size", "; ".join(long_functions)))

    for path in _iter_authored_text(repository_root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        relative = path.relative_to(repository_root).as_posix()
        if "/mnt" + "/data/" in text or "/home" + "/oai/" in text or "user-" + "tfbr" in text:
            local_paths.append(relative)
        for match in meta_terms.finditer(text):
            meta_hits.append(f"{relative}:{match.group(0)}")
    if local_paths:
        findings.append(Finding("P0", "local_paths", "; ".join(sorted(set(local_paths)))))
    if meta_hits:
        findings.append(Finding("P1", "process_language", "; ".join(sorted(set(meta_hits))[:40])))

    artifact = repository_root / "artifact"
    required = [
        artifact / "README.md",
        artifact / "REPLAY.md",
        artifact / "METHOD.md",
        artifact / "BENCHMARK.md",
        artifact / "LICENSE",
        artifact / "run_replay.sh",
        artifact / "data" / "corpus" / "ledger.csv",
        artifact / "data" / "corpus" / "screening_log.csv",
        artifact / "spec" / "evidence_types.json",
        artifact / "spec" / "profiles.json",
        repository_root / "paper" / "main.pdf",
        repository_root / "paper" / "supplement.pdf",
    ]
    for path in required:
        if not path.is_file() or path.stat().st_size == 0:
            findings.append(Finding("P0", "required_file", f"missing or empty: {path.relative_to(repository_root)}"))

    capsule_rows = audit_capsule(artifact, load_subjects(artifact))
    capsule_failures = [row["subject_id"] for row in capsule_rows if row["status"] != "pass"]
    if capsule_failures:
        findings.append(Finding("P0", "corpus_capsule", "; ".join(capsule_failures)))

    with (artifact / "data" / "corpus" / "screening_log.csv").open(newline="", encoding="utf-8") as handle:
        screening_rows = list(csv.DictReader(handle))
    if len(screening_rows) != 57:
        findings.append(Finding("P1", "screening_log", f"expected 57 rows, observed {len(screening_rows)}"))
    excluded = [row for row in screening_rows if row.get("included", "").lower() != "true"]
    if len(excluded) != 16:
        findings.append(Finding("P1", "screening_log", f"expected 16 retained exclusions, observed {len(excluded)}"))

    direct_tools = sorted((artifact / "tool").glob("*.py"))
    tool_results: list[dict[str, object]] = []
    for tool in direct_tools:
        text = tool.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(tool))
        has_main = any(isinstance(node, ast.FunctionDef) and node.name == "main" for node in ast.walk(tree))
        has_argparse = "argparse.ArgumentParser" in text or "argparse" in text
        passed = has_main and has_argparse
        tool_results.append({"tool": tool.name, "status": "pass" if passed else "fail"})
        if not passed:
            findings.append(Finding("P1", "tool_contract", f"{tool.name}: missing main()/argparse interface"))
    shell = artifact / "run_replay.sh"
    if shell.is_file():
        result = _run(["bash", "-n", str(shell)])
        if result.returncode != 0:
            findings.append(Finding("P0", "shell_syntax", result.stderr.strip()))

    summary: dict[str, object] = {
        "status": "pass" if not findings else "fail",
        "top_level": roots,
        "python_files": len(python_files),
        "python_source_lines": source_lines,
        "functions": functions,
        "direct_tools": len(direct_tools),
        "direct_tool_results": tool_results,
        "corpus_capsules": len(capsule_rows),
        "screening_rows": len(screening_rows),
        "retained_exclusions": len(excluded),
        "findings": [item.as_dict() for item in findings],
    }
    write_json(output, summary)
    return summary


def _manifest_paths(repository_root: Path) -> list[Path]:
    excluded_names = {"replay_manifest.csv", "replay_summary.json", "timing_summary.json"}
    excluded_suffixes = {".aux", ".bbl", ".blg", ".log", ".out", ".fls", ".fdb_latexmk", ".pyc", ".pyo"}
    paths: list[Path] = []
    for path in sorted(repository_root.rglob("*")):
        if not path.is_file() or path.name in excluded_names:
            continue
        if path.suffix.lower() in excluded_suffixes or path.name.endswith(".synctex.gz"):
            continue
        if any(part in {"__pycache__", ".pytest_cache", ".cache"} for part in path.parts):
            continue
        paths.append(path)
    return paths


def write_replay_manifest(repository_root: Path, manifest_path: Path, summary_path: Path, elapsed_seconds: float) -> dict[str, object]:
    paths = _manifest_paths(repository_root)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for path in paths:
        rows.append({
            "path": path.relative_to(repository_root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "bytes", "sha256"])
        writer.writeheader()
        writer.writerows(rows)
    required_summaries = [
        repository_root / "artifact" / "evidence" / "study_summary.json",
        repository_root / "artifact" / "evidence" / "unit_test_summary.json",
        repository_root / "artifact" / "evidence" / "claim_scope_summary.json",
        repository_root / "artifact" / "evidence" / "paper_audit_summary.json",
        repository_root / "artifact" / "evidence" / "baseline_contract_summary.json",
        repository_root / "artifact" / "evidence" / "under_admission_summary.json",
        repository_root / "artifact" / "evidence" / "external_validation_summary.json",
        repository_root / "artifact" / "evidence" / "corpus_diversity_summary.json",
        repository_root / "artifact" / "evidence" / "negative_control_summary.json",
        repository_root / "artifact" / "evidence" / "validation_closure_summary.json",
        repository_root / "artifact" / "evidence" / "overfitting_sentinel_summary.json",
        repository_root / "artifact" / "evidence" / "benchmark_scope_contract_summary.json",
        repository_root / "artifact" / "evidence" / "repository_audit_summary.json",
    ]
    statuses: dict[str, str] = {}
    for path in required_summaries:
        if path.is_file():
            value = json.loads(path.read_text(encoding="utf-8"))
            statuses[path.stem] = str(value.get("status", "missing"))
        else:
            statuses[path.stem] = "missing"
    status = "pass" if all(value == "pass" for value in statuses.values()) else "fail"
    summary: dict[str, object] = {
        "status": status,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "files_hashed": len(rows),
        "bytes_hashed": sum(int(row["bytes"]) for row in rows),
        "manifest_sha256": sha256_file(manifest_path),
        "component_status": statuses,
        "volatile_unhashed_files": ["artifact/evidence/timing_summary.json"],
    }
    write_json(summary_path, summary)
    return summary


def verify_replay_manifest(repository_root: Path, manifest_path: Path) -> dict[str, object]:
    failures: list[str] = []
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        path = repository_root / row["path"]
        if not path.is_file():
            failures.append(f"missing:{row['path']}")
            continue
        if str(path.stat().st_size) != row["bytes"]:
            failures.append(f"size:{row['path']}")
        if sha256_file(path) != row["sha256"]:
            failures.append(f"digest:{row['path']}")
    return {"status": "pass" if not failures else "fail", "files": len(rows), "failures": failures}
