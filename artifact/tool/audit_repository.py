#!/usr/bin/env python3
"""Check repository layout and package hygiene."""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pylockglyph.surface import audit_command_surface

BAD_SUFFIXES = {'.aux', '.bbl', '.blg', '.log', '.out', '.fls', '.fdb_latexmk', '.pyc', '.pyo'}
BAD_DIRS = {'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache', '.ipynb_checkpoints'}
REQUIRED = [
    'artifact/README.md', 'artifact/REPLAY.md', 'artifact/METHOD.md', 'artifact/BENCHMARK.md',
    'artifact/LICENSE', 'artifact/run_replay.sh', 'artifact/data/corpus/README.md', 'artifact/data/corpus/ledger.csv',
    'artifact/data/corpus/screening_log.csv', 'artifact/spec/external_validation_lock.json', 'paper/main.tex', 'paper/main.pdf',
    'paper/supplement.tex', 'paper/supplement.pdf', 'paper/references.bib',
    'artifact/evidence/external_disagreement_analysis.md', 'artifact/evidence/negative_control_provenance.md',
    'artifact/evidence/known_limitations.md',
]


def _remove_residue() -> None:
    for cache in list(REPOSITORY.rglob('__pycache__')):
        for item in cache.glob('*'):
            item.unlink(missing_ok=True)
        cache.rmdir()
    for cache in list(REPOSITORY.rglob('.pytest_cache')):
        for item in sorted(cache.rglob('*'), reverse=True):
            if item.is_file():
                item.unlink(missing_ok=True)
            elif item.is_dir():
                item.rmdir()
        cache.rmdir()
    for pattern in ('*.aux', '*.bbl', '*.blg', '*.log', '*.out', '*.fls', '*.fdb_latexmk', '*.synctex.gz'):
        for item in (REPOSITORY / 'paper').glob(pattern):
            item.unlink(missing_ok=True)


def _public_corpus_metadata_boundary() -> dict[str, int]:
    subject_root = ROOT / 'data' / 'corpus' / 'subjects'
    email_pattern = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
    descriptor_pattern = re.compile(r'large\s+language\s+model', re.IGNORECASE)
    email_files: set[str] = set()
    descriptor_files: set[str] = set()
    for path in subject_root.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in {'.toml', '.lock', '.txt', '.md', '.json'}:
            continue
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding='utf-8', errors='ignore')
        if email_pattern.search(text):
            email_files.add(rel)
        if descriptor_pattern.search(text):
            descriptor_files.add(rel)
    return {
        'public_subject_files_with_upstream_email_fields': len(email_files),
        'public_subject_files_with_package_description_phrases': len(descriptor_files),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence' / 'repository_audit_summary.json')
    args = parser.parse_args()
    findings: list[dict[str, str]] = []
    _remove_residue()
    top = sorted(p.name for p in REPOSITORY.iterdir())
    if top != ['artifact', 'paper']:
        findings.append({'severity': 'P0', 'check': 'top_level_layout', 'detail': str(top)})
    for rel in REQUIRED:
        path = REPOSITORY / rel
        if not path.is_file() or path.stat().st_size == 0:
            findings.append({'severity': 'P0', 'check': 'required_file', 'detail': rel})
    residue = []
    names = []
    local_path_hits = []
    for path in REPOSITORY.rglob('*'):
        rel = path.relative_to(REPOSITORY).as_posix()
        if any(part in BAD_DIRS for part in path.parts):
            residue.append(rel)
        if path.is_file() and (path.suffix in BAD_SUFFIXES or path.name.endswith('.synctex.gz')):
            residue.append(rel)
        if any(token in rel.lower() for token in ('ga'+'te6', 'ga'+'te_', 'fi'+'nal', 'sub'+'mission', 're'+'view_'+'sim')):
            names.append(rel)
        if path.is_file() and path.suffix.lower() in {'.py', '.md', '.tex', '.json', '.csv', '.sh'}:
            text = path.read_text(encoding='utf-8', errors='ignore')
            if '/mnt' + '/data/' in text or '/home' + '/oai/' in text or 'user-' + 'tfbr' in text:
                local_path_hits.append(rel)
    if residue:
        findings.append({'severity': 'P0', 'check': 'build_residue', 'detail': '; '.join(sorted(set(residue))[:40])})
    if names:
        findings.append({'severity': 'P1', 'check': 'process_name', 'detail': '; '.join(sorted(set(names))[:40])})
    if local_path_hits:
        findings.append({'severity': 'P0', 'check': 'local_paths', 'detail': '; '.join(sorted(set(local_path_hits))[:40])})
    provenance_trace_hits = []
    trace_patterns = (
        'GitHub.' + 'fetch_file',
        'via Git' + 'Hub connector',
        'fetched via ' + 'connector',
        'main_default_ref_via_' + 'connector',
        'this ' + 'container',
        'que' + 'ued, ' + 'not counted',
        'future ' + 'policy ' + 're' + 'view',
        'pilot ' + 'fixture',
    )
    numbered_trace = re.compile(r'turn\d+file\d*|turn\d+(?:/turn\d+)+')
    for path in REPOSITORY.rglob('*'):
        rel = path.relative_to(REPOSITORY).as_posix()
        if path.is_file() and path.suffix.lower() in {'.py', '.md', '.tex', '.json', '.csv', '.txt', '.sh'}:
            text = path.read_text(encoding='utf-8', errors='ignore')
            if any(pattern in text for pattern in trace_patterns) or numbered_trace.search(text):
                provenance_trace_hits.append(rel)
    if provenance_trace_hits:
        findings.append({
            'severity': 'P1',
            'check': 'provenance_trace_terms',
            'detail': '; '.join(sorted(set(provenance_trace_hits))[:40]),
        })
    py_files = sorted((ROOT).rglob('*.py'))
    syntax_errors = []
    source_lines = 0
    for path in py_files:
        text = path.read_text(encoding='utf-8')
        source_lines += sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#'))
        try:
            ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            syntax_errors.append(f'{path.relative_to(REPOSITORY)}:{exc.lineno}:{exc.msg}')
    if syntax_errors:
        findings.append({'severity': 'P0', 'check': 'python_syntax', 'detail': '; '.join(syntax_errors)})
    direct_tools = sorted((ROOT / 'tool').glob('*.py'))
    for tool in direct_tools:
        text = tool.read_text(encoding='utf-8')
        if 'def main(' not in text or 'argparse' not in text:
            findings.append({'severity': 'P1', 'check': 'tool_contract', 'detail': tool.name})
    command_surface = audit_command_surface(ROOT, ROOT / 'evidence' / 'command_surface_summary.json')
    _remove_residue()
    if command_surface['status'] != 'pass':
        findings.append({'severity': 'P1', 'check': 'command_surface', 'detail': '; '.join(command_surface.get('failures', []))})
    public_metadata = _public_corpus_metadata_boundary()
    summary = {
        'status': 'pass' if not findings else 'fail',
        'top_level': top,
        'python_files': len(py_files),
        'python_source_lines': source_lines,
        'tool_scripts': len(direct_tools),
        'direct_tool_run_status': command_surface['status'],
        'direct_tool_run_scripts': command_surface['tools'],
        'public_corpus_metadata_boundary': public_metadata,
        'findings': findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
