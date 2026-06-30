#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPOSITORY_ROOT="$(cd "$ARTIFACT_ROOT/.." && pwd)"
PAPER_ROOT="$REPOSITORY_ROOT/paper"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH=1704067200
export FORCE_SOURCE_DATE=1
export TZ=UTC

progress() { printf '[PyLockGlyph] %s\n' "$1" >&2; }
now() { python3 - <<'PY'
import time
print(time.monotonic())
PY
}
run_pdflatex() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 90 pdflatex -interaction=nonstopmode -halt-on-error -file-line-error "$1" >/dev/null
  else
    pdflatex -interaction=nonstopmode -halt-on-error -file-line-error "$1" >/dev/null
  fi
}
run_bibtex() {
  if command -v bibtex >/dev/null 2>&1; then
    bibtex ./main >/dev/null
  elif [ -x /usr/bin/bibtex.original ]; then
    /usr/bin/bibtex.original ./main >/dev/null
  else
    echo "bibtex executable not found" >&2
    exit 1
  fi
}
check_python_dependencies() {
  python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    try:
        import tomli  # noqa: F401
    except ModuleNotFoundError:
        raise SystemExit("Python 3.10 replay requires: python3 -m pip install -r requirements.txt")
PY
}

clean_transients() {
  rm -f "$PAPER_ROOT"/*.aux "$PAPER_ROOT"/*.bbl "$PAPER_ROOT"/*.blg \
        "$PAPER_ROOT"/*.log "$PAPER_ROOT"/*.out "$PAPER_ROOT"/*.fls \
        "$PAPER_ROOT"/*.fdb_latexmk "$PAPER_ROOT"/*.synctex.gz
  find "$REPOSITORY_ROOT" -type d -name __pycache__ -prune -exec rm -rf {} +
  find "$REPOSITORY_ROOT" -type d -name .pytest_cache -prune -exec rm -rf {} +
}

STARTED="$(now)"
progress "check Python dependencies"
check_python_dependencies
progress "clean evidence"
rm -rf "$ARTIFACT_ROOT/evidence"
mkdir -p "$ARTIFACT_ROOT/evidence"
clean_transients

progress "run study"
python3 - "$ARTIFACT_ROOT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from pylockglyph.study import run_study
summary = run_study(root, root / "evidence")
print(json.dumps({"status": summary["status"], "subjects": summary["subjects"], "package_records": summary["package_records"], "controlled_cases": summary["controlled_cases"]}, sort_keys=True), flush=True)
raise SystemExit(0 if summary["status"] == "pass" else 1)
PY

progress "run tests"
python3 "$ARTIFACT_ROOT/tool/run_tests.py"

progress "prepare paper data"
python3 "$ARTIFACT_ROOT/tool/paper_data.py"

progress "compile main"
(
  cd "$PAPER_ROOT"
  run_pdflatex main.tex
  run_bibtex
  run_pdflatex main.tex
  run_pdflatex main.tex
)

progress "compile supplement"
(
  cd "$PAPER_ROOT"
  run_pdflatex supplement.tex
  run_pdflatex supplement.tex
)

progress "audit claim scope"
python3 "$ARTIFACT_ROOT/tool/audit_claim_scope.py"

progress "audit paper"
python3 "$ARTIFACT_ROOT/tool/audit_paper.py"

progress "audit baseline contract"
python3 "$ARTIFACT_ROOT/tool/audit_baseline_contract.py"

progress "analyze baseline under-admissions"
python3 "$ARTIFACT_ROOT/tool/analyze_under_admissions.py"

progress "audit external validation lock"
python3 "$ARTIFACT_ROOT/tool/audit_external_validation.py"

progress "audit corpus diversity"
python3 "$ARTIFACT_ROOT/tool/audit_corpus_diversity.py"

progress "audit negative controls"
python3 "$ARTIFACT_ROOT/tool/audit_negative_controls.py"

progress "audit validation closure"
python3 "$ARTIFACT_ROOT/tool/audit_validation_closure.py"

progress "audit overfitting sentinel"
python3 "$ARTIFACT_ROOT/tool/audit_overfitting_sentinel.py"

progress "audit benchmark scope contract"
python3 "$ARTIFACT_ROOT/tool/audit_benchmark_scope_contract.py"

clean_transients

progress "audit repository"
python3 "$ARTIFACT_ROOT/tool/audit_repository.py"

ELAPSED="$(python3 - "$STARTED" <<'PY'
import sys, time
print(time.monotonic() - float(sys.argv[1]))
PY
)"
progress "build replay manifest"
python3 "$ARTIFACT_ROOT/tool/build_replay_manifest.py" --elapsed "$ELAPSED"

progress "verify replay"
python3 "$ARTIFACT_ROOT/tool/verify_replay.py"

cat "$ARTIFACT_ROOT/evidence/replay_summary.json"
