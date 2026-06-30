# PyLockGlyph

PyLockGlyph issues profile-indexed admission verdicts for Python
manifest/lockfile evidence.  It answers a local question that precedes SBOM
construction, vulnerability matching, and reproducible builds: does the pair
contain the typed evidence required by a named downstream analysis?

The implementation supports PDM, pip-tools, Pipenv, Poetry, and uv.  It
normalizes package records, evaluates eight required evidence types, applies two
consumer profiles, and materializes every reported table from commit-pinned
public capsules.

## Quick start

Python requirement: CPython 3.11 or newer, or CPython 3.10 with the
conditional dependency in `requirements.txt` installed.

System requirements: a POSIX shell, `pdflatex`, BibTeX, `pdfinfo`, and
`pdftotext`.

```sh
cd artifact
python3 -m pip install -r requirements.txt
./run_replay.sh
```

The command rebuilds the study outputs, runs the test suite, regenerates the
LaTeX tables, compiles both PDFs, checks claim scope and paper/evidence consistency, audits the
repository, and writes a SHA-256 manifest.  It does not require network access.

## Repository map

- `data/corpus/ledger.csv`: included public subjects.
- `data/corpus/screening_log.csv`: retained inclusion and exclusion decisions.
- `data/corpus/README.md`: public-capsule metadata boundary.
- `EXCLUSIONS.md`: inclusion rules and retained exclusion categories.
- `data/corpus/subjects/`: byte-complete manifest, lockfile, license, and
  acquisition capsules.
- `pylockglyph/`: parsers, evidence model, admission predicate, theory
  replay, control generation, and audits.
- `tests/`: deterministic unit and integration tests.
- `tool/`: command-line entry points.
- `evidence/`: regenerated CSV/JSON results and replay manifest.
- `USAGE.md`: one-pair command for checking a local manifest/lockfile outside
  the benchmark ledger.
- `../paper/`: article, supplement, bibliography, generated tables, and PDFs.

## Central outputs

`evidence/study_summary.json` is the compact machine-readable result.  The
main row-level outputs are `profile_outcomes.csv`, `package_records.csv`,
`projection_disagreement.csv`, and the six controlled-validation files.  The
finite truth table and constructive projection-loss cases are retained rather
than summarized away.

`evidence/negative_control_summary.json` separates expected-reject controls
from preservation controls.  It reports the obligation coverage of evidence
removals, adversarial vectors, executable mutations, weakening relations, and
the zero false-accept count, so a passing controlled suite is interpretable as
contract falsification rather than an accuracy score.
`evidence/negative_control_provenance.md` records that these controls are
corpus-derived transformations rather than fitted examples.

`evidence/manager_profile_summary.csv` and
`evidence/missing_obligations.csv` report per-manager outcomes.  The projection
contrast files (`projection_summary.csv`, `projection_disagreement.csv`, and
`projection_separation_witnesses.csv`) show where simpler admission rules
over-admit relative to the profile-indexed verdict.  The consumer-baseline
files (`consumer_baseline_summary.csv` and `consumer_baseline_matrix.csv`) repeat
that comparison for named downstream proxies: SBOM inventory, vulnerability
matching, reproducible-build input checking, and full dependency-graph analysis.
`evidence/under_admission_summary.json` explains the under-admission rows as
projection requirements outside the compared consumer proxy, not as external
tool false negatives.  `evidence/external_validation_summary.json` audits a
frozen 15-subject sanity check with `cyclonedx-py` and `pip-audit`; this check
is separate from the formal proxy baseline and records unsupported manager
formats explicitly.  `evidence/external_disagreement_analysis.md` gives
concrete disagreement examples, while `evidence/semantic_spotcheck_records.csv`
checks a 50-plus-record cross-manager sample against a separately written raw-field
extractor.
The release audits `baseline_contract_summary.json`,
`corpus_diversity_summary.json`, `validation_closure_summary.json`, and
`overfitting_sentinel_summary.json`
make the baseline mapping, benchmark concentration boundary, and absence of
subject-specific method code directly checkable.

## One-pair check

To inspect a local manifest/lockfile pair without adding it to the benchmark,
run:

```sh
python3 tool/check_pair.py --manager poetry --manifest /path/to/pyproject.toml --lockfile /path/to/poetry.lock
```

See `USAGE.md` for interpretation notes and supported manager names.

## Scope

The corpus is an intentionally heterogeneous benchmark, not a probability
sample of the Python ecosystem.  Counts are therefore benchmark-scoped.  An
admission verdict states whether the local bytes satisfy a declared evidence
profile; it is not a vulnerability verdict, an SBOM, or a provenance claim.
The retained exclusions document the inclusion boundary and do not contribute
to outcomes, tuning, or denominators.
The downstream consumer comparisons are a formal evidence-obligation proxy,
not an external tool execution baseline, and the corpus is a
construct-validation benchmark, not a random sample or comprehensive ecosystem
coverage claim.

The subject capsules retain public upstream manifest and lockfile bytes,
including third-party maintainer fields and package descriptions when those
fields are part of the checked-in project files.  Those bytes are corpus
provenance, not project-author identity.  The repository audit reports this
metadata boundary separately from project-authored anonymity checks.
