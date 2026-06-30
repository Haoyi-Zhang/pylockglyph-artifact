# Reproduction

Run the complete offline workflow from `artifact/`:

```sh
python3 -m pip install -r requirements.txt
./run_replay.sh
```

The `requirements.txt` file is intentionally small: it installs `tomli` only
for Python versions older than 3.11, where the standard-library `tomllib`
module is unavailable.

The workflow performs these steps in order:

1. recreate `evidence/` from the checked-in corpus capsules;
2. run all unit and integration tests;
3. generate the paper tables, plot coordinates, and numeric macros;
4. compile `paper/main.pdf` and `paper/supplement.pdf`;
5. check page allocation, citation closure, numeric consistency, anonymity,
   and PDF structure;
6. check baseline-contract fairness, baseline under-admission explanations,
   the frozen external-tool validation lock, corpus concentration, negative
   controls, semantic spot-checks, documented limitations, subject-specific
   overfitting sentinels, and reviewer-risk boundaries for the formal evidence-obligation proxy and
   construct-validation benchmark role;
7. check repository layout, Python syntax, capsule completeness, prohibited
   residue, and direct execution of command-line tools;
8. write `evidence/replay_manifest.csv` and `evidence/replay_summary.json`.

All temporary LaTeX logs and Python caches are removed before the command
returns.  A nonzero exit code means at least one contract failed.
The replay manifest hashes deterministic source, evidence, and PDF artifacts;
wall-clock timing is retained in `evidence/timing_summary.json` but excluded
from the stable hash envelope.

The replay itself is CPU-only and does not use network access, cloud
accounts, private data, or external services.  The only optional setup step is
installing the conditional Python 3.10 compatibility dependency from
`requirements.txt`; Python 3.11 and newer use the standard-library TOML reader.

The default replay audits `spec/external_validation_lock.json` rather than
calling external package-analysis tools.  To regenerate that lock, install
`cyclonedx-py` and `pip-audit` in an environment outside the artifact tree and
run:

```sh
python3 tool/run_external_validation.py --tool-bin /path/to/external-tool/bin
```

The generated lock records the tool versions, selected public subjects,
supported and unsupported manager formats, agreement/disagreement labels, and
root-cause classifications.  The standard replay then rechecks that lock
against the current corpus and certificate predictions.

The replay also checks claim-scope discipline: benchmark results must not be
rewritten as ecosystem prevalence, manager rankings, or accuracy-style claims.
It regenerates `evidence/consumer_baseline_summary.csv` and
`evidence/consumer_baseline_matrix.csv`, which score named downstream consumer
proxies against the projection baselines, then audits that mapping separately
in `evidence/baseline_contract_summary.json`.
