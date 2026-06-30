# Public benchmark

The benchmark contains 41 public repositories across five Python dependency
managers.  Every included subject is pinned to a commit and contains:

- the exact manifest and lockfile bytes;
- one or more local license files;
- `acquisition.json` with repository, commit, file digests, and acquisition
  metadata;
- `PROVENANCE.md` describing the capsule.

`data/corpus/ledger.csv` is the analysis denominator.  The retained
`screening_log.csv` records 57 screened rows, including all 16 excluded
rows and their reasons.  Inclusion requires a byte-complete pair, verified
license evidence, successful local parsing, and a nonduplicate repository
commit.  Excluded rows are retained only as screening evidence: they are not
imputed, replaced, tuned against, or used in any reported denominator.

The canonical subject provenance is the ledger row plus the matching capsule
under `data/corpus/subjects/<subject_id>/`. Each capsule stores the exact
repository URL, commit, manifest path, lockfile path, license evidence, and
file digests in `acquisition.json`, with a human-readable `PROVENANCE.md`
summary beside it.

The benchmark deliberately spans format families and evidence patterns.  It is
a construct-validation benchmark for comparative diagnosis within the
checked-in subjects, not a random sample, manager ranking, or comprehensive
ecosystem-coverage claim.  It is not intended to estimate ecosystem prevalence
or manager market share.  `evidence/corpus_diversity_summary.json` quantifies
this boundary with manager counts, concentration, entropy, unique-repository
counts, and the retained exclusion ledger.

Per-manager outcomes are regenerated in
`evidence/manager_profile_summary.csv` and
`evidence/missing_obligations.csv`.  Projection contrasts are regenerated in
`evidence/projection_summary.csv`, `evidence/projection_disagreement.csv`, and
`evidence/projection_separation_witnesses.csv`; these files are the benchmark's
baseline probes for simpler parser-, metadata-, integrity-, manifest-subset,
source-identity, resolver-metadata, SBOM-minimal, vulnerability-graph, and
reproducible-lock admission rules.  The downstream consumer baseline files
`evidence/consumer_baseline_summary.csv` and `evidence/consumer_baseline_matrix.csv`
map the same probes to SBOM inventory, vulnerability matching, reproducible-input,
and dependency-graph consumers without treating the corpus as a prevalence sample.
