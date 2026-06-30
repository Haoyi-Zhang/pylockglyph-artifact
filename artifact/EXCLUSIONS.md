# Screening exclusions

`data/corpus/screening_log.csv` is the complete screening ledger for the
checked-in benchmark. It contains 57 screened rows: 41 included subjects and 16
retained exclusions. The excluded rows are not used for admission outcomes,
profile denominators, timing, projection contrasts, controlled-validation
counts, or paper tables.

## Decision rules

A row is included only when all four conditions hold:

- the manifest and lockfile are both retained as byte-complete local evidence;
- license evidence is retained locally;
- the pair parses successfully under the manager adapter;
- the repository commit is not a duplicate of an already included subject.

Rows are excluded when any condition fails. The exclusion decision is recorded
before analysis and is not changed in response to admission outcomes.

## Exclusion categories

- **Excerpt-only rows**: the available public material is a partial excerpt
  rather than a complete repository subject.
- **Completeness failures**: the manifest or lockfile bytes are not retained in
  complete form, even if metadata or a header is visible.
- **License-boundary failures**: local license evidence is missing.
- **Evidence-content failures**: the retained lock has no package records.

The ledger keeps these rows visible so evaluators can audit the inclusion
boundary without treating excluded rows as negative examples or hidden test
cases.
