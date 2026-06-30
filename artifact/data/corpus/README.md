# Public Corpus Capsule Boundary

The files under `subjects/` are byte-complete public manifest, lockfile,
license, and acquisition capsules for the included benchmark subjects.  They
are retained so that parser behavior, evidence extraction, and replay hashes
are evaluated on the same bytes that define the benchmark rows.

Some public manifests include upstream maintainer names or email addresses,
and some lockfiles include third-party package descriptions.  These fields are
not project-author metadata, credentials, private correspondence, or workflow
notes.  They are treated as public corpus bytes and remain inside the replay
hash envelope to avoid changing the evidence that the parsers consume.

Project-authored files are audited separately for local paths, credentials,
process residue, and author identity.  The benchmark does not use upstream
maintainer metadata as a label, outcome, tuning signal, or denominator.
