# Evidence Obligations and Admission Rule

For each parsed manifest/lockfile pair, PyLockGlyph constructs a Boolean
vector over eight required evidence types:

- `identity`: every normalized record names a package;
- `version`: every record carries an exact resolved coordinate;
- `source`: the pair explicitly anchors the package source or index;
- `integrity`: every record has hashes, a pinned source, or a local source;
- `resolver_epoch`: the lock records the format/resolver epoch needed to
  interpret its semantics;
- `dependency_edge`: the lock serializes at least one dependency relation;
- `manager_metadata`: manager-specific lock metadata is present;
- `manifest_agreement`: default direct requirements occur in the lock.

The `inventory` profile requires every obligation except `dependency_edge`.
The `dependency_graph` profile requires all eight.  Admission is a principal
filter: a parsed pair is admitted exactly when its evidence support contains
the profile requirement set.  Evidence types are not interchangeable.

Manager adapters only extract fields serialized in the local pair.  They do
not infer a default source from file type, manufacture dependency edges, query
an index, or accept partial hash coverage as complete integrity evidence.

Construct validation combines exhaustive Boolean replay, constructive
projection-loss cases, executable document mutations, typed evidence
removals, adversarial vectors, metamorphic relations, formatting invariance,
and a separately written parser.  The controlled suites include both
preservation controls and expected-reject controls: each required evidence type is
removed in isolation, removed through adversarial vectors, and represented in
executable mutations or weakening relations.  The replay records missing
evidence-type diagnostics and requires zero false accepts for these negative
controls.

The baseline comparison is a declared projection contract rather than a tuned
classifier or external tool execution baseline: every projection and downstream
consumer is represented as a formal evidence-obligation proxy over the eight
evidence obligations and replayed over the same included bytes.  A separate
sentinel scans method source for subject-specific repository, commit, or
identifier literals so that the admission logic cannot silently specialize to
the benchmark rows.

The small external-tool check is a sanity check for the proxy boundary, not a
replacement for the formal contract.  It freezes a 15-subject sample spanning
all five manager families and records how `cyclonedx-py` and `pip-audit`
process supported formats.  PDM and uv subjects remain in the sample as
documented unsupported formats for those two tools, so tool coverage is not
confused with lockfile evidence coverage.

To avoid a closed-loop validation story, replay also materializes a
manager-balanced semantic spot-check.  The spot-check compares 60 sampled
package records when enough package entries are available, and otherwise keeps
all manager families represented above the 50-record threshold.  It checks
sampled package records against a separately written raw-field extractor for
name/version identity, source-presence, integrity-presence, and
dependency-presence evidence.  This check is separate from the profile
admission predicate and is reported with concrete rows rather than only a
summary count.

Claim-scope discipline is part of the method: counts are interpreted as construct-validation benchmark results for the included bytes and named profiles, not as population estimates.
