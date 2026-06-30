# Negative Control Provenance

The expected-reject controls are corpus-derived transformations, not fitted examples.
There is no training stage, learned parameter, or subject-specific branch in the admission predicate.
Expected outcomes follow from the profile requirement sets: if a required evidence bit is removed from an eligible pair, the principal-filter predicate must reject the transformed pair.

- Corpus-derived expected-reject cases: 725
- Synthetic expected-reject cases: 0
- Preservation controls: 246
- False accepts: 0
- Obligations covered: dependency_edge, identity, integrity, manager_metadata, manifest_agreement, resolver_epoch, source, version

The transformations do not alter the admission logic after seeing outcomes. They are regenerated from the checked-in public capsules during replay, and the overfitting sentinel separately scans method code for subject identifiers, repository names, commits, and subject-specific branches.
