# Known Limitations

- Flat pip-tools requirements can be consumed by vulnerability lookup tools without source anchors or dependency edges; PyLockGlyph intentionally rejects those pairs for graph-aware profiles.
- Some SBOM tools infer a default package source when a lockfile omits an explicit source. PyLockGlyph does not infer that source because the admission verdict is limited to serialized local evidence.
- The external validation harness does not execute PDM or uv through cyclonedx-py or pip-audit because those tools do not expose matching parsers in the pinned environment.
- A Poetry project can satisfy PyLockGlyph's evidence obligations while a concrete external tool fails on project-layout details; such rows are recorded as external-tool limitations, not as proof of downstream success.
- PyLockGlyph checks manifest/lockfile evidence, not resolver correctness, vulnerability database freshness, or whether a package can be installed from the network at replay time.
