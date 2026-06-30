# External Disagreement Analysis

This file explains disagreements in the small external-tool sanity check.
The external tools are not treated as ground truth for PyLockGlyph's declared
profile-indexed admission contract; disagreements identify boundary differences
between a concrete tool policy and the formal evidence obligations.

| subject | manager | tool | consumer | PyLockGlyph decision | external result | missing obligations | concrete package example | interpretation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| piptools_tong89_smartnode_3d8db92 | pip-tools | cyclonedx-py | sbom_inventory | reject | processed JSON | source;dependency_edge;manifest_agreement | sgp4 2.22, hashes=2, dependencies=0 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| piptools_python_pyperformance_1d3e217 | pip-tools | cyclonedx-py | sbom_inventory | reject | processed JSON | source;integrity;dependency_edge;manifest_agreement | psutil 7.0.0, hashes=0, dependencies=0 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| piptools_python_pyperformance_1d3e217 | pip-tools | pip-audit | vulnerability_matching | reject | processed JSON | source;integrity;dependency_edge;manifest_agreement | psutil 7.0.0, hashes=0, dependencies=0 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| piptools_rmax_scrapy_inline_requests_2cbbb66 | pip-tools | cyclonedx-py | sbom_inventory | reject | processed JSON | source;integrity;dependency_edge;manifest_agreement | alabaster 0.7.8, hashes=0, dependencies=0 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| piptools_rmax_scrapy_inline_requests_2cbbb66 | pip-tools | pip-audit | vulnerability_matching | reject | processed JSON | source;integrity;dependency_edge;manifest_agreement | alabaster 0.7.8, hashes=0, dependencies=0 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| poetry_pycap_b1cf4ae | poetry | cyclonedx-py | sbom_inventory | reject | processed JSON | source | astroid 3.3.8, hashes=2, dependencies=1 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |
| poetry_python_poetry_cf54a1c | poetry | cyclonedx-py | sbom_inventory | admit | no parseable JSON |  | anyio 4.13.0, hashes=2, dependencies=3 | the formal obligations are present, but the external command did not produce parseable JSON; this row is retained as an external-tool limitation |
| poetry_hyperdxio_hyperdx_py_05c52ff | poetry | cyclonedx-py | sbom_inventory | reject | processed JSON | source | astroid 2.15.8, hashes=2, dependencies=3 | external tool emitted output even though the formal consumer obligation set is incomplete; this is a tool-policy difference, not evidence that the missing obligation is present |

Interpretation:

- `cyclonedx-py` can emit an inventory for some pairs that lack PyLockGlyph's explicit source or manifest-agreement obligations. PyLockGlyph therefore records a conservative reject for the declared profile rather than claiming the tool output is unusable.
- `pip-audit` can perform a flat vulnerability lookup from pinned requirement lines without dependency-edge or source evidence. PyLockGlyph's `vulnerability_matching` proxy is stricter because it models graph-aware matching obligations.
- A `cyclonedx-py` failure on a Poetry subject is retained as an external-tool parse/environment limitation, not converted into a PyLockGlyph success claim.

