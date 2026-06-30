# Applying PyLockGlyph to a local pair

The benchmark replay is the authoritative artifact workflow. For a quick
one-pair check outside the benchmark ledger, use `tool/check_pair.py` from the
artifact directory:

```sh
python3 tool/check_pair.py \
  --manager poetry \
  --manifest /path/to/pyproject.toml \
  --lockfile /path/to/poetry.lock
```

The command prints JSON with parser status, package count, the eight required
evidence types, and the two profile decisions. It does not modify the benchmark,
write corpus files, contact the network, install packages, or infer missing
evidence.

Supported manager names are `pdm`, `pip-tools`, `pipenv`, `poetry`, and `uv`.
Use the manager that produced the lockfile. A failing parse is reported as a
nonzero exit code with the parser error in the JSON payload.

Typical interpretation:

- `inventory.eligible = true` means the pair satisfies the evidence required by
  the inventory profile.
- `dependency_graph.eligible = true` means the pair also has dependency-edge
  evidence.
- `missing` lists exactly which required evidence types are absent for a
  profile.
- An admission verdict is local to the supplied bytes; it is not a vulnerability
  verdict, SBOM, or provenance claim.
