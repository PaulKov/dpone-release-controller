# Release contract authority

This directory contains the versioned, production-owned, language-neutral
inputs for generated release contracts. It is intentionally separate from
`tests/`: test fixtures consume these sources and cannot define production
schema or wire authority.

Authority flows in one direction:

```text
contracts/ + checked public schemas -> tools/evidence/*registry.py
                                     -> generators -> tests/fixtures/
```

- `registries/` binds each public structural schema path, digest, closed type
  inventory and semantic validator. The checked public schema under `docs/` is
  the human-reviewable source; the registry prevents silent replacement.
- Runtime Python validators remain normative for semantic, ordering, provider
  and fencing constraints that JSON Schema cannot express.
- `vectors/` owns positive cross-language bytes for contracts that require
  contextual or binary examples. Production parsers verify every vector before
  it can be projected into `tests/fixtures/`.
- `docs/` and `tests/fixtures/` are generated projections. Editing either one
  without changing the source is rejected by generator checks.

Contract changes must update the public schema or vector source and its compact
registry binding, run every generator in `--write` mode, then run the full test
suite and generators again in `--check` mode. Byte drift is a reviewed protocol
change; silent fixture regeneration is forbidden.
