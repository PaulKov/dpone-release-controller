# Quarantined controller replacement stack

## Purpose

The former controller prototype arrived as one change containing the domain,
state machine, generated contracts, tests, and documentation. The replacement
uses an acyclic stacked review. Every layer is independently buildable and the
only dependency direction is from a later layer to an earlier one.

| Layer | Review scope | Provider authority |
| --- | --- | --- |
| Q1 emergency quarantine | Remove the historical writer graph and retain an inert marker plus a permanent CLI tombstone | None |
| Domain and candidate model | Canonical identifiers, receipt vocabulary, candidate archive/stream contracts, and public-closure HOLD types | None |
| State and service primitives | Pure operation, route, service, and receipt-state building blocks | None |
| Controller composition | Compose the pure state machine and wire catalog without a runtime entry point | None |
| Normative artifacts | Production-owned registries, generators, schemas, and fixed vectors | None |
| Offline conformance | Python 3.11/3.12 tests, static boundaries, generated-byte checks, and reviewer documentation | None |

The current layer is **domain and candidate model**. It intentionally has no
provider client, network transport, subprocess call, workflow dispatch, secret,
OIDC permission, artifact upload, or target-repository route.

## Dependency rule

Every `tools.evidence.release_*` import must resolve inside the current layer or
an earlier layer. The quarantine test parses the import graph, rejects missing
edges, and rejects cycles. Production modules may not import test-owned
authority.

## Self-service review

Run the dependency-free checks on any supported Python interpreter:

```console
python3 -B -m unittest discover -s tests -v
python3 -B -m compileall -q tests tools
git diff --check
```

These checks establish properties of the checked-in source only. They do not
observe or change GitHub, PyPI, Backblaze B2, the target repository, or any
historical credential.

## Activation boundary

No layer in this stack authorizes activation. Provider preparation, independent
approval, exact-head rehearsal, and an activation change remain separately
reviewed work. The Q1 operational quarantine evidence is still mandatory.
