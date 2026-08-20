# dpone-release-controller

External privileged composition root planned for dpone release-trust **shape B**
([ADR 0028](https://github.com/PaulKov/dpone/blob/master/docs/adr/0028-frozen-release-policy-and-publication-boundary.md)).

## Status

**QUARANTINE PATCH / NOT DEPLOYED OR ACTIVATED.** This repository is an
inventory and tooling scaffold. The source tree removes the historical live
workflow path and introduces a validation-only workflow at
`.github/workflows/controller-quarantine.yml`; provider-side quarantine is not
complete until the operational controls below are independently verified.

This repository is not the live Trusted Publisher and is not proof that ADR
0028 or release policy v2 is active in `PaulKov/dpone`.

Controller repository: `PaulKov/dpone-release-controller` (id `1305993853`).
Target repository: `PaulKov/dpone` (id `1255975556`).

The new executable source workflow intentionally performs no controlled
release/provider mutation. A dry-run still creates normal GitHub Actions
run/log/artifact transport:

- `mode` defaults to `dry-run`;
- dispatch values are validated before use and reach shell only through `env`;
- preflight rejects unless GitHub supplies the exact controller repository id,
  `workflow_dispatch`, `refs/heads/master`, and quarantine workflow ref;
- the checked-in activation policy is `quarantined`, policy v1, mutation off;
- no B2, GitHub App, OIDC, attestation, PyPI, tag, or Release credentials are
  available to the workflow;
- every action is pinned to an exact SHA already approved in the dpone
  baseline; and
- `live` is rejected inside preflight before any follow-up step; changing the
  policy alone is insufficient because the quarantine workflow supplies no
  activation marker or live mutation job.

The last guarantee is deliberate defense in depth. Restoring a live mutation
pipeline requires a separate reviewed code change after the activation gates
below are closed; changing a repository variable is insufficient.

## Self-service validation

The controller runtime modules use the Python standard library. Contract
validation additionally uses the locked development tools declared in
`pyproject.toml` and `uv.lock`: `jsonschema` for schema tests and `ruff`
for source checks. Use Python 3.11 as selected by `.python-version` and uv
0.11.28, then synchronize without changing the lock:

```console
$ uv sync --frozen
$ uv run --frozen ruff check .
$ uv run --frozen ruff format --check .
$ uv run --frozen python -B -m compileall -q scripts tests tools
$ uv run --frozen python -B -m unittest discover -s tests -v
```

The CI workflow runs the same locked commands on Python 3.11 and 3.12 and
checks every generated contract producer with `--check`. Use a producer's
explicit `--write` mode only in the reviewed contract change that owns the
generated output. All five producers below reject a missing mode and reject
unexpected files in their managed namespace; invoke the receipt-vector module
explicitly as shown.
These are the exact regeneration commands:

```console
$ uv run --frozen python -B scripts/generate_release_controller_action_contract.py --write
$ uv run --frozen python -B scripts/generate_release_controller_vectors.py --write
$ uv run --frozen python -B scripts/generate_release_controller_wire_contracts.py --write
$ uv run --frozen python -B scripts/generate_release_receipt_schema.py --write
$ uv run --frozen python -B -m tools.evidence.release_receipt_vectors --write
```

The public closure producer intentionally has no write mode while its contract
is on HOLD; CI invokes its read-only `--check` quarantine assertion.

Exercise the local preflight without credentials or network access:

```bash
preflight_output="$(mktemp)"
INPUT_MODE=dry-run \
INPUT_TAG=v0.74.0 \
INPUT_TTL_SECONDS=900 \
GITHUB_RUN_ID=1 \
GITHUB_SHA=0000000000000000000000000000000000000000 \
GITHUB_REPOSITORY=PaulKov/dpone-release-controller \
GITHUB_REPOSITORY_ID=1305993853 \
GITHUB_EVENT_NAME=workflow_dispatch \
GITHUB_REF=refs/heads/master \
GITHUB_WORKFLOW_REF=PaulKov/dpone-release-controller/.github/workflows/controller-quarantine.yml@refs/heads/master \
uv run --frozen python tools/controller_preflight.py validate \
  --policy config/release-controller-activation.json \
  --github-output "$preflight_output"
```

Accepted tags are canonical `vSemVer` values without build metadata. TTL is
bounded to 60–3600 seconds. Empty dry-run tags become a per-run quarantine tag;
live mode requires an explicit tag. Shell payloads, Unicode digits, unknown
modes, malformed policy fields, marker mismatches, and commit-binding
mismatches fail closed.

### Permanently quarantined historical evidence CLI

The historical entry point at tools/evidence/release_evidence_cli.py is
**PERMANENTLY QUARANTINED / NOT AN OPERATOR INTERFACE**. Current source is a
compatibility tombstone: it cannot dispatch a historical subcommand, load the
retired runtime graph, access credentials, or mutate GitHub, PyPI, B2, or a
local test stream.

Help is read-only and documents the replacement protocol:

~~~bash
uv run --frozen python -B tools/evidence/release_evidence_cli.py --help
~~~

Every non-help invocation exits with status 2 before runtime loading. There is
no compatibility or activation flag; the former
`--allow-dormant-bootstrap-mutations` option is rejected like any other
invocation. The activation-bound broker v2 protocol is the only permitted
release-state writer.

This tombstone limits accidental use of current source only. Historical refs
and eligible historical run replays remain separate provider risks, so the
operational quarantine controls below are still mandatory.

## Operational quarantine checklist

The code patch is necessary but not sufficient. Before anyone may describe the
live controller as quarantined, an administrator must record evidence that:

1. the historical workflow id `316322127` is disabled or retired after the old
   `.github/workflows/release-controller.yml` disappears from the default
   branch; all queued/in-progress runs are cancelled, and the provider proves
   that historical run `29735872648` cannot be re-run;
2. the historical B2 application key, GitHub App private key, and client secret
   are revoked or rotated, and no stale secret can authorize an old ref;
3. `master` and all release environments reject unreviewed refs and
   administrator bypass;
4. the new quarantine workflow can run only from `refs/heads/master`, while a
   dispatch against any historical branch or tag fails closed; and
5. the installed GitHub App's broad write permissions are removed or the App is
   suspended until job-specific least-privilege credentials are approved.

GitHub permits manual workflow dispatch against a selected branch or tag.
It also permits eligible historical workflow runs to be re-run for a bounded
retention window using their original commit/ref and workflow definition.
Deleting the historical default-branch workflow identity, binding the new ref
in preflight, and revoking its credentials are therefore complementary—not
interchangeable—controls.

## Required before activation

Activation is a reviewed cutover, not a workflow input. At minimum it requires:

1. Protect this repository's default branch and release environments without
   administrator bypass.
2. Replace the broad GitHub App with job-specific, least-privilege credentials;
   mutation jobs must never checkout mutable controller or candidate code.
3. Replace long-lived B2 keys with short-lived, audience-bound credentials and
   prove transactional CAS, lease renewal, fencing, holds, and recovery.
4. Import the exact certified candidate and verify all eight distributions,
   provenance, public bundle, policy digest, tag object, and peeled commit.
5. Rebind all four PyPI Trusted Publishers only after a protected rehearsal;
   verify Integrity API provenance for the exact published file set.
6. Prove exact GitHub Release id/assets/body, immutable-release closure,
   Snapshot C, CLOSED, and deterministic recovery.
7. Obtain fresh GO review and atomically cut `PaulKov/dpone` from policy v1 to
   policy v2.
8. Change the checked-in activation policy to a reviewed active policy v2,
   bind its marker digest, bind the exact workflow commit out of band, and
   restore the audited live jobs in a separate PR.

See [`docs/live-inventory.md`](docs/live-inventory.md) for observed provider
state and historical bootstrap mutations.

## Historical bootstrap warning

The former scaffold's `mode=live` was not harmless: run `29735872648` created
an attestation, a lightweight target tag, a draft GitHub Release, and an asset
in `PaulKov/dpone`. Those objects are inventory evidence only. They do not
constitute production release authority, PASS, GO, policy-v2 activation, or a
verified publication.
