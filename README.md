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

Run the dependency-free contract suite from the repository root:

```bash
python3 -B -m unittest discover -s tests -v
```

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
python3 tools/controller_preflight.py validate \
  --policy config/release-controller-activation.json \
  --github-output "$preflight_output"
```

Accepted tags are canonical `vSemVer` values without build metadata. TTL is
bounded to 60–3600 seconds. Empty dry-run tags become a per-run quarantine tag;
live mode requires an explicit tag. Shell payloads, Unicode digits, unknown
modes, malformed policy fields, marker mismatches, and commit-binding
mismatches fail closed.

### Dormant historical evidence CLI

The historical entry point at tools/evidence/release_evidence_cli.py is
**DORMANT / NOT AN OPERATOR INTERFACE**. Every subcommand appends evidence-store
receipts in its normal mode, including the observe and attest-draft-dry-run
commands; stage-draft-live can also mutate GitHub.

By default the CLI exits before loading its retired runtime graph or accessing
credentials, files, or the network. Help is safe and documents the guard:

~~~bash
python3 -B tools/evidence/release_evidence_cli.py --help
~~~

Controlled forensic compatibility requires the global
--allow-dormant-bootstrap-mutations flag before the subcommand. The flag is a
per-invocation acknowledgement, not activation or release authorization;
--dry-memory does not replace it. Do not persist the flag in a workflow,
configuration, alias, or environment variable.

This entry-point guard limits accidental use of current source only. Direct
module imports, historical refs, and eligible historical run replays bypass
it, so the provider controls in the operational checklist remain mandatory.

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
