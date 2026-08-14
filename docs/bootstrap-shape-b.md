# Shape B bootstrap — retired provisioning guide

Status: **RETIRED / DO NOT EXECUTE.** This document records why the historical
scaffold was created; it is not an operator runbook and does not activate ADR
0028 in `PaulKov/dpone`.

The retained tools/evidence/release_evidence_cli.py entry point is likewise
**DORMANT / NOT AN OPERATOR INTERFACE**. All of its subcommands can append
evidence-store receipts, including commands named observe or dry-run, and
stage-draft-live can mutate GitHub. It refuses normal execution before loading
the legacy runtime unless a caller supplies the explicit global
--allow-dormant-bootstrap-mutations acknowledgement before the subcommand.

That per-invocation flag exists only for separately approved forensic
compatibility. It neither activates a controller nor authorizes a release, and
--dry-memory is not a substitute. The guard does not secure direct imports,
historical refs, or provider-side re-runs; credential revocation and workflow
disablement remain mandatory.

The historical bootstrap combined a broad GitHub App, long-lived B2
credentials, mutable controller code, and direct provider mutation. A live run
used that path. The exact observed objects and unresolved provider controls are
recorded in [`live-inventory.md`](live-inventory.md).

## GitHub App disposition

The installed App must be suspended or reduced and its private key/client
secret rotated before any controller work resumes. The checked-in
[`github-app-manifest.json`](../github-app-manifest.json) now describes a
read-only inspection shape only. Updating that file does not change the
installed App. The historical one-click HTML form is intentionally disabled.

Any future activation design must use job-specific credentials with the exact
minimum repository permissions. No privileged job may checkout mutable
controller or candidate code.

## Evidence-store disposition

Backblaze B2 Object Lock remains inventory evidence, not transaction authority.
Object Lock alone cannot provide compare-and-swap, a unique lease sequence,
fencing, renewal, one-use capabilities, or deterministic recovery. Revoke or
rotate the historical application key. A future design requires a transactional
coordinator plus an outbox that verifies the immutable B2 archive before any
provider-mutation capability is issued.

The historical `store_id` shape is retained only for forensic compatibility:

```text
b2://<bucket-name>?region=<region>&object_lock=compliance&retention_days_pre_mutation=365&retention_days_closed=2557
```

Do not create, delete, overwrite, publish, or reuse any historical bootstrap
object without a separate evidence-preserving cleanup plan and approval.
