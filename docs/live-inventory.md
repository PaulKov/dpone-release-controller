# Live inventory (controller) — 2026-08-14

Status: **QUARANTINE REQUIRED — provider/bootstrap objects exist; Trusted
Publisher and policy v2 are not activated.**

This inventory records observed state. It is not an activation receipt. No
provider setting, secret, tag, release, or stored object was changed while
preparing the quarantine patch.

## Controller source and governance

| Field | Observed value |
|---|---|
| repository | `PaulKov/dpone-release-controller` |
| audited default-branch commit | `ae15f09d38d5fa623eba739c6030557842ae7a3a` |
| branch rulesets / branch protection | none observed |
| environments | `release-attest`, `pypi`, `github-release` |
| environment protection / administrator bypass | zero protection rules observed; administrator bypass not closed |
| workflow id | `316322127` |
| historical workflow name | `Release controller scaffold` |

The quarantine source deletes the historical default-branch workflow path and
adds `.github/workflows/controller-quarantine.yml`, a dependency-free,
validation-only identity. It does not claim that this local patch has been
merged or deployed. Live repository state must be re-read after merge, and
historical workflow id `316322127` must be proven disabled or retired.
Queued/in-progress runs must be absent, and historical run `29735872648` must
be proven ineligible for re-run before operational quarantine can be claimed.

## GitHub App

| Field | Observed value |
|---|---|
| name / slug | `dpone-release-controller` |
| app_id | `4341356` |
| installation_id | `147673155` |
| html_url | <https://github.com/apps/dpone-release-controller> |
| installed repositories | `PaulKov/dpone`, `PaulKov/dpone-release-controller` |
| permissions | metadata:read, contents:write, actions:read, checks:read, statuses:read, administration:write, attestations:write |
| private key / client secret | Actions secrets on the controller repository |

This permission set is not least privilege: one App combines target content,
administration, and attestation authority. The quarantine workflow does not
mint an App token or reference the App secret.

## Evidence store (Backblaze B2)

| Field | Observed value |
|---|---|
| bucket | `dpone-release-evidence-v1` |
| bucket_id | `87db248c461b71c09afb0416` |
| account_id | `7b4c6b10ab46` |
| endpoint | `s3.us-east-005.backblazeb2.com` |
| api_url | `https://api005.backblazeb2.com` |
| object_lock | enabled |
| applicationKeyId | `0057b4c6b10ab460000000001` |
| application key secret | Actions secret `B2_APPLICATION_KEY` |
| store_id | `b2://dpone-release-evidence-v1?endpoint=s3.us-east-005.backblazeb2.com&object_lock=enabled&bucket_id=87db248c461b71c09afb0416&retention_days_pre_mutation=365&retention_days_closed=2557` |
| smoke object | `bootstrap/smoke/20260719T212938Z-store-smoke.json` — compliance retention about 365 days, PASS |

The observed workflow used static long-lived B2 credentials. Object Lock alone
does not prove transactional compare-and-swap, fencing, renewal, capability
separation, holds, or recovery closure. The quarantine workflow references no
B2 variable or secret.

## Historical live bootstrap mutation

Workflow run `29735872648` executed the former `mode=live` path and produced:

| Object | Observed value |
|---|---|
| GitHub attestation id | `36134964` |
| lightweight target tag | `v0.0.0-shape-b-bootstrap-29735872648` |
| tag target | `b91dae…` (inventory observation; re-read full SHA before any cleanup decision) |
| draft GitHub Release id | `356647437` |
| draft state | draft=`true`, prerelease=`true`, immutable=`false` |
| uploaded assets | one 81-byte bootstrap asset |

These are real mutations, contrary to the previous stale statement “No
mutation jobs yet.” Do not delete, publish, retarget, or reuse them without a
separate evidence-preserving cleanup decision.

## Explicit non-claims and unresolved gates

- ADR 0028 / policy v2 in `PaulKov/dpone` remain inactive.
- PyPI Trusted Publisher bindings for the four projects are not proven rebound
  to this controller.
- No exact eight-distribution candidate import and cryptographic provenance
  closure is implemented.
- No exact PyPI Integrity proof, immutable GitHub Release closure, Snapshot C,
  CLOSED receipt, or deterministic recovery proof exists.
- The historical controller checkout/actions and broad credentials do not meet
  the privileged job-boundary requirements.
- Repository/environment protections and no-bypass posture are not closed.
- Historical refs and the provider re-run window remain risks until workflow id
  `316322127` is retired, no active run remains, run `29735872648` cannot be
  re-run, and the broad B2/App credentials are revoked or rotated. A
  source-only patch is not evidence of those provider changes.
- Credential values previously exposed in chat must be rotated independently;
  this inventory never treats a pasted credential as trusted.

Therefore neither the historical run nor this inventory authorizes a dpone
release. Re-audit provider state after the quarantine patch is merged, then
follow the activation checklist in the repository README.
