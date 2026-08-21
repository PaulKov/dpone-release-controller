# Historical controller inventory

Status: **UNVERIFIED PROVIDER STATE / CODE QUARANTINE ONLY**.

This document separates historical observations from desired state. Values
below are retained for incident response and must not be interpreted as proof
of current authority, revocation, rotation, or production readiness.

## Historical observations

| Resource | Last recorded value | Current claim |
|---|---|---|
| controller repository | `PaulKov/dpone-release-controller` (`1305993853`) | identity only |
| target repository | `PaulKov/dpone` (`1255975556`) | identity only |
| legacy workflow | id `316322127`, path `.github/workflows/release-controller.yml` | removed by the quarantine patch; provider retirement still requires evidence |
| historical run | `29735872648` | retained run; re-run eligibility must be checked provider-side |
| GitHub App | app `4341356`, installation `147673155` | historical broad-write installation; suspend, uninstall, or reduce provider-side |
| B2 bucket | `dpone-release-evidence-v1`, id `87db248c461b71c09afb0416` | historical inventory; writer credentials must be revoked or rotated |

The former workflow used repository-level B2 and GitHub App secrets. Secret
names and provider objects are not proof that their values remain valid, but
their retirement must be demonstrated rather than inferred from this patch.

## Code state after this patch

- no release workflow is manually dispatchable;
- no B2, GitHub, PyPI, lease, attestation, or evidence writer implementation
  remains in the current default-branch tree;
- the compatibility CLI always fails closed; and
- the checked-in App manifest requests metadata read access only.

## Required fresh observation

Before future activation, capture signed or independently reviewed evidence for
workflow state and historical re-run behavior, active/queued runs, App
installation permissions, Actions secrets and variables, branch/environment
protection, B2 key state, PyPI Trusted Publisher rows, and target release/tag
inventory. Record observation time and immutable evidence digests.
