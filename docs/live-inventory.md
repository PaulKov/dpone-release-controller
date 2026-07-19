# Live inventory (controller) — 2026-07-19

Status: **PARTIAL — App installed + B2 WORM smoke verified. Mutation jobs / TP / policy v2 not activated.**

## GitHub App

| Field | Value |
|---|---|
| name / slug | `dpone-release-controller` |
| app_id | `4341356` |
| installation_id | `147673155` |
| html_url | https://github.com/apps/dpone-release-controller |
| installed repositories | `PaulKov/dpone`, `PaulKov/dpone-release-controller` |
| permissions | metadata:read, contents:write, actions:read, checks:read, statuses:read, administration:write, attestations:write |
| private key / client secret | Actions secrets on this repo only |

## Evidence store (Backblaze B2)

| Field | Value |
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
| smoke object | `bootstrap/smoke/20260719T212938Z-store-smoke.json` (compliance retention ~365d) PASS |

## Explicit non-claims

- ADR 0028 / policy v2 in `PaulKov/dpone` remain **inactive**.
- No PyPI Trusted Publisher rebind yet.
- No mutation jobs yet.
- Rotate `B2_APPLICATION_KEY` after chat exposure when convenient.

## Evidence tooling (2026-07-19)

Mirrored from `PaulKov/dpone` `tools/agent_policy/release_*.py` into
`tools/evidence/`. Workflow job `admit-and-lease` appends `LEASE_ACQUIRED` to
B2 only — no PyPI / GitHub Release mutation and no policy v2 cutover.
