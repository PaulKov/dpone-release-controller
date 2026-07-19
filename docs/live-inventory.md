# Live inventory (controller) — 2026-07-19

Status: **PARTIAL — App registered + B2 bucket exists; App not yet installed on target repos.**

## GitHub App

| Field | Value |
|---|---|
| name / slug | `dpone-release-controller` |
| app_id | `4341356` |
| html_url | https://github.com/apps/dpone-release-controller |
| owner | `PaulKov` (`74862786`) |
| private key / client secret | stored as GitHub Actions secrets on this repo (not in git) |
| installation_id | `UNVERIFIED` — install required |

Install (logged in as PaulKov):

https://github.com/apps/dpone-release-controller/installations/new

Select both `PaulKov/dpone` and `PaulKov/dpone-release-controller` (or all repos owned by PaulKov if preferred for solo-maintainer).

## Evidence store (Backblaze B2)

| Field | Value |
|---|---|
| bucket | `dpone-release-evidence-v1` |
| bucket_id | `87db248c461b71c09afb0416` |
| endpoint | `s3.us-east-005.backblazeb2.com` |
| region | `us-east-005` |
| type | private |
| object_lock | enabled |
| lifecycle | keep all versions |
| store_id | `b2://dpone-release-evidence-v1?endpoint=s3.us-east-005.backblazeb2.com&object_lock=enabled&bucket_id=87db248c461b71c09afb0416&retention_days_pre_mutation=365&retention_days_closed=2557` |
| application key | stored as repo secret `B2_APPLICATION_KEY` |
| application key id | `UNVERIFIED` — still needed for B2 authorize-account |

## Explicit non-claims

- ADR 0028 / policy v2 in `PaulKov/dpone` remain **inactive**.
- No PyPI Trusted Publisher rebind yet.
- No mutation jobs yet.
