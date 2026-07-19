# Shape B bootstrap: GitHub App + Backblaze B2 WORM

Status: **PROVISIONING**. Does not activate ADR 0028 in `PaulKov/dpone`.

## Chosen free WORM store

**Backblaze B2** with Object Lock (compliance mode), free tier ~10 GB.

Why not:
- Cloudflare R2 — no Object Lock / WORM
- Company AWS/GCP already logged in on workstation — wrong tenancy for public `dpone` release evidence
- GitHub Actions artifacts — transport only, not receipt authority (ADR 0028)

Canonical `store_id` format (after bucket exists):

```text
b2://<bucket-name>?region=<region>&object_lock=compliance&retention_days_pre_mutation=365&retention_days_closed=2557
```

## GitHub App

Manifest: [`github-app-manifest.json`](../github-app-manifest.json)

One-click (while logged into GitHub as `PaulKov`):

1. Open https://github.com/settings/apps/new
2. Or run `scripts/open-app-manifest.html` locally and submit the form
3. Install the App on `PaulKov/dpone` and `PaulKov/dpone-release-controller`
4. Store App ID + installation ID in inventory (never commit private key)

## B2 bucket

```bash
# after account + application key
b2 bucket create dpone-release-evidence-v1 allPrivate \
  --default-server-side-encryption SSE-B2 \
  --file-lock-enabled
```

Set default retention to at least 2557 days for closed streams (or per-object
on append). Writer credentials must be OIDC-exchanged or short-lived keys
scoped to this bucket only — never long-lived admin keys in `dpone`.
