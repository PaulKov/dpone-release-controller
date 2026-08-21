# Broker provisioning and recovery runbook

> **Current state: `DPONE_PROVIDER_MUTATION_HOLD_V1`.** Every provider-mutating `--apply`
> operation below is a future post-lift ceremony description. In this publication candidate it
> fails with `PROVIDER_MUTATION_HOLD` before secret reads, temp/report reservation, subprocess,
> fetch, client, or provider access. Never attempt to bypass the guard with environment variables,
> flags, local files, credentials, or injected dependencies.

Read-only/offline commands currently allowed are `pnpm config:check`, `pnpm privacy:check`, the
test/lint/type/format gates, `bootstrap:live` without `--apply`, GitHub App PEM conversion without
`--apply`, and Cloudflare observer token evidence verification. The latter two read named local
secret files but contact no provider. `version:upload` and `version:deploy` require an explicit
`--apply` and remain unconditionally held.

## Preconditions

Do not create a live config or deploy authority until all of these are true:

1. Commit P, its protected annotated controller execution tag, workflow ID/blob, action inventory, and selected-actions policy are reviewed and frozen.
2. Both repositories report GitHub OIDC `use_default=true`, `use_immutable_subject=true`, and the exact immutable numeric owner/repository prefix. The current live baseline with `use_immutable_subject=false` is not admissible.
3. All isolated GitHub Apps have distinct app/installation identities, one selected repository, exact read-only/write permissions, and no extra webhook/OAuth surface. The PyPI gate App is separate.
4. The B2 bucket is `allPrivate`, SSE-B2/AES256, Object Lock COMPLIANCE with 2557-day default retention, no lifecycle rules, and no replication. Writer and observer keys are bucket/prefix restricted, distinct, and non-expiring.
5. The complete provider-evidence manifest and both independent operator approvals are WORM-confirmed. Naked evidence digests are not sufficient.
6. The authenticated exclusive private-service binding graph and every current deployment/version membership are provider-observed and pinned in A0.

## GitHub App key conversion

GitHub downloads PKCS#1 `BEGIN RSA PRIVATE KEY` PEM files. Runtime Workers accept only unencrypted PKCS#8 `BEGIN PRIVATE KEY` PEM files. Convert and verify the public SPKI fingerprint without printing either private key:

```sh
pnpm github-app-key:provision -- \
  --input /secure/path/downloaded-app.pem \
  --expected-spki-sha256 sha256:<reviewed-lowercase-fingerprint> \
  --config /absolute/path/to/wrangler.controller-run-reader.jsonc \
  --version-tag <reviewed-validation-tag> \
  --version-message <reviewed-validation-message>
```

This validation mode uploads nothing. After a separately reviewed HOLD lift, the apply form must change `--config` to the exact corresponding `.live.jsonc` path and add `--apply`; merely adding `--apply` to the provisioning-config example is invalid. The future apply form pipes the converted key into `wrangler versions secret put`, creating an undeployed immutable Worker version. The provisioner uses a mode-0600 temporary file, zeroes buffers where possible, and removes its private temporary directory. The source PEM is never copied or logged. After upload, run the closed private-service smoke that reauthenticates `GET /app` and an exact selected-repository installation token; A0 remains blocked until that provider observation is WORM-confirmed.

## One-use blank-account lifecycle bootstrap

Cloudflare does not apply Durable Object lifecycle changes through `wrangler versions upload`; a migration takes effect only when the containing Worker version is deployed. On an empty account, the only permitted `wrangler deploy` is therefore the reviewed one-use bootstrap below. It first creates every private service as a route-less, credential-free deny Worker, including the closed projector, PyPI gate, release mutator, runtime deployment gate, WORM services, and readers.

The WORM lifecycle deployment is deliberately distinct from the other private deny Workers. It deploys `src/bootstrap-worm.ts`, whose default entrypoint remains credential-free and fail-closed, but whose named ES-module exports are the same final `CloudflareEvidenceBatch` and `WormExactObjectEffect` classes. The preserved WORM bindings and append-only `v1`/`v2` `new_sqlite_classes` migrations create both SQLite namespaces without exposing a usable WORM endpoint. The bootstrap then deploys `src/bootstrap-ingress.ts` against the final ingress config so the reviewed ingress SQLite migrations `v1`/`v2` are applied. The ingress owns the final Custom Domain but serves only `/livez`; readiness, activation, provider, receipt, runtime, and webhook paths return canonical `503`.

The tracked `wrangler.*.live.jsonc` files are publication review templates with synthetic identifiers. For a future non-public cutover change, replace every classified placeholder with provider-observed values and review the final service-binding graph before dry validation. Declarative Durable Object config `exports` are intentionally forbidden because they are incompatible with this gradual/versioned rollout; the reviewed migration histories are rollout prerequisites. The canonical bootstrap report uses schema `dpone.release-broker-bootstrap-report.v2` and must carry an explicit `plan.lifecycle_migrations` projection for both ingress and WORM. A report that substitutes the obsolete `legacy_migrations_only` assertion is not admissible provenance.

```sh
pnpm bootstrap:live -- \
  --report /secure/evidence/bootstrap-report.json \
  --version-tag <reviewed-bootstrap-tag> \
  --version-message <reviewed-bootstrap-message>

# Only inside the approved blank-account ceremony:
pnpm bootstrap:live -- \
  --report /secure/evidence/bootstrap-report.json \
  --version-tag <reviewed-bootstrap-tag> \
  --version-message <reviewed-bootstrap-message> --apply
```

`--apply` uses fixed reviewed config paths; arbitrary service names, routes, entrypoints, and migrations are not accepted. It deploys the private deny entrypoints first, using `src/bootstrap-worm.ts` for WORM, and then deploys the ingress deny entrypoint. The bootstrap uploads **no secret at all**: Cloudflare cannot retain a bootstrap copy of a later shared key, and the first shared keys are created only by the paired final authority ceremony. The command re-queries each exact version and its 100% deployment, verifies the final hostname deny matrix, and exclusively creates the canonical provider-observation report. An existing report path blocks reuse. A partial failure is safe and fail-closed but requires operator reconciliation; never blindly rerun it or delete the report to bypass the one-use guard.

After bootstrap, generic `wrangler deploy` is permanently forbidden. Upload final private versions through the immutable tooling, then use the paired four-service authority ceremony below. The bootstrap version is a lifecycle baseline, not activation evidence or rollback authority.

## Paired authority-key ceremony

Never provision the ingress/WORM shared key or either B2 credential independently. Prepare two different mode-`0600` canonical secret documents with exact byte shape `{"application_key":"…","key_id":"…"}\n`: the writer document must be the prefix-scoped `writeFiles` key, while the observer document must carry only the seven frozen list/read capabilities. Prepare separate canonical sanitized restriction-evidence documents; they bind the key-ID fingerprint, exact bucket, `receipts/v1/` prefix, exact capabilities, and `application_key_expiration_timestamp:null`, but they are not provider proof.

After the one-use lifecycle bootstrap, the paired command uploads the four reviewed final authority Workers in the exact effect order ingress → B2 observer → Cloudflare observer → WORM. This finite dependency order makes every downstream pin derivable from an already uploaded immutable version. In particular, WORM receives `WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY` as the exact `cloudflare-worker:<account>/<service>@<version>` identity of the read-only B2 observer; a signed caller header cannot choose or weaken that pin. WORM receives only its writer B2 credential, while the B2 observer receives only its read credential and the Cloudflare observer receives only its restricted provider credential. The command re-queries all four immutable versions. It uses only `versions upload --strict --secrets-file`; it never clones an implicit “latest” version:

```sh
pnpm authority-keys:provision -- \
  --input /secure/path/fresh-32-byte-key.bin \
  --cloudflare-observer-rpc-key /secure/path/fresh-cloudflare-observer-rpc-key.bin \
  --cloudflare-evidence-rpc-key /secure/path/fresh-cloudflare-evidence-rpc-key.bin \
  --admin-access-principals /secure/evidence/admin-access-principals.json \
  --writer-secret /secure/path/b2-writer.json \
  --observer-secret /secure/path/b2-observer.json \
  --writer-restriction-evidence /secure/evidence/b2-writer-restriction.json \
  --observer-restriction-evidence /secure/evidence/b2-observer-restriction.json \
  --cloudflare-observer-token /secure/path/cloudflare-observer-token.json \
  --cloudflare-observer-restriction-evidence /secure/evidence/cloudflare-observer-restriction.json \
  --cloudflare-observer-provider-policy-evidence /secure/evidence/cloudflare-provider-policy.json \
  --bootstrap-report /secure/evidence/bootstrap-report.json \
  --ingress-config /absolute/path/to/wrangler.live.jsonc \
  --observer-config /absolute/path/to/wrangler.worm-version-observer.live.jsonc \
  --cloudflare-observer-config /absolute/path/to/wrangler.cloudflare-deployment-observer.live.jsonc \
  --worm-config /absolute/path/to/wrangler.worm-mirror.live.jsonc \
  --result /secure/evidence/authority-version-ceremony.jsonl \
  --version-tag <reviewed-tag> --version-message <reviewed-message> --apply
```

Before the first upload, the command byte-verifies the canonical mode-`0600` one-use bootstrap report, including its explicit ingress/WORM lifecycle-migration projection, and proves that all four authority configs and final-entrypoint digests still equal the reviewed local bytes. The result is a mode-`0600`, hash-chained canonical JSONL journal: its creation, every `HOLD` transition, and the final record are fsynced. A failure leaves every durably known version ID in the last complete `HOLD` record.

If a process died after Cloudflare accepted an upload but before the next journal record was durable, rerun the **same** command with the same secret bytes, config bytes, tag, message, bootstrap report, and result path, adding `--recover`. Recovery verifies the complete journal prefix and all immutable fingerprints, discards only an unterminated tail, and queries the bounded provider version list. A matching version can be adopted only when that role has a prior fsynced `ABSENT` record with the exact predecessor upload state. It continues only when the effect is absent or exactly one matching version can be fully re-queried; multiple matches, a changed message, a broken chain, changed input authority, or a full ten-version provider window with no match remains `HOLD`.

Run the ceremony in an exclusive upload window: no other process may upload any of the four authority Workers until the journal is complete or reconciled. The bounded Wrangler list cannot prove historical absence once its ten-version window is saturated, so the command deliberately refuses to label that state `ABSENT`. Never delete the journal or start a second ceremony with the same tag to bypass reconciliation.

A success remains `READY_FOR_PRIVATE_PREFLIGHT`, not activated: the exact private writer authorization and observer authorization/list-bucket re-queries must still prove the restriction and bucket state before A0 or promotion.

`versions upload` is neither migration proof nor deployment proof. Before A0, deploy the exact final WORM version at 100%, re-query the provider until that one version is the exact observed 100% deployment, and run the closed internal `CloudflareEvidenceBatch` and `WormExactObjectEffect` journal smoke/requery. The smoke must prove durable journal recovery, a single writer dispatch, and exact observer-backed confirmation rather than merely obtaining a successful Worker response. Any version mismatch, traffic split, unconfirmed journal slot, divergent B2 object/version observation, or unavailable requery leaves the authority in `HOLD`; A0 must not start.

The command does not deploy any version. Generic `version:upload` is rejected for ingress, WORM, B2 observer, and Cloudflare observer so a secretless or credential-aliased candidate cannot bypass the paired ceremony. Every key and credential input must be an exact mode-`0600` regular file. Temporary Wrangler secret documents are mode `0600`, zeroed in memory where possible, and removed after each upload. No application key, authorization response, upload URL, or provider bearer is written to stdout or the ceremony journal.

## Version rollout

Outside the exact blank-account lifecycle bootstrap above, never use `wrangler deploy` for production. A reviewed live config must be an exact `wrangler.*.live.jsonc` file with an account ID, immutable service name, live mode, version metadata, disabled tracing, and no embedded secret. Upload one immutable version:

```sh
pnpm version:upload -- --config /absolute/path/to/wrangler.<service>.live.jsonc \
  --tag <reviewed-tag> --message <reviewed-message> --apply
```

Keep the current stable version in the deployment while staging the candidate at zero traffic:

```sh
pnpm version:deploy -- --config /absolute/path/to/wrangler.<service>.live.jsonc \
  --stable <stable-version-id> --candidate <candidate-version-id> \
  --message <reviewed-message> --stage --apply
```

Exercise the closed health/provider requery using an explicit version override. Promote only after the exact version identity and fault matrix pass:

```sh
pnpm version:deploy -- --config /absolute/path/to/wrangler.<service>.live.jsonc \
  --stable <stable-version-id> --candidate <candidate-version-id> \
  --message <reviewed-message> --promote --apply
```

Rollback uses the same reviewed config and explicit IDs with `--rollback`. It must never cross back to the one-use bootstrap lifecycle version. Do not evict a pinned private version while any activation epoch/recovery attempt references it.

## Ambiguous WORM write recovery

If SQLite append succeeded but WORM confirmation timed out, retry the exact same authenticated canonical request. A byte-identical existing row may finish mirror confirmation even after the original 15-minute ceremony window; a new or divergent body is still rejected. Never edit/delete the local row or choose a new object key.

## Verification

Run with exact Node and pnpm versions from `packageManager`/`engines`:

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm audit --prod --audit-level high
```

`pnpm check` includes project policy verification, formatting, lint, typecheck, PKCS conversion/fingerprint tests, unit/DO fault tests, and the real workerd candidate stream boundary.
