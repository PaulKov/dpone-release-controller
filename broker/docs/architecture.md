# Release authority broker architecture

This directory describes the fail-closed Cloudflare release-authority broker. It contains route-less provisioning configs and fourteen `wrangler.*.live.jsonc` **publication review templates**. The templates describe the intended binding graph but carry only classified synthetic account/provider identifiers, an `.invalid` hostname, and no secrets. The shared `DPONE_PROVIDER_MUTATION_HOLD_V1` source guard rejects every executable provider mutation before real adapters or ceremony secrets are reached. A future deployment is not release authority until its append-only A0/A1 activation epoch has been independently verified and WORM-confirmed.

## Isolation model

- The public ingress verifies route-specific GitHub Actions OIDC and owns only Durable Object bindings. It has no GitHub App private key and no B2 key.
- `ActivationRegistry`, `AuthReplayLedger`, and per-release `ReleaseLedger` use distinct SQLite Durable Object namespaces. GitHub OIDC replay authority is global across routes/releases.
- Private Workers have one credential role each. Candidate, controller-run, governance, WORM writer, and WORM observer roles are separate services and versions. Mutation services remain unavailable until their one-use capability and receipt schemas are frozen.
- Every private call is version-bound. Read-only calls verify the returned Worker version. A side-effecting Worker must verify its own expected immutable version before reading the body or contacting a provider.
- The B2 writer has only `writeFiles`. The observer has exactly `listBuckets`, `listFiles`, `readBucketEncryption`, `readBucketReplications`, `readBucketRetentions`, `readFileRetentions`, and `readFiles`. Neither role can delete, bypass governance, or change retention.

## Activation evidence

Large provider observations are not embedded in SQLite or A0. Each closed evidence entry is independently canonicalized, WORM-written, exact-version downloaded, and retention-confirmed. A0 will contain a small ordered manifest of immutable object pointers and projection digests once the cross-repository manifest schema is frozen.

Raw bytes are endpoint-classified:

- Safe, fixed, read-only endpoints such as GitHub OIDC customization may retain bounded raw response bytes.
- Credential or capability responses never retain raw bytes. This includes B2 authorization/upload URLs, GitHub installation tokens, and artifact redirect URLs. Their adapters emit only closed sanitized projections.
- `Authorization`, `Set-Cookie`, `Location`, bearer/token fields, upload URLs, and signed query strings are forbidden from evidence, logs, traces, WORM objects, and errors.

WORM calls use a paired immutable-version ceremony. The ingress key version is created first; its exact Worker version is compiled into the WORM caller identity, and the same fresh HMAC key is injected into a new undeployed WORM version. The WORM Worker authenticates the canonical request before reading evidence bytes or calling B2. Caller-set identity headers alone are never accepted.

Commit A is not trusted from an administrator-supplied digest. During A0, the pinned controller reader walks the exact Git commit and non-recursive tree chain, downloads only the six schema-owned executable blobs, recomputes each Git blob SHA-1 and raw SHA-256, and returns a credential-free canonical observation. Ingress compares that observation to the submitted canonical inventory before A0 is appended and WORM-confirmed.

## Transaction and network boundary

SQLite transactions decide sequence, lease/fence, replay, intent consumption, and append-only state. Provider/B2 network I/O never occurs inside a SQLite transaction. A successful authority response is returned only after its canonical receipt bytes are committed and the exact B2 version is read back and retention-confirmed. Ambiguous provider outcomes are reconciled from provider state and never retried blindly.

## Current safe state

The activation proof, receipt-independent provider readers, bounded candidate stream, exact Commit-A inventory, B2 v4 WORM adapters, and immutable rollout algorithms are implemented and tested through explicit fake effect ports. Selected-actions policies are exact full-SHA arrays derived from Commit A; wildcards are rejected. Public mutation and typed receipt/lease routes remain `503` until the schema-owner operation-sequence vector and transactional `ReleaseLedger` implementation match byte-for-byte. The former C5/check/lease public-closure design is a quarantined historical prototype. The clean controller currently ends at internal `CLOSED`, which is not public closure authority; the runtime closure route remains `503` until a separately approved new public-projection contract replaces or explicitly retires the old selectors.

The tracked review templates are deliberately unresolved and cannot be promoted by any production-bound command in this candidate. Repository inspection cannot prove whether any historical Worker exists in a provider account; deployment state must be established by dated provider observation, never by a source-code claim.

The pinned `release-receipt-envelope-v2` fixture is exact historical input, not current authority. It preserves the pre-HOLD broker receipt contract, including public-closure variants subsequently removed or quarantined by the clean controller line. Config integrity verifies its bytes, while runtime wiring continues to deny closure and public mutation.
