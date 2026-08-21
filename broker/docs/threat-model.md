# Threat model

## Protected assets

- Release receipt sequence/head, lease/fencing state, mutation intent consumption, and activation A0/A1 records.
- GitHub App private keys, B2 keys, installation tokens, upload capabilities, artifact signed URLs, webhook secrets, and Cloudflare admin identity.
- Exact provider observations and immutable WORM versions used to prove release authority.

## Trust boundaries and controls

| Threat                                  | Primary controls                                                                                                                                                                                                                                                                                                                                      | Failure behavior                         |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Forged/replayed Actions identity        | Exact issuer/audience/immutable subject/repo/workflow/ref/SHA/environment/run/check claims; provider check-run requery; global one-use JTI DO; 60-second token age                                                                                                                                                                                    | Reject before business mutation          |
| Stale lease or fence                    | Per-release SQLite DO; strict server time, 45/300 renewal cadence, monotonic fencing, and server-resolved current head/attempt/lease authority                                                                                                                                                                                                        | Reject and enter recovery/HOLD           |
| Provider credential exfiltration        | Credential-isolated private Workers; no token response; tracing disabled; bounded closed RPC                                                                                                                                                                                                                                                          | Service unavailable, no fallback token   |
| Version-override fallback               | Pre-effect self-version/identity check; A0 deployment membership; authenticated exclusive binding/capability required                                                                                                                                                                                                                                 | Reject before provider/B2 call           |
| B2 overwrite/delete ambiguity           | Deterministic key, Object Lock COMPLIANCE, exact version inventory/readback, digest/retention/SSE checks, delete/divergence rejection                                                                                                                                                                                                                 | No success response                      |
| Capability-bearing evidence persistence | Endpoint-classified raw retention; secret-field/signed-URL denylist; sanitized domain-separated projections                                                                                                                                                                                                                                           | Evidence entry rejected before WORM      |
| Oversized/stalled bodies                | Strict decimal Content-Length, exact EOF, byte/chunk caps, empty-chunk rejection, idle/absolute deadlines, cancellation                                                                                                                                                                                                                               | Canonical bounded error                  |
| GitHub/B2 response drift                | Exact repo/account/bucket/path/API/status/content-type/headers, JS-safe IDs, pagination bounds, no redirects/cookies                                                                                                                                                                                                                                  | Adapter returns 503                      |
| Compromised operator                    | mTLS plus Cloudflare Access, request replay consumption, two distinct allowlisted approvals over exact evidence root/A0 nonce                                                                                                                                                                                                                         | Activation remains unprovisioned         |
| Published control-plane metadata        | Synthetic Wrangler review templates; full-tree exact-UTF-8 scan; reject unclassified types/identifiers and secret artifacts                                                                                                                                                                                                                           | Publication fails before release         |
| Accidental provider command             | Exact exported mutation-symbol inventory; unconditional import-resolved HOLD at every production engine/helper before option snapshot/parsing/use, injected dependency/provider-port reads or invocation, secrets, temp state, journals, subprocesses, fetches, or clients                                                                            | `PROVIDER_MUTATION_HOLD`                 |
| Static-policy parser bypass             | Builtins-only trusted bootstrap; regular-contained files; exact 21-file byte/import closure before pinned Espree/eslint-scope load; exact exports/effect-data initializers/HOLD AST/call graph; typed ambient, filesystem, and I/O ownership; full simulation Program pins; denied dynamic code, loaders, injected callbacks, and unowned descendants | Preflight fails before production import |
| Test seam becomes an authority bypass   | Production graph cannot import test modules; exact simulations accept primitive JSON text only and have no callback, filesystem, subprocess, network, or provider capability                                                                                                                                                                          | Static/runtime gate fails                |

## Explicit unresolved activation blockers

- The schema-owner operation-sequence v2 vector and its typed request/response/error codecs are not yet mirrored. No generic caller-authored receipt body is permitted.
- `ReleaseLedger` still needs the vector-derived transactional state machine that resolves current head/attempt/lease/fence server-side, authors envelopes/IDs/timestamps itself, and implements idempotent typed candidate admission and mutation reconciliation.
- The historical C5/`CLOSED_CHECK_VERIFIED`/`LEASE_RELEASED` public-closure design is quarantined. The clean controller's terminal internal `CLOSED` state is not public closure authority. Runtime closure remains unavailable until a separately approved new public-projection contract replaces or explicitly retires those old selectors.
- Complete live GitHub Actions/environment/ruleset/App and B2 provider observations must be captured into A0. Commit-A blob/tree evidence is already independently recomputed; the remaining observations cannot be substituted with operator assertions.
- The tracked Wrangler live-shaped files are synthetic publication review templates. A reviewed custom Cloudflare hostname, account/zone, Access/mTLS identifiers, GitHub App identifiers, B2 bucket/key observations, and current deployment observations are not present in the publishable candidate.
- Source inspection does not establish whether a historical Worker exists. Only dated, independently retained provider evidence may make that claim.
- The exact historical receipt fixture remains a config-integrity input only. Its pre-HOLD public-closure variants are not runtime closure authority.
- The quarantined production mutation implementation is intentionally unreachable and is not
  exercised through an authorization bypass. A lift requires a newly reviewed production adapter
  and isolated provider-effect verification; passing the declarative trace models is insufficient.
- Module loading may establish static import bindings, and native direct-entry detection may inspect
  only `process.argv[1]` and invoke native path/URL comparison helpers before dispatch. Those
  operations do not snapshot, parse, or use CLI options or invoke injected dependency/provider
  ports. Every exported production `main` enters the HOLD as its exact first statement,
  before the function can create its own frozen snapshot of `process.argv.slice(2)`.
- The static quarantine proves reviewed syntax and graph ownership under an explicit denied-feature
  model and a trusted pinned Node startup. Its builtins-only bootstrap root cannot self-hash; it
  verifies the exact policy closure before loading trusted installed parser dependencies. The proof
  does not cover `NODE_OPTIONS`, preload/custom-loader execution, a malicious or prototype-poisoned
  runtime, adapter semantics, provider readiness, or a malicious simultaneous edit of the trusted
  bootstrap and checked source. Any bootstrap, production, or policy change therefore requires
  independent semantic review.

These are availability/security interlocks, not warnings. Production mutation endpoints must remain unavailable until every blocker has a negative test and an immutable activation evidence pointer.
