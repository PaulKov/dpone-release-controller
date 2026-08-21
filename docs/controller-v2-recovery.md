# Controller v2 execution and recovery proposal — INACTIVE / HOLD

Status: **INACTIVE / PROPOSED / HOLD — DO NOT OPERATE OR DEPLOY.** No production
controller-v2 service, public closure contract, runtime promotion path, or
effect-bearing route is activated by this document. Except where a paragraph
explicitly describes the current fail-closed HOLD, the requirements below are
future design constraints and must not be read as claims about deployed state.

If separately approved and activated, the production workflow commit (`P`)
would execute only through an immutable, protected, annotated controller tag.
The exact `refs/tags/vMAJOR.MINOR.PATCH` ref, tag-object SHA, peeled commit SHA
(`P`), workflow id/path/blob, ruleset evidence, and no-bypass evidence would be
recorded in broker provisioning record A0. The future controller would never
create, move, or delete that tag.

Every future admission would use fresh OIDC and provider observations. It
would require:

- `workflow_dispatch` on the exact A0 tag;
- `GITHUB_REF` and `workflow_ref` equal to that tag and workflow path;
- `GITHUB_SHA` equal to A0's peeled commit `P`;
- an annotated tag object distinct from `P`; and
- the production workflow path still present on the current default branch.

The last condition would be a GitHub dispatch-availability requirement, not
release authority. `master` could advance after `P`; recovery would continue
from the A0 tag. However, the workflow file would have to remain at the same
path on the default branch until every attempt for that epoch was durably
`CLOSED` or `ABORTED`. The broker would re-read the default-branch blob on
every admission. A missing path, mutable branch dispatch, tag mismatch, or
stale A0/A1 proof would fail closed.

## Public closure and runtime HOLD

The current source state deliberately exposes no public closure contract. The
controller's private receipt ledger may finish atomically at internal
`CLOSED`, which is terminal and releases the active lease, but it cannot build,
verify, upload, project, or route a public closure artifact. Public marker,
closure, and runtime modules return the stable
`PUBLIC_CLOSURE_CONTRACT_NOT_FROZEN` failure before inspecting caller input.

No closure/runtime operation, broker route, wire codec, schema, golden fixture,
or generator output is active. This HOLD has no environment-variable or caller
override. Lifting it requires a separately reviewed public field allowlist,
authenticity anchor, frozen byte contract, privacy canaries, and regenerated
schemas and vectors. Confidential receipt, service, and provider models are not
an acceptable substitute for that review.

## Public activation identities and confidential evidence

The broker's current v1 A0 and A1 envelopes are confidential control-plane
records. They contain identity commitments and provider identifiers whose
disclosure is incompatible with a public closure artifact. The controller must
not import them into, or reproduce them through, a public receipt or closure
member. A redacted v1 envelope is not an authority record because its identity
was computed over the complete confidential bytes.

Any future publication boundary would require separately frozen v2 public-core
A0 and A1 identities. Their canonical allowlisted bytes would contain an
opaque, nonce-salted commitment to the confidential sidecar; the nonce and
sidecar would remain broker-internal unless an explicitly authorized audit
retrieved them. The public record identifier would derive only from the
public-core envelope, so its integrity could be checked without private
preimages or control-plane IDs. That self-derived identifier and the salted
commitment would **not** prove broker
authorship. The A1 public core would chain to the A0 public core without
duplicating the private evidence tree.

Every future public-core envelope would be capped at 65,536 bytes before JSON
decoding. Duplicate keys, non-canonical JSON, an invalid self-derived
`record_id`, and an invalid full canonical record digest would be rejected.
Parsing would yield an explicitly untrusted transport document. These transport
and hash checks would not grant authority by themselves: the exact v2 semantic
parser, public A1-to-A0 chain, sidecar commitment, chronology, and
broker-authenticated private validation would all have to succeed inside the
pinned HTTPS route and exact OIDC audience/environment exchange. A detached or
copied document would fail with
`UNAUTHENTICATED_PUBLIC_CORE` unless a separately reviewed immutable public
provenance mechanism accompanies it. No such signing or immutable provenance
anchor is currently frozen. No transport adapter may construct an accepted
public-core value while the HOLD is active; a future adapter would require the
exact authenticated broker/runtime-gate boundary. Until the v2 schemas,
goldens, sidecar commitment ceremony, public receipt projection, and
authenticity boundary are byte-frozen, the controller keeps closure generation
and every effect-bearing route unavailable.

The proposed content-pinned GitHub Artifact Attestation boundary is specified
in [`public-authenticity-anchor.md`](public-authenticity-anchor.md). It closes
the archive subject, repository, workflow, source-ref/source-commit certificate
claims, and Sigstore bundle verification contract. The annotated tag object,
its peeled commit, protection and no-bypass evidence remain a separate A0
proof. The boundary stays inactive until a real archive and bundle,
out-of-band trusted root, reviewed verifier version/digest, OS-level no-network
execution record, independent environment approval, and A0 admission are
reviewed together. Merely landing that verifier does not freeze public closure
bytes or authorize an attestation-producing workflow.

If a future public closure is approved, it must never contain the broker's raw
receipt chain. It may carry only a frozen, allowlisted public projection and
aggregate commitments as untrusted transport. No runtime acceptance path
exists while the HOLD is active.

Actor, subject, JTI, certificate, Access, B2, GitHub App, Cloudflare
account/service/version/deployment/storage, request, run, check, and artifact
control-plane identifiers would remain in the confidential ledger and evidence
sidecars.

Any approved implementation would enforce this separation as an import
boundary, not as a best-effort redaction pass. Public activation, marker,
closure, runtime-verification, and wire modules could depend only on
public-core contracts and generic canonical or archive primitives. They could
not import raw receipt-envelope, private service activation/inventory, or
provider-control-plane models. HOLD tests seed calls
with confidential canaries and prove rejection occurs without importing or
decoding private models. They also require legacy schema IDs and generated
artifacts to remain absent. Any later transport format and response-header
policy would require a new reviewed contract before code activation.

The proposed version-scoped A1 record would not, by itself, prove that the
version was still the active account-wide authority. Before admission or any
provider effect, the broker would have to read a monotonic account-global
activation-head witness from its Durable Object, prove its immutable WORM
version, and bind the fresh read to the request. A long-lived witness would not
expire merely because time passed; the freshness window would apply to the
current-head read. Generation rollback, a generation gap, a reused A1 or
ingress version, a wrong predecessor, and a detached generation scalar would
all fail closed. Until the exact broker head
schemas, goldens, and current-state RPC are byte-frozen and imported, all
effect-bearing controller routes remain unavailable.

Recovery would roll to a new attempt and strictly higher fencing token while
keeping the same release authority and queue entry. Existing provider state
would be reconciled before a new one-use mutation intent was issued. Advancing
`master` would not authorize newer code for the old release, and deleting the
workflow path could not silently abandon a partially published release.

## Frozen candidate and PyPI byte budgets

The proposed candidate admission contract would mirror the target producer
schema byte-for-byte and pin its SHA-256 in
`config/release-controller-v2.json`. The proposed provider ZIP budget would be
25 files, 256 MiB per member, and 768 MiB in aggregate. Inside that envelope,
every `dist/` wheel or sdist would be limited to exactly 100,000,000 bytes and
the ordered eight-file distribution matrix would be limited to 512 MiB. Those
same constants would be enforced again when mutation intents and provider
upload receipts were validated, so an admitted candidate could not be widened
at the publication boundary.

## Commit-A identity under HOLD

The internal `CLOSED` receipt may retain commitments to a separately reviewed
controller action bundle, without making those commitments a public marker or
runtime authority. There is no executable runtime-closure route, request,
response, or promotion verifier in the current contract. Any future Commit-A
exchange must be reviewed together with the public authenticity anchor and
cannot be enabled merely by presenting existing private-ledger commitments.

## Ordered typed operations

`release-controller-operation-profile-v2.json` is the checked-in proposed
workflow/broker action contract. If activated, each operation would fix its
job, environment, ordered phases, methods, paths, OIDC audiences,
request/response schemas, effects, and receipt kinds.
The workflow would supply only the operation ID and its declared immutable
selectors. It could not submit an envelope, ledger head, lease, fence, producer,
committer, timestamp, broker URL, or arbitrary body.

Candidate admission would be one audited state machine: stream the provider
artifact, deep-verify the exact raw ZIP and all 25 semantic members locally,
then submit typed candidate evidence. The broker would derive current ledger
state and author the CANDIDATE_HANDOFF receipt. Later publication jobs would
re-stream the same target artifact under fresh authorization and re-run the
verifier; it would not be copied into a second controller artifact. Cross-job
outputs are non-authoritative UX hints only. Under the public closure HOLD, the
operation registry ends at the internal `CLOSED` append and defines no closure
artifact or runtime transport.

## Fresh provider-effect authority

Every one of the eight proposed mutation operations would consume exactly one
fresh, operation-bound authority guard. The guard would bind the admitted
intent subject, attempt, lease, fence, activated-authority head, WORM-mirrored
deployment observation, permission-scoped service, and provider observation.
It would contain no bearer token or portable capability. Provider observation,
broker acceptance, durable consumption, and dispatch would all have to occur
inside the closed 60-second guard window.

Private mutators would also have to durably record their provider outcome
before that window closed. The proposed sole runner-executed effect, PyPI
trusted publishing, would use a distinct `GITHUB_ACTION_DISPATCH` guard. Its
consumption receipt would be the durable one-shot dispatch reservation: the
provider requery could finish after the guard expired only while the same
attempt, lease, and fence remained active. A timeout or ambiguous provider
result would never permit a second dispatch. Recovery would re-query first and
either bind the original
consumption to the observed exact outcome or enter HOLD; a new intent would be
possible only after the provider conclusively proved absence and the broker
issued new fenced authority.
