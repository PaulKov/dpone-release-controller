# Activation component manifest v2 — candidate contract

Status: **HOLD / non-authoritative**. The modules described here are pure codecs, deterministic
builders, a version-scoped local journal, a closed local semantic validator, and a dependency-
injected confidential resolver. No HTTP route, B2 credential/provider adapter, activation record,
snapshot verifier, or global-head path consumes them yet. The existing v1 schemas remain
fail-closed.

## Why this candidate exists

The checked-in production-valid A0 request generator is 71,403 canonical UTF-8 bytes, 1,426 JSON
value nodes, depth 9, and a 132-byte maximum string. It deliberately exceeds both the 65,536-byte
and 512-node private boundaries. The exact golden is generated and asserted by
`test/activation-component-payload-fixture.test.ts`; it is not copied from an ephemeral audit
script. Raising the global limits would hide duplicated authority data and would expand every
private parsing surface.

The candidate therefore stages the large A0 inputs as 15 exact components, stores every component
under immutable WORM authority, stores a separately sealed component manifest, and lets compact A0
carry only the final manifest pointer. The candidate confidential resolver fetches and verifies the
manifest and every component before its closed kind-specific parser derives runtime trust; no live
provider adapter invokes that port yet.

## Fixed staged flow

1. The caller computes the 15 canonical payload digests locally and submits the small set roster.
2. The broker validates the complete, ordered roster and freezes one broker clock in a set
   descriptor. The exact descriptor is durable before any component effect.
3. Each later request carries one exact component envelope. The envelope binds the descriptor ID,
   descriptor raw SHA-256, semantic set ID, component kind, and payload digest. The journal stages
   the exact bytes for all 15 components without performing an external write.
4. Only after the full roster is present, the broker runs every closed kind-specific parser and all
   cross-component coherence checks. It then atomically selects one winner and seals all 15 generic
   exact-object effect plans before the first WORM dispatch. Invalid or missing component 15
   therefore cannot leave 14 irreversible orphan effects.
5. The broker executes the sealed effects and, after all 15 confirm, builds a manifest entirely from
   the descriptor, exact envelope bytes, and exact canonical generic-effect results. Each result is
   reparsed against its recomputed sealed effect and converted to an opaque branded confirmation;
   the authoritative manifest builder does not accept caller-supplied WORM scalars.
6. The manifest is itself written through a separate generic exact-object effect. Compact A0 stores
   only `{manifest_id, manifest_sha256, worm}`. The pointer builder likewise accepts only the
   revalidated branded manifest confirmation and returns owned canonical bytes plus an explicit
   `UNTRUSTED` wrapper.

The final local journal authority is minted through a module-private `WeakMap`; a structural
`CONFIRMED_JOURNAL` object is not authority. Its public snapshot boundary requires that private
identity, reparses fresh owned descriptor and pointer bytes, and recomputes their session/digest
bindings. Exact retries of the original selection operation rebuild the same all-15 effect plan in
every later selected state, including either terminal HOLD, without changing or rearming any effect.
SQL guards also forbid deleting selected entries/session state, the singleton selection, or a
persisted manifest authority.

The journal admits at most four live and eight lifetime sessions per worker version, with a 900-second
provisional TTL. Generation 1 is immutable. Only an incomplete generation that durably becomes
`ABANDONED` with the exact expiry code may receive its one predecessor-bound successor; that
successor has a new descriptor identity and object-key namespace. Nothing is rewritten in place.
`REJECTED`, selected, or effect-sealed sessions cannot reissue, and delayed retries always recover
their original generation.

No transport request ID, admin replay JTI, Access assertion, HTTP clock, or B2 version ID
participates in semantic set identity. Confidential OIDC rehearsal `jti_sha256` values are retained
inside the `oidc` component and therefore do participate in payload and set identity.

## Closed roster

`component_profile` is `A0_INPUT_V1`; `activation_sequence` is `0`. The order is normative:

1. `admin_access`
2. `b2`
3. `broker_core`
4. `controller`
5. `controller_governance`
6. `github_apps`
7. `oidc`
8. `service_authority_header`
9. `service_authority_inventory`
10. `service_authority_a0_deployments`
11. `service_authority_a1_deployments`
12. `service_authority_network`
13. `service_authority_receipt_bindings`
14. `target_governance`
15. `trusted_publishers`

The authority inventory exists exactly once. `broker_core` contains no `private_services` copy.
Closed GitHub-app, deployment, network, and broker reconstruction derives duplicated authority
fields from that normalized inventory and reruns the existing production validators and digests.

## Descriptor and identities

The v2 descriptor contains:

```text
schema, schema_version, activation_sequence, component_profile,
component_set_committed_at, component_set_id, worker_version_id,
components[{component_kind,payload_sha256}], descriptor_id
```

`component_set_id` is a domain-separated digest over profile, sequence, worker version, and the
ordered kind/payload-digest roster. `descriptor_id` is a second domain-separated digest over the
complete descriptor core excluding itself. `descriptor_sha256` is the raw SHA-256 of the complete
canonical descriptor including `descriptor_id`.

The committed clock is deliberately excluded from `component_set_id`, but it is included in both
descriptor identities. A different clock therefore produces a different descriptor, component IDs,
envelope bytes, and object keys. A journal must never replace a descriptor in place.

## Component envelope and key

Every stored component uses schema `dpone.release-activation-component.v2` and contains:

```text
schema, schema_version, activation_sequence, component_profile,
component_set_id, component_set_descriptor_id, component_set_descriptor_sha256,
worker_version_id, component_kind, component_id, payload_sha256, payload
```

`component_id` binds the set ID, descriptor ID, descriptor raw SHA, profile, sequence, worker
version, kind, and payload digest. The exact WORM key is:

```text
receipts/v2/activation-components/<worker-version>/<set-id-hex>/
  <descriptor-id-hex>/<descriptor-sha-hex>/<kind>/<component-id-hex>.json
```

The WORM digest must equal the SHA-256 of the full canonical envelope. Payload digests alone are never
accepted as activation pointers.

## Manifest and compact A0 pointer

The manifest repeats the frozen descriptor bindings and contains the ordered 15 entries:

```text
component_kind, component_id, payload_sha256, envelope_sha256,
worm{digest,key,retention_until,version_id}
```

`manifest_id` is a domain-separated digest over the complete manifest core excluding itself.
`manifest_sha256` is the raw SHA-256 of the complete canonical manifest. The manifest object key is:

```text
receipts/v2/activation-component-manifests/<worker-version>/<set-id-hex>/
  <manifest-id-hex>/<manifest-sha-hex>.json
```

The compact A0 pointer contains only the manifest ID, full SHA, and exact WORM pointer. Generic parse
results are labelled `UNTRUSTED`; syntax and digest validation do not imply that any component is an
acceptable admin, governance, deployment, or authority document.

Candidate effect preparation injects an exact v2 object-key predicate into the shared generic-effect
preparation core. The existing runtime/default wrapper still applies only the v1 allowlist. This pure
seam neither enables a v2 route nor grants a provider credential.

## Confidential resolver boundary

The pure resolver accepts the exact compact pointer bytes sourced by its caller and derives both
namespace prefixes internally. Its specialized read port cannot request an arbitrary object key.
The port returns a complete, non-paginated manifest-prefix snapshot bounded to two versions and a
complete descriptor-prefix snapshot bounded to sixteen versions. The resolver requires exactly one
manifest version and exactly fifteen component versions: no old, hidden, deleted, duplicate,
non-latest, extra, or paginated entry is accepted.

Every response is synchronously converted from data descriptors into owned plain values before the
first digest await. The bucket snapshot distinguishes the Backblaze bucket ID/name from the
authenticated Cloudflare reader-authority account; `cloudflareAccountId` is explicitly not a
Backblaze account identifier. A future adapter must source that account from its authenticated
service authority, while independently observing the provider bucket metadata. The resolver checks
both identities and the private bucket posture, JSON content type, SSE-B2 encryption, exact size,
SHA-1, SHA-256, WORM key/version/retention, and sole-latest status. It then reparses the manifest,
rebuilds the descriptor solely from the manifest roster, reparses all 15 envelopes in normative kind
order, and runs the same closed cross-component semantic reconstruction used by journal selection.
The manifest version ID may not be reused by a component. Historical ingress identity is derived
from the pointer worker version, the fixed ingress service name, and the trusted account; it is
independent of the current resolver worker version or authentication pins.

The production-valid compact semantic projection is a checked-in candidate golden of 6,160 bytes,
96 nodes, depth 4, a 279-byte maximum string, and SHA-256
`sha256:26926bbf4ab158b469d34b260c15ca836cb412311292c9a6f52c7d90f0f6fddf`. This digest is an
executable drift detector for the candidate, not a frozen public schema commitment. The projection
contains only the component-set/manifest authority and the derived runtime trust projection; raw
provider evidence, payloads, rehearsal JTIs, admin principal commitments, and component bodies are
not returned. The public structural parser remains untrusted. Only the resolver mints the private
`RESOLVED_SEMANTICS` result, whose canonical bytes are re-owned on every access and reparsed by its
snapshot boundary.

`RESOLVED_SEMANTICS` deliberately does **not** prove that this pointer won the operation journal or
belongs to a particular A0 record. Future materialization must cross-bind the exact pointer and
descriptor to the journal-selected operation; a future outer verifier must source that pointer from
the authenticated immutable record. Resolver success alone cannot authorize A0 selection.

## Budgets

- Component payload: at most 60,000 bytes, 384 nodes, depth 14, and 32,768 bytes per string/key.
- Full component envelope: at most 65,536 bytes, 399 nodes, depth 16.
- Descriptor and manifest: at most 65,536 bytes, 512 nodes, depth 16.
- Every byte array is bounded through intrinsic typed-array length/copy operations before the first
  asynchronous digest; caller-defined `byteLength` and iterators are never allocation authority.
- All WORM retention must cover at least 2,557 days from the frozen set clock.

The measured candidate manifest fixture is 13,504 bytes and 162 nodes. The earlier modeled compact A0
core, including a derived 14-role runtime-trust projection and a 15-anchor Cloudflare manifest, is
24,990 bytes and 389 nodes. These are design measurements, not frozen live schema vectors.

The checked-in production-valid generator normalizes the oversized request into exactly 15 payloads
totalling 49,786 bytes. The largest payload is 9,485 bytes and 160 nodes; the deepest is depth 7; the
largest string/key is 132 bytes. The ordered per-kind payload and full-envelope golden vectors are
asserted in `test/activation-component-payload-fixture.test.ts` and
`test/activation-component-payload.test.ts`. Every row is also checked independently against the
normative limits above, so compensating size drift cannot hide a changed component.

## Required integration work before removing HOLD

- Keep the implemented candidate journal authority chain intact: it stores and reparses all 15 exact
  generic-effect results, seals the deterministic manifest effect under the selected pins, stores its
  exact result and canonical pointer atomically, and rebuilds the complete chain on every confirmed
  read. Its bounded generation rule remains unchanged: only an incomplete expired generation may
  create its unique predecessor-bound successor; no descriptor is ever replaced in place, and no
  rejected, selected, effect-sealed, held, or confirmed session may reissue.
- Keep the implemented closed kind-specific parsers and cross-component validator as the sole local
  semantic acceptance boundary. Generic descriptor, envelope, manifest, and pointer parsing remains
  explicitly `UNTRUSTED`.
- Add the reviewed confidential namespace-reader provider adapter without weakening the pure
  resolver contract. Mutable SQL and caller-provided projections are not resolver authority; the
  adapter must stream-cap bodies and independently observe bucket/version metadata.
- Add compact A0/A1 v2 builders and a snapshot/global-head verifier that resolves components. Do not
  reconstruct or accept the oversized v1 envelope.
- Review B2 credentials and prefix restrictions. `b2-native-provider`, WORM configuration, observer
  configuration, and the current generic exact-object allowlist all hard-code `receipts/v1/`.
  Enabling `receipts/v2/` requires a separate reviewed credential/prefix ceremony (or an explicitly
  reviewed common prefix) plus an authority-expectation update. This candidate does not widen them.
- Preserve the candidate journal's local crash/concurrency matrix when adding the remote runner, and
  add end-to-end tests for generic-effect response loss, exact resolver reads, and final HTTP response
  loss before any schema or golden freeze.
