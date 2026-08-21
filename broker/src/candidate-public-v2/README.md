# Candidate public-v2 pure codecs

Status: **candidate only, integration HOLD, not a schema or authenticity freeze**.

This directory is deliberately isolated from broker routes, registries, private WORM records,
provider adapters, generated schemas, and frozen hashes. Its outputs are syntax-checked and
self-consistent but remain `UntrustedPublicV2`. There is no exported `Accepted` type or
constructor.

## Authenticity boundary

A canonical self-ID, raw digest, sidecar commitment, or deterministic ZIP proves only local
byte integrity. It does not prove broker authorship, private policy semantics, protected-branch
lineage, or successful activation. An accepted object may eventually be constructed only by an
authenticated direct broker/runtime-gate transport adapter that cross-checks the exact response
received in that exchange. That adapter does not exist in this candidate. Offline acceptance is
therefore unavailable, and a caller-invented but self-consistent document must remain untrusted.

The response-header adapter is also out of scope. Edge-added header names and normalization must
be frozen from a live rehearsal of the actual hostname; arbitrary widening is forbidden. No
request ID, tracing ID, reservation ID, JTI, WORM anchor, generation/head ID, key/cert ID, or
other control-plane field belongs in public bytes.

## Canonical JSON and identities

`canonical.ts` accepts only non-empty canonical UTF-8 byte documents up to 65,536 bytes. It
rejects a BOM, invalid UTF-8, non-canonical raw bytes, floats, unsafe integers, lone surrogates,
non-ASCII keys, sparse/extended arrays, symbols, accessors, non-enumerable properties, and
non-plain object prototypes. Frozen plain DTOs are accepted. Object keys use ascending ASCII
order. Strings use lowercase `\u00xx` for remaining controls, the short JSON escapes where
defined, and no escaping of solidus, non-ASCII, U+2028, or U+2029.

Identities are lowercase tagged digests:

```text
ID(domain, payload) = "sha256:" || hex(SHA-256(C({"domain": domain, "payload": payload})))
RAW(document)        = "sha256:" || hex(SHA-256(C(document)))
```

The domain is printable ASCII, 1..128 bytes, without NUL. A0, A1, proof, closure, release,
activation, inventory, authority, and candidate identities each have distinct domains in their
own codec.

## Private sidecar commitment

Each logical issuance receives one broker-generated, non-zero 32-byte random nonce `N`. `N`,
the opening, and the private payload remain confidential and must never be serialized into a
public document or ZIP. The public document carries only the opaque commitment.

The committed sidecar `S` is canonical JSON with this closed field set:

```text
kind, private_payload_schema, private_payload_sha256,
public_context_sha256, schema, schema_version
```

`kind` has one runtime source (`SIDECAR_KINDS`) and maps to exactly one private payload schema.
The public context is the exact document base before adding its document-local commitment and
terminal self-ID. Embedded A0/A1 documents are not stripped.

The commitment framing is unambiguous:

```text
ASCII("dpone.release.private-sidecar-commitment.v2")
|| 0x00
|| U32BE(32)
|| N
|| U64BE(len(C(S)))
|| C(S)
```

The public value is `"sha256:" || hex(SHA-256(frame))`. Verification derives the commitment
only from `publicDocument.private_sidecar_commitment`; a separately supplied commitment is not
accepted. The terminal field and document schema are derived from `kind`, never caller-selected.

`nonceFingerprintSha256 = SHA-256(N)` is only a candidate-private diagnostic fingerprint. It is
not a frozen durable uniqueness key and has no effect on public-v2 bytes.

## Public records and closure

- A0 (`provisioned`) is sequence 0 with `previous = "GENESIS"`. Its controller action commit
  must differ from the controller workflow commit (`A != P`).
- A1 (`activated`) is sequence 1 and links exactly to A0 by both `previous` self-ID and raw A0
  digest. `baseline_source` is a reusable epoch baseline.
- The activation proof embeds exact A0/A1 records and raw digests. Its injected clock is floored
  to UTC seconds; expiry is exactly 60 seconds later. Callers cannot author proof time.
- The runtime closure binds the fixed four-project release identity, exact eight distribution
  rows, activation identity, controller action, and baseline policy/workflow blob and raw digests.

There is **no public constraint between release peeled commit R and baseline commit C5**. R may
equal C5 or be a protected descendant. The private runtime gate must prove `identical|ahead`,
behind=0, merge-base, and protected-default-branch lineage. The hard public inequality remains
controller action A != controller workflow P.

Source SHAs in this candidate are non-secret opaque content anchors. They are not an offline
provider provenance proof. No repository/provider fact is inferred by these codecs.

## Deterministic archive

The public archive owns exactly this order and no caller-selectable names:

1. `activation-a0-public-core-v2.json`
2. `activation-a1-public-core-v2.json`
3. `runtime-closure-public-v2.json`

The ZIP uses STORE only, flags 0, version-needed 20, made-by `0x0314`, DOS time `0x0000`, DOS
date `0x0021`, internal attributes 0, external attributes `0x81a40000`, no extras/comments/data
descriptors/trailing bytes/ZIP64, exact CRCs/sizes/offsets, and one EOCD. Raw and aggregate
expanded sizes are each at most 65,536 bytes. Size checks occur before copies or allocations.
Parsing the ZIP re-runs all A0/A1/closure semantic links and still returns untrusted values.

## Retry lifecycle and integration HOLD

`replay-state.ts` is a pure transition/reference model, not persistence authority. It enforces:

```text
RESERVED_NO_EFFECT -> PRIVATE_FROZEN -> PRIVATE_WORM_IN_FLIGHT
-> PRIVATE_WORM_CONFIRMED -> PUBLIC_FROZEN -> PUBLIC_EFFECT_IN_FLIGHT -> CONFIRMED
```

Only `RESERVED_NO_EFFECT` can cancel. Ambiguous private WORM activity enters `HOLD_PRIVATE`.
Ambiguous public dispatch enters `HOLD_PUBLIC`; it can perform observer-only reconciliation and
must never re-dispatch the effect. A retry must reuse byte-for-byte nonce, canonical private
payload, opening, and public document.

Before any route can use these builders, a separate reviewed durable layer must atomically bind
an intent and issuance ordinal, reserve a domain-separated nonce-uniqueness key, persist the
frozen private/public bytes and state, enforce expiry/reissue policy, and recover ambiguous
effects. None of those authorities is simulated here. Every builder result therefore says
`UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE`.

## Verification

Focused tests are named `test/candidate-public-v2-*.test.ts`. They cover canonical collision and
descriptor canaries, mutation races, split commitment authority, wrong private schema, A0/A1
cross-links, clock bounds, R==C5 and R!=C5, fixed-project request identity, every ZIP metadata
covert channel, replay transitions, uniform errors, trust non-upgrade, and a hard-pinned
deterministic TypeScript candidate vector. A Python mirror and reviewed durable journal schema
are still required before calling any vector cross-language or frozen.
