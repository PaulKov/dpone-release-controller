# Compact activation records v2 — isolated candidate

## Status and scope

This document describes the isolated compact-v2 structural slice in
`src/activation-record-v2-*.ts`. The slice is deliberately not connected to activation routes,
Durable Object storage, provider clients, runtime configuration, or the confidential component
resolver.

Every builder and parser returns `trust: "UNTRUSTED"`. Passing these parsers proves only that a
canonical document has the closed v2 topology and internally consistent identities. It does not
prove that a journal selected the component set, that the resolver accepted its semantics, or that
the WORM objects exist.

## Self-service API

- `buildActivationProvisionedRecordV2(body)` builds an A0 document and derives its self-ID.
- `buildActivationActivatedRecordV2(body)` builds an A1 document and derives its self-ID.
- `parseActivationRecordV2(bytes)` accepts only the two v2 record schemas.
- `parseActivationRecordV2Chain(a0Bytes, a1Bytes)` additionally cross-binds A1 to A0.
- `activationRecordV2FullDigest(bytes)` returns the digest of the complete canonical document.
- `activationRecordV2WormKey(worker, sequence, digest)` derives the candidate record key.
- `isActivationRecordV2WormKey(key, expected?)` is the isolated candidate key policy.
- `activationRecordV2Budget(value)` reports canonical bytes, nodes, depth, and maximum key/string
  sizes.

Inputs must be plain data. Builders reject accessors, non-plain objects, sparse arrays, unsafe
numbers, oversized strings, and over-budget structures. Parsers enforce the byte cap before copying
the supplied `Uint8Array` and reject duplicate JSON fields before `JSON.parse` can collapse them.

## Closed limits

| Limit               |                       Value |
| ------------------- | --------------------------: |
| Canonical bytes     |                      65,536 |
| JSON nodes          |                         512 |
| Depth, root at zero |                          16 |
| UTF-8 key bytes     |                         512 |
| UTF-8 string bytes  |                         512 |
| WORM retention      | committed time + 2,557 days |

Canonical JSON uses the repository's safe-integer identity domain. Every timestamp is a canonical
24-byte millisecond ISO timestamp. Every digest is tagged as `sha256:<64 lowercase hex>`.

## Identity rules

The record self-ID excludes only the `record_id` member:

```text
record_id = sha256(canonicalBytes(record without record_id))
record_sha256 = sha256(canonicalBytes(record including record_id))
```

The full digest is not embedded in the record, avoiding a circular identity. It becomes WORM
metadata and, for A0, is carried by the A1 `provisioned` pointer.

Candidate record key:

```text
receipts/v2/activation/{worker_version_id}/{sequence}-{recordShaHex}.json
```

Attempt and issuance identities use the v2 domains and exclude request IDs and clocks. The internal
request ID is exactly `activation-` plus the issuance digest hex.

## A0 topology

`dpone.release-broker-provisioned.v2` contains:

- root chronology, fencing token `1`, sequence `0`, and `previous: "GENESIS"`;
- the selected descriptor summary, exact manifest pointer, pointer digest, resolver projection
  digest, and selected session identity;
- the operation attempt and issuance binding;
- four ordered direct evidence pointers;
- one 15-entry service-authority anchor vector;
- the record self-ID.

The direct vector is fixed in this order:

1. `CONTROLLER_ACTION`
2. `CONTROLLER_OIDC`
3. `TARGET_OIDC`
4. `TARGET_RULESET`

Controller action is a `DIRECT_WORM` commitment, not a read-only embedded body. Each direct entry
contains only request/evidence/effect/result/absence digests and a WORM pointer. Executor and
observer pins, exact effect results, and evidence bodies remain off-record.

The component record contains only the selected manifest pointer and resolver projection digest.
The manifest, descriptor roster, and all 15 component envelopes remain off-record.
The selected session `fresh_until` must exactly equal the journal TTL derived from the descriptor
commit. It commits the selection snapshot; it is not a post-selection deadline for evidence effects
or Cloudflare reads already issued from that selection.

## Service-authority vector

Slots `0..13` are `cloudflare_service_deployments`, in the explicit protocol tuple:

1. `attestation_mutator`
2. `candidate_reader`
3. `closed_projector`
4. `cloudflare_deployment_observer`
5. `controller_run_reader`
6. `governance_reader`
7. `pypi_deployment_gate`
8. `pypi_reader`
9. `release_authority_ingress`
10. `release_mutator`
11. `runtime_deployment_gate`
12. `tenant_scanner`
13. `worm_mirror`
14. `worm_version_observer`

Slot `14` has `authority_role: null` and `kind: "cloudflare_network_surface"`. The implementation
uses a literal tuple and never derives protocol ordering with `Object.keys()`.

Each compact entry has only `record_id`, `record_sha256`, slot metadata, and its WORM pointer. The
full sanitized record and full Cloudflare batch result stay off-record. `records_sha256` commits a
domain-separated canonical anchor vector.

## A1 topology and chain binding

`dpone.release-broker-activated.v2` contains approvals, target, promotion report pointer, its own
operation/service-authority observation, and the A0 pointer.

The chain parser requires all of the following:

- both records are v2 and ordered A0 then A1;
- `A1.previous == A1.provisioned.record_id == A0.record_id`;
- A1 carries A0's full digest and exact candidate WORM key;
- worker, component set, manifest pointer digest, and resolver projection digest equal A0;
- A0 committed strictly before promotion started;
- A0 WORM retention is at least 2,557 days from A0 commit.

Legacy v1 documents and mixed v1/v2 chains fail closed. No down-conversion or dual-write behavior is
included.

## Authority work intentionally outside this slice

A production verifier must inject and cross-bind these independent sources:

| Compact commitment                     | Required authority                                           |
| -------------------------------------- | ------------------------------------------------------------ |
| Selected component/session fields      | Confirmed component-journal authority                        |
| Manifest pointer and projection digest | Confidential resolver and exact WORM namespace reads         |
| Direct request/effect/result digests   | Resolver-derived read plan and execution pins                |
| Four direct WORM pointers              | Exact fetched evidence bodies and generic-effect results     |
| Batch/delegation commitments           | Current operation issuance and resolver-derived service plan |
| Fifteen service anchors                | Exact fetched sanitized records and rebuilt batch result     |
| A1 provisioned pointer                 | Confirmed A0 registry row and record WORM result             |
| Promotion pointer                      | Exact promotion-report WORM object                           |

Private authority brands must not be serialized through Durable Object RPC. This candidate neither
mints nor accepts such brands.

## Reproducible fixture budgets

Tests build from the checked-in production component resolver and Cloudflare provider fixtures.

| Record | Fixture bytes | Conservative bytes | Nodes | Depth |
| ------ | ------------: | -----------------: | ----: | ----: |
| A0     |        17,013 |             26,922 |   269 |     5 |
| A1     |        15,242 |             24,036 |   244 |     5 |

The conservative fixture uses a non-null journal predecessor and unique 512-byte WORM version IDs;
it also maximizes the free promotion-report key while retaining every exact key policy. Both records
retain more than 38 KB of byte headroom and more than 240 nodes of structural headroom.

Run the isolated verification with:

```sh
pnpm exec vitest run test/activation-record-v2.test.ts test/activation-record-v2-negative.test.ts
pnpm exec tsc --noEmit
node scripts/check-module-size.mjs
```
