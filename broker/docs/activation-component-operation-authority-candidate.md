# Component resolver to compact A0 authority — isolated candidate

## Status

This is a private, candidate-only authority seam. It is not connected to activation routes,
Durable Object schemas, provider clients, runtime configuration, or the production registry.
It does not widen the 65,536-byte or 512-node protocol limits.

The seam authorizes only the compact A0 `component_authority` subtree and a limited projection of
semantic commitments and service pins. It is **not** a complete provider or Cloudflare observation
plan. In particular, the compact resolver projection intentionally omits the full service-authority
expectation, deployments, network surface, and target ruleset body.

## Self-service API

```ts
const authority = await bindActivationProvisionAuthority(confirmedJournal, resolvedSet);
const retry = await snapshotConfirmedActivationProvisionAuthority(authority);
```

`bindActivationProvisionAuthority` accepts only two independently branded values:

1. a confirmed component-journal authority rebuilt from the final SQLite journal chain; and
2. resolved component semantics rebuilt from the exact manifest and 15 component WORM namespaces.

Both inputs are passed through their private-brand snapshot APIs before any field is consumed. A
literal, spread, prototype graft, proxy, extracted constructor, or serialized copy cannot mint the
operation authority. The returned literal trust label has no authorizing meaning without the
module-private `WeakMap` entry.

Every byte getter returns a fresh copy. Nested descriptor, session, commitment, pin, and compact
JSON projections are recursively immutable. A caller that mutates any returned byte array cannot
change the next retry snapshot.

## Exact cross-binding

The binder reparses fresh owned copies of the journal descriptor, manifest pointer, and resolver
projection. It requires exact agreement on:

- descriptor commit time, descriptor ID/SHA, component set ID, and historical worker version;
- journal session ID, generation, ordinal, predecessor, state, and derived historical
  `fresh_until`;
- manifest ID, manifest SHA, complete manifest WORM tuple, pointer key-derived worker/set, and
  exact canonical pointer bytes;
- pointer SHA and resolver projection SHA recomputed from exact bytes.

The resulting `component_authority` has exactly the compact-v2 topology:

```text
{
  descriptor,
  manifest_pointer,
  manifest_pointer_sha256,
  resolved_projection_sha256,
  session
}
```

It is passed through `validateActivationRecordV2ComponentAuthority`. The stable A0 intent digest is
then derived with the shared `activationRecordV2IntentSha256(..., 0)` function. No parallel identity
domain exists in this module.

## Historical trust and pins

No current resolver or broker worker version is used as historical authority.

- The historical ingress pin is derived from the resolved Cloudflare account, the fixed
  `release_authority_ingress` service definition, and the selected descriptor worker version.
- Controller-action and controller-OIDC reads use the resolved `controller_run_reader` pin.
- Target-OIDC and target-ruleset reads use the resolved `governance_reader` pin.
- Direct evidence WORM effects use resolved `worm_mirror` and `worm_version_observer` pins.
- The Cloudflare batch tuple uses resolved `cloudflare_deployment_observer`, `worm_mirror`, and
  `worm_version_observer` pins.

Each projected pin is rechecked for its fixed service name, Cloudflare account-qualified identity,
UUID version, and exact `@version` suffix. The public compact component-authority document contains
no `private_services` object or confidential component payload.

The exposed semantic commitments are limited to the resolved account, controller-action bundle
digest, service-authority expectation digest, and target-ruleset evidence/projection digests.

## Retry and recovery contract

The authority is independent of an operation issuance. Exact retries and later issuance reissues
must reproduce identical component-authority bytes/SHA, provision-intent bytes/SHA, historical
worker, commitments, and pins. A future coordinator must:

1. reread the confirmed journal authority after restart;
2. re-resolve the exact journal pointer;
3. bind both private authorities again; and
4. compare/CAS the stable component-authority and intent digests before any provider or WORM effect.

The selected session's `fresh_until` remains a historical selection commitment. It is not a
post-selection deadline for already authorized evidence work.

## Deliberate HOLDs before runtime integration

- The resolver must retain a separate private, revalidated full service-authority expectation
  capability before a production Cloudflare observer plan can be built after restart. That data
  must not be added to the compact record.
- The final journal capability owns the exact WORM pins rebuilt from the persisted selection.
  Before minting operation authority, the binder compares all four executor/observer identity and
  version scalars with the resolver-derived `worm_mirror` and `worm_version_observer` pins. A pin
  transplant therefore fails even when the descriptor, manifest pointer, and compact projection
  otherwise remain internally valid.
- Existing v1 operation runner and record materializer must not receive a reconstructed oversized
  v1 request from this authority.
- Exact `Uint8Array` boundary hardening across older resolver/component helpers remains a separate
  pre-runtime task. This seam consumes only their already branded, freshly owned snapshots.

Run the focused candidate gates with:

```sh
pnpm exec vitest run \
  test/activation-component-operation-authority.test.ts \
  test/activation-component-operation-authority-negative.test.ts
pnpm exec tsc --noEmit
pnpm exec eslint src/activation-component-operation-*.ts \
  test/activation-component-operation-authority*.ts
pnpm exec prettier --check src/activation-component-operation-*.ts \
  test/activation-component-operation-authority*.ts \
  docs/activation-component-operation-authority-candidate.md
node scripts/check-module-size.mjs
```
