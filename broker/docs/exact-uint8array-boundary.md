# Exact Uint8Array ownership boundary

Status: candidate-only foundation. It does not enable a route, provider, runtime cutover, or
deployment.

## Why this boundary exists

Activation component, journal, resolver, operation, and compact-record code all receive exact
canonical byte sequences. A JavaScript `Uint8Array` is not safe to copy by reading
`input.byteLength` and calling `Uint8Array.from(input)`:

- an own `byteLength` property can hide the native view length;
- an own `Symbol.iterator` can execute caller code or produce an unrelated number of bytes;
- a Proxy or subclass can execute traps or override ordinary operations;
- a SharedArrayBuffer, resizable ArrayBuffer, or detached buffer does not provide the fixed owned
  snapshot required across an `await`.

`ownExactUint8Array` is the single dependency-leaf implementation for these boundaries. Callers
provide their existing BrokerError code and status policy; the helper does not define domain
semantics.

## Contract

The function accepts an `unknown` byte candidate and trusted static boundary policy. The policy is
snapshotted once before the candidate is inspected. It then performs these steps in order:

1. `ArrayBuffer.isView` rejects a Proxy without invoking `getPrototypeOf` or ordinary property
   traps.
2. The view prototype must be exactly `Uint8Array.prototype`, and the intrinsic TypedArrayName
   getter must return `Uint8Array`. Subclasses, other typed views, and other views re-prototyped as
   a Uint8Array are rejected.
3. The `%TypedArray%.prototype` native getters read the internal byte length, byte offset, and
   backing buffer. Own shadow properties are never consulted.
4. The backing store prototype must be exactly `ArrayBuffer.prototype`. SharedArrayBuffer is
   rejected.
5. Native ArrayBuffer getters reject detached and resizable backing stores.
6. Minimum and maximum byte limits are checked before allocation or copy.
7. Own string or symbol decorations are deliberately ignored. No ordinary property, accessor, or
   iterator is read, so a decoration cannot execute or change the copied byte identity. The owned
   result retains none of them. Avoiding O(n) index-key enumeration also keeps replay cost bounded
   by the native copy itself.
8. A fixed plain ArrayBuffer-backed destination is allocated at the already-validated native
   length. `Uint8Array.prototype.set` is invoked intrinsically, so a caller iterator is never used.

The return value is a new `Uint8Array<ArrayBuffer>` with byte offset zero and a fixed backing store
whose size equals the selected view length. Mutation of the source after the call cannot change the
owned result.

## Usage

```ts
const owned = ownExactUint8Array(input, {
  code: "DOMAIN_BYTES_INVALID",
  invalidStatus: 409,
  maximum: 65_536,
  minimum: 1,
  sizeStatus: 413,
});
```

Boundary policy is code-owned configuration, not request data. Keep it as a literal or frozen
constant. Do not derive its error code, statuses, or limits from an untrusted payload.

An async function must call the helper before its first `await` and use only the returned bytes
afterward. Do not retain the original view alongside the owned snapshot.

## Migrated boundaries

The unified helper now owns byte ingress for:

- activation component canonical decoding, envelopes, closed payloads, confirmations, and
  manifests;
- confidential resolver pointer input and exact namespace object bodies;
- activation operation slot/store snapshots and record-source snapshots;
- activation component journal result/effect snapshots;
- compact activation-record v2 parsing.

Each caller preserves its established public BrokerError contract. Notable policies are:

| Boundary                                               | Invalid shape | Size outside range |
| ------------------------------------------------------ | ------------: | -----------------: |
| Component codec/envelope/payload/confirmation/manifest |           409 |                413 |
| Confidential resolver pointer                          |           409 |                413 |
| Resolver namespace body                                |           409 |                409 |
| Operation store and record source                      |           413 |                413 |
| Component journal                                      |           409 |                413 |
| Compact activation record v2                           |           413 |                413 |

Resolver namespace bodies intentionally retain the existing 409 contract because metadata,
content, and length are one closed provider-authority tuple. Operation and compact-record callers
intentionally retain their established size-oriented 413 contract for every invalid byte view.

## Verification and self-service checklist

Before adding another byte ingress:

1. Accept `unknown` at the runtime boundary even if the internal TypeScript API is narrower.
2. Snapshot with `ownExactUint8Array` before parsing, hashing, storing, or awaiting.
3. Choose a fixed maximum and the domain's existing BrokerError code/status mapping.
4. Test Proxy, subclass, a non-byte typed array re-prototyped as Uint8Array, own `byteLength`, own
   iterator, hidden and symbol decorations (ignored, never evaluated, and absent from the result),
   fixed-size overflow, SharedArrayBuffer, resizable buffer when supported, detached buffer, source
   mutation, and caller-error normalization.
5. Verify the call site never falls back to `Uint8Array.from(untrustedInput)` or an ordinary
   `.byteLength` check.

The helper imports only `errors.ts`. Component, journal, operation, resolver, and record modules
depend on it one way; it never imports those higher-level modules. This is a deliberately narrow
one-way assertion, not a claim that the pre-existing whole repository graph is acyclic. Reproduce
the marker gate from the repository root:

```sh
test "$(rg -c '^import .* from ' src/exact-uint8array.ts)" -eq 1
test "$(rg -c '^import \{ BrokerError \} from \"\./errors\";$' src/exact-uint8array.ts)" -eq 1
test "$(rg -l 'from \"\./exact-uint8array\"' src/*.ts | wc -l | tr -d ' ')" -eq 11
```

## Residual HOLD inventory

The following byte-copy sites remain outside this atomic candidate slice and must be migrated or
proven internal before runtime cutover:

- `activation-operation-effects-validation.ts`;
- `activation-operation-cloudflare-request.ts`;
- `activation-operation-record-lifecycle.ts`;
- `activation-operation-runtime-port.ts` (runtime integration is explicitly out of scope);
- `activation-operation-identity.ts`;
- `candidate-public-v2/bytes.ts`, whose public body and private-nonce helpers still use ordinary
  length/iterator copying, plus direct `parseCanonicalPublicV2` and deterministic ZIP parser/member
  snapshot paths that do not yet own exact native views; these require a separate candidate error-
  policy migration;
- `canonical.ts::sha256Hex` and direct async callers that pass caller-owned byte views rather than
  an already-owned domain snapshot;
- `worm-exact-object-effect-contract.ts`, `worm-exact-object-effect-result.ts`,
  `worm-exact-object-effect-client.ts`, and `worm-exact-object-effect-runner.ts`, plus the private
  exact-object handler and Durable Object byte boundaries; migrated component callers pre-own
  their inputs, but the generic exported/runtime surfaces still need an exact-ingress audit;
- private branded/output copies in operation-authority and record builders;
- descriptor/builder output copies and SQL-owned ArrayBuffer snapshots that are not currently
  public or async ingress.

This list is a cutover blocker inventory, not an authorization to widen the 65,536-byte or
512-node limits. Any future migration must preserve the caller's domain error contract and rerun
the same hostile-input matrix.
