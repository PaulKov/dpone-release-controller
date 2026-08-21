# Admin activation v2 codec — isolated candidate boundary

## Status and non-authority guarantee

This codec is candidate-only. It is not wired into the ingress routes, replay ledger, activation
registry, runtime configuration, provider clients, or deployment tooling. The production admin
handlers continue to use the existing v1 path. Parsing a v2 document returns an explicitly
`UNTRUSTED` structural value and cannot authorize persistence or an external effect.

The split `admin-activation-v2-canonical.ts` leaf owns the raw byte boundary. The semantic codec
then performs closed schema and route dispatch. Keeping these responsibilities separate makes the
byte rules reusable without coupling them to activation state.

## Self-service contract

Call `parseAdminActivationV2Ingress(bytes, context)` with:

- an exact native `Uint8Array` containing one canonical JSON object;
- the already selected provision or finalize route; and
- the trusted Worker version expected for STAGE or FINALIZE.

The boundary rejects decorated/proxied typed arrays, empty or oversized bodies, a UTF-8 BOM,
malformed UTF-8, duplicate object fields, non-object roots, and noncanonical serialization. Every
successful result owns the bytes and returns a fresh copy from `canonicalBytes`.

The semantic layer accepts only five closed variants: BEGIN, REISSUE, STAGE, PROVISION, and
FINALIZE. BEGIN requires the exact component roster in canonical order. STAGE and FINALIZE bind to
the trusted expected Worker version. Known v1 schemas fail before action-specific validation, so a
caller cannot downgrade through a v2-shaped route.

## Error taxonomy

Raw boundary failures retain distinct stable codes:

- `ADMIN_ACTIVATION_V2_UTF8_INVALID` for malformed UTF-8;
- `ADMIN_ACTIVATION_V2_DUPLICATE_FIELD` for duplicate JSON members;
- `ADMIN_ACTIVATION_V2_BOM_FORBIDDEN` for a BOM;
- `ADMIN_ACTIVATION_V2_BODY_NONCANONICAL` for valid JSON with different bytes; and
- `ADMIN_ACTIVATION_V2_BODY_INVALID` for other raw-body failures.

Schema, action, roster, route, Worker binding, and size errors remain separate semantic failures.
All failures are fail-closed and non-retryable.

## Verification and deliberate HOLD

Run the isolated gates with:

```sh
pnpm exec vitest run test/admin-activation-v2-codec.test.ts
pnpm exec tsc --noEmit
pnpm exec eslint src/admin-activation-v2-canonical.ts src/admin-activation-v2-codec.ts \
  test/admin-activation-v2-codec.test.ts
pnpm exec prettier --check src/admin-activation-v2-canonical.ts \
  src/admin-activation-v2-codec.ts test/admin-activation-v2-codec.test.ts \
  docs/admin-activation-v2-codec-candidate.md
node scripts/check-module-size.mjs
```

Runtime wiring remains on HOLD until authentication, replay semantics, durable state transitions,
provider-effect recovery, and the full cutover evidence are independently reviewed together.
