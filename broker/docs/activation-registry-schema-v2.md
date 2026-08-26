# ActivationRegistry internal schema v2

## Status and boundary

`initializeActivationRegistrySchemaV2()` is the fail-closed bootstrap for a new,
version-scoped compact-v2 `ActivationRegistry` Durable Object. It is deliberately
not wired into HTTP routes, provider calls, the current `ActivationRegistry`
constructor, or the v1 runtime stores yet. Enabling those call sites is a separate
cutover ceremony.

The bootstrap accepts only two storage states:

1. no application-owned SQLite tables, indexes, triggers, or views; or
2. the complete v2 topology with matching registry and component-journal stamps.

A v1, unversioned, partial, unknown, or worker-version-conflicting layout fails
closed without dropping, rebuilding, or updating anything.

## Usage

Call the initializer from the version-scoped Durable Object constructor while the
v2 runtime cutover is being integrated:

```ts
initializeActivationRegistrySchemaV2(ctx.storage, immutableWorkerVersionId);
```

The worker version must be the immutable 36-character version ID already required
by the component journal. Repeating the call with the same version is idempotent.
Repeating it with an alias or another version fails with
`ACTIVATION_REGISTRY_V2_STAMP_CONFLICT`.

Do not run the initializer against an existing v1 object. Provision a fresh
version-scoped Durable Object instead. There is intentionally no in-place migration
or empty-legacy rebuild path.

## Atomic topology

One outer `DurableObjectStorage.transactionSync()` owns the complete bootstrap:

- operation intents, issuances, slots, Cloudflare anchors, and the live-issuance
  index;
- activation records;
- the full component journal, selection singleton, manifest authority, indexes,
  triggers, and journal stamp;
- one immutable component-to-operation binding table and its guards; and
- the registry stamp, written last.

The component journal exposes an in-transaction initializer for this composition.
Its existing public initializer still owns its own transaction, so standalone
journal users keep the previous behavior.

The generated `activation-registry-schema-v2-fingerprint.json` is an exact,
collision-free snapshot of every sorted `{type, name, sqlite_schema.sql}` row. The
bootstrap compares all 50 user-defined objects inside the outer transaction. It
therefore rejects same-name weak tables, no-op trigger replacements, extra indexes,
and persisted views; SQLite-owned `sqlite_autoindex_*` rows are intentionally
excluded. When intentional DDL changes, regenerate and review the snapshot together
with a schema-version decision instead of editing it by hand.

### Regenerating the fingerprint

Regeneration is a deliberate schema-review operation, never a runtime fallback:

1. Decide whether the DDL change requires a new registry schema version. Make the
   reviewed DDL change first.
2. In a disposable focused test, call `initializeActivationRegistrySchemaV2()` on
   empty storage and capture the rows below from its `REGISTRY_STAMPED` checkpoint.
   Throw `CAPTURE_SCHEMA_V2` from that callback so the outer transaction rolls the
   temporary topology back.
3. Serialize the returned array with `JSON.stringify(rows, null, 2)`, replace
   `src/activation-registry-schema-v2-fingerprint.json`, and remove the disposable
   capture test.
4. Review the JSON diff as DDL, then run the focused suite and `pnpm check`. The
   normal bootstrap must pass its final exact-topology assertion; forged-table and
   forged-trigger regressions must remain red for the forged layouts.

Use exactly the same query and ordering as the runtime assertion:

```sql
SELECT type, name, sql
FROM sqlite_schema
WHERE type IN ('index', 'table', 'trigger', 'view')
  AND name NOT LIKE 'sqlite_%'
ORDER BY type, name;
```

The capture checkpoint fires after all DDL and both stamps exist but before the
snapshot assertion. It exists so a stale snapshot can be regenerated without
committing any intermediate schema. Never weaken or skip the normal assertion in
production code.

If any DDL statement, seed insert, invariant check, or injected checkpoint throws,
SQLite rolls back every object and stamp. A retry begins from an empty topology.

## Compact-v2 invariants

### Operation roster

The shared operation DDL is profile-driven. Legacy callers continue to receive the
v1 profile. The v2 profile enforces the roster against the owning intent sequence:

| Sequence | Slot                | Kind               | Index |
| -------- | ------------------- | ------------------ | ----: |
| A0 (`0`) | `CONTROLLER_ACTION` | `DIRECT_WORM`      |     0 |
| A0 (`0`) | `CONTROLLER_OIDC`   | `DIRECT_WORM`      |     1 |
| A0 (`0`) | `TARGET_OIDC`       | `DIRECT_WORM`      |     2 |
| A0 (`0`) | `TARGET_RULESET`    | `DIRECT_WORM`      |     3 |
| A0 (`0`) | `CLOUDFLARE_BATCH`  | `CLOUDFLARE_BATCH` |     4 |
| A1 (`1`) | `CLOUDFLARE_BATCH`  | `CLOUDFLARE_BATCH` |     0 |

An intent must be inserted as `OPEN`, an issuance must be inserted as `RESERVED`,
and its slots must be inserted as `PREPARED` while the issuance remains `RESERVED`.
Intent, issuance, and slot identity fields are immutable; slot deletion is
forbidden. Leaving `RESERVED` requires all five A0 slots or the single A1 slot. In
particular, an A0 Cloudflare slot cannot use the A1 index, an A1 issuance cannot
acquire an A0 direct-effect slot, and a partial roster cannot begin provider work.
A slot may leave `PREPARED` only after that exact sequence roster is complete; the
parent may still be `RESERVED`, preserving the current prepare-before-collect
statement order.

### Record ownership

`activation_records.operation_issuance_id` is physically `TEXT NOT NULL UNIQUE` in
v2 and remains nullable in the legacy profile. The foreign key continues to point
to the durable issuance. An insert trigger requires the owning intent to remain
`OPEN` and the issuance to be its greatest ordinal in exactly `READY_TO_APPEND`.
The record sequence and request digest must equal the intent sequence and
`intent_sha256`; its committed timestamp must equal the non-null issuance
`record_committed_at`. Record core fields are immutable and record deletion is
forbidden. These constraints prevent an unowned, stale, premature, or
cross-commitment compact-v2 record while preserving all v1 tests and data semantics.
Record self-ID, canonical-byte, and digest validation remains owned by the
application parser.

### Component-to-operation binding

`activation_component_operation_binding_v2` contains exactly one optional singleton
row with these authority fields:

- `selected_session_id` — unique reference to the selected component session and
  its manifest row;
- `attempt_id` — unique reference to the stable A0 operation intent;
- `manifest_pointer_sha256` — copied cross-domain commitment, verified against the
  confirmed manifest row for that same session; and
- `resolved_projection_sha256` — the only new scalar projection commitment.

The table stores no BLOB and does not copy descriptor, manifest, result, or record
bytes. An insert is accepted only when:

- the journal selection and manifest are both `CONFIRMED` for the same session and
  pointer digest;
- that session remains `SELECTED` and belongs to the journal-stamped worker version;
- the operation intent is sequence A0 and remains `OPEN`;
- the intent belongs to the same journal-stamped worker version;
- an issuance for that attempt is the greatest ordinal; and
- the issuance is still in an eligible, nonterminal state (`RESERVED`, `COLLECTING`,
  `FROZEN`, `EFFECTS_PENDING`, or `READY_TO_APPEND`) with the complete five-slot A0
  roster.

Every binding update and delete is rejected.

The binding intentionally does not persist an issuance ID. If an undispatched
issuance expires, the operation authority may create the next ordinal for the same
attempt without rewriting the confirmed component commitment. Execution and the
record row still fence the exact current issuance ID.

## Failure codes

| Code                                                  | Meaning                                                                                      |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `ACTIVATION_REGISTRY_V2_TOPOLOGY_CONFLICT`            | Missing, unexpected, or byte-divergent schema object; includes views and weak same-name DDL. |
| `ACTIVATION_REGISTRY_V2_STAMP_INVALID`                | Registry stamp cannot be read with the v2 shape.                                             |
| `ACTIVATION_REGISTRY_V2_STAMP_CONFLICT`               | Version, singleton, or worker-version value differs.                                         |
| `ACTIVATION_REGISTRY_V2_RECORD_OWNERSHIP_INVALID`     | The record issuance column is not `TEXT NOT NULL`.                                           |
| `ACTIVATION_COMPONENT_OPERATION_BINDING_INVALID`      | Component authority, pointer, sequence, or current issuance is not eligible.                 |
| `ACTIVATION_COMPONENT_OPERATION_BINDING_IMMUTABLE`    | A caller attempted to update or delete the binding.                                          |
| `ACTIVATION_OPERATION_SLOT_PROFILE_INVALID`           | A slot does not belong to the exact A0/A1 v2 roster.                                         |
| `ACTIVATION_OPERATION_ROSTER_INCOMPLETE`              | An issuance attempted to leave `RESERVED` without its complete roster.                       |
| `ACTIVATION_OPERATION_INTENT_IDENTITY_IMMUTABLE`      | A caller attempted to rewrite durable operation identity.                                    |
| `ACTIVATION_OPERATION_INTENT_INITIAL_STATE_INVALID`   | A new intent did not start in `OPEN`.                                                        |
| `ACTIVATION_OPERATION_ISSUANCE_IDENTITY_IMMUTABLE`    | A caller attempted to rewrite issuance identity or chronology.                               |
| `ACTIVATION_OPERATION_ISSUANCE_INITIAL_STATE_INVALID` | A new issuance did not start in `RESERVED`.                                                  |
| `ACTIVATION_OPERATION_SLOT_IDENTITY_IMMUTABLE`        | A caller attempted to move or reclassify a slot.                                             |
| `ACTIVATION_OPERATION_SLOT_DELETE_FORBIDDEN`          | A caller attempted to remove a v2 operation slot.                                            |
| `ACTIVATION_RECORD_OPERATION_BINDING_INVALID`         | A record is not bound to the latest ready issuance and exact intent digest/time.             |
| `ACTIVATION_RECORD_CORE_IMMUTABLE`                    | A caller attempted to rewrite record identity or canonical bytes.                            |
| `ACTIVATION_RECORD_DELETE_FORBIDDEN`                  | A caller attempted to remove a v2 activation record.                                         |

## Verification

The focused suite covers:

- exact fresh bootstrap and both stamps;
- idempotence and worker-version conflict;
- rollback and clean retry after every bootstrap checkpoint;
- preservation of populated v1, unversioned, partial, and unknown state;
- rejection of persisted views, same-name weak tables, and no-op trigger forgeries;
- physical `NOT NULL` record ownership and a BLOB-free binding table;
- exact sequence-aware operation rosters, identity immutability, and latest-ready
  record sequence/digest/time cross-binding; and
- binding eligibility, pointer equality, worker equality, complete-roster gating,
  ordinal reissue recovery, and immutability.

Run it locally with:

```sh
pnpm exec vitest run \
  test/activation-registry-schema-v2.test.ts \
  test/activation-registry-schema-v2-security.test.ts
```
