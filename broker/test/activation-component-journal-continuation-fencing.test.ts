import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ACTIVATION_COMPONENT_JOURNAL_TTL_MS } from "../src/activation-component-journal-contract";
import type { ActivationComponentJournalManifestRow } from "../src/activation-component-journal-manifest-schema";
import {
  componentResults,
  componentVersion,
  confirmComponents,
  confirmManifest,
  confirmedContinuationFixture,
  continuationEntry,
  continuationManifest,
  continuationResultBytes,
  continuationSelection,
  installSelectionAbort,
  removeTestTrigger,
  restartedStore,
  sealManifest,
  selectedContinuationFixture,
  type SelectedContinuationFixture,
} from "./activation-component-journal-continuation.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal continuation fencing", () => {
  it("normalizes invalid byte views, enforces both size edges, and snapshots caller bytes", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-bytes-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const effect = required(fixture.sealed.effects[0]);
      const valid = continuationResultBytes(effect, componentVersion(0), 1_000);
      class DerivedBytes extends Uint8Array {}

      for (const bytes of [
        new DerivedBytes(valid),
        new DataView(valid.buffer) as unknown as Uint8Array,
        new Proxy(Uint8Array.from(valid), {}),
      ]) {
        await expect(
          fixture.store.confirmComponentEffect(
            fixture.prepared.session.sessionId,
            effect.effectId,
            bytes,
          ),
        ).rejects.toMatchObject({
          code: "ACTIVATION_COMPONENT_JOURNAL_BYTES_INVALID",
          status: 409,
        });
      }
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          effect.effectId,
          new Uint8Array(),
        ),
      ).rejects.toMatchObject({ code: "ACTIVATION_COMPONENT_JOURNAL_BYTES_INVALID", status: 413 });
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          effect.effectId,
          new Uint8Array(65_537),
        ),
      ).rejects.toMatchObject({ code: "ACTIVATION_COMPONENT_JOURNAL_BYTES_INVALID", status: 413 });
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          effect.effectId,
          new Uint8Array(65_536),
        ),
      ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID");

      const expected = Uint8Array.from(valid);
      const pending = fixture.store.confirmComponentEffect(
        fixture.prepared.session.sessionId,
        effect.effectId,
        valid,
      );
      valid.fill(0);
      await pending;
      expect(
        new Uint8Array(
          required(
            continuationEntry(state.storage, fixture.prepared.session.sessionId, 0).result_bytes,
          ),
        ),
      ).toEqual(expected);
    });
  });

  it("continues after TTL and facade restart, while detecting stored component corruption", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-restart-ttl-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const original = await selectedContinuationFixture(state.storage);
      original.clock.milliseconds += ACTIVATION_COMPONENT_JOURNAL_TTL_MS + 1;
      const restarted = withStore(original, restartedStore(state.storage, original.clock));
      await confirmComponents(restarted);
      const secondRestart = withStore(original, restartedStore(state.storage, original.clock));
      const manifestSeal = await sealManifest(secondRestart);
      await expect(confirmManifest(secondRestart, manifestSeal)).resolves.toMatchObject({
        outcome: "CONFIRMED",
      });
      await expect(
        restartedStore(state.storage, original.clock).confirmedAuthority(
          original.prepared.session.sessionId,
        ),
      ).resolves.toMatchObject({ trust: "CONFIRMED_JOURNAL" });
    });

    const corruptStub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-corrupt-0001");
    await runInDurableObject(corruptStub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      state.storage.sql.exec(
        `UPDATE activation_component_session_entries_v2 SET envelope_bytes = ?
         WHERE session_id = ? AND ordinal = 0`,
        new Uint8Array([0]),
        fixture.prepared.session.sessionId,
      );
      await expect(
        restartedStore(state.storage, fixture.clock).unresolvedComponentEffects(
          fixture.prepared.session.sessionId,
        ),
      ).rejects.toThrow("ACTIVATION_COMPONENT_ENVELOPE_INVALID");
      expect(continuationSelection(state.storage)).toEqual({
        hold_code: null,
        state: "COMPONENT_EFFECTS_SEALED",
      });
    });
  });

  it("fails closed when terminal manifest, result, effect, or pointer authority is corrupted", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-terminal-corrupt-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await confirmedContinuationFixture(state.storage);
      const row = state.storage.sql
        .exec<ActivationComponentJournalManifestRow>(
          `SELECT * FROM activation_component_manifest_authority_v2 WHERE session_id = ?`,
          fixture.prepared.session.sessionId,
        )
        .one();
      const entry = continuationEntry(state.storage, fixture.prepared.session.sessionId, 0);
      state.storage.sql.exec("DROP TRIGGER activation_component_entry_confirmed_immutable_v2");
      for (const [field, invalid, original] of [
        ["result_bytes", flipped(required(entry.result_bytes)), required(entry.result_bytes)],
        ["result_sha256", fakeDigest(5), required(entry.result_sha256)],
      ] as const) {
        updateConfirmedEntryField(
          state.storage,
          fixture.prepared.session.sessionId,
          field,
          invalid,
        );
        await expect(
          fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
        ).rejects.toBeDefined();
        updateConfirmedEntryField(
          state.storage,
          fixture.prepared.session.sessionId,
          field,
          original,
        );
        await expect(
          fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
        ).resolves.toMatchObject({ trust: "CONFIRMED_JOURNAL" });
      }
      const corruptions = [
        corruption("manifest_bytes", flipped(row.manifest_bytes), row.manifest_bytes),
        corruption("manifest_sha256", fakeDigest(1), row.manifest_sha256),
        corruption("effect_id", fakeDigest(2), row.effect_id),
        corruption("result_bytes", flipped(required(row.result_bytes)), required(row.result_bytes)),
        corruption("result_sha256", fakeDigest(3), required(row.result_sha256)),
        corruption(
          "pointer_bytes",
          flipped(required(row.pointer_bytes)),
          required(row.pointer_bytes),
        ),
        corruption("pointer_sha256", fakeDigest(4), required(row.pointer_sha256)),
      ] as const;

      state.storage.sql.exec("DROP TRIGGER activation_component_manifest_immutable_v2");
      for (const { field, invalid, original } of corruptions) {
        updateManifestField(state.storage, fixture.prepared.session.sessionId, field, invalid);
        await expect(
          fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
        ).rejects.toBeDefined();
        expect(continuationSelection(state.storage).state).toBe("CONFIRMED");
        updateManifestField(state.storage, fixture.prepared.session.sessionId, field, original);
        await expect(
          fixture.store.confirmedAuthority(fixture.prepared.session.sessionId),
        ).resolves.toMatchObject({ trust: "CONFIRMED_JOURNAL" });
      }
    });
  });

  it("detects selected WORM pin drift before accepting the sealed manifest", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-pin-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      await confirmComponents(fixture);
      const sealed = await sealManifest(fixture);
      const before = continuationManifest(state.storage, fixture.prepared.session.sessionId);
      const version = "44444444-4444-4444-8444-444444444444";
      state.storage.sql.exec("DROP TRIGGER activation_component_selection_authority_immutable_v2");
      state.storage.sql.exec(
        `UPDATE activation_component_selection_v2
         SET worm_service_identity = ?, worm_version_id = ? WHERE singleton = 1`,
        `cloudflare-worker:${"b".repeat(32)}/worm-mirror@${version}`,
        version,
      );

      await expect(
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_EFFECT_CONFLICT");
      await expect(
        fixture.store.confirmManifestEffect(
          fixture.prepared.session.sessionId,
          sealed.effect.effectId,
          continuationResultBytes(sealed.effect, "4_z-journal-manifest-pin-drift", 3_000),
        ),
      ).rejects.toThrow("ACTIVATION_COMPONENT_JOURNAL_EFFECT_CONFLICT");
      expect(continuationSelection(state.storage).state).toBe("MANIFEST_EFFECT_SEALED");
      expect(continuationManifest(state.storage, fixture.prepared.session.sessionId)).toEqual(
        before,
      );
    });
  });

  it("rolls back component completion, manifest seal, and final confirmation on trigger aborts", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-continuation-rollback-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = componentResults(fixture.sealed);
      for (let ordinal = 0; ordinal < 14; ordinal += 1) {
        await fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          required(fixture.sealed.effects[ordinal]).effectId,
          required(results[ordinal]),
        );
      }
      installSelectionAbort(
        state.storage,
        "activation_component_test_components_confirmed",
        "COMPONENTS_CONFIRMED",
      );
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          required(fixture.sealed.effects[14]).effectId,
          required(results[14]),
        ),
      ).rejects.toThrow("TEST_ABORT_CONTINUATION_TRANSITION");
      expect(continuationEntry(state.storage, fixture.prepared.session.sessionId, 14)).toEqual({
        result_bytes: null,
        result_sha256: null,
        status: "SEALED",
      });
      removeTestTrigger(state.storage, "activation_component_test_components_confirmed");
      await fixture.store.confirmComponentEffect(
        fixture.prepared.session.sessionId,
        required(fixture.sealed.effects[14]).effectId,
        required(results[14]),
      );

      installSelectionAbort(
        state.storage,
        "activation_component_test_manifest_sealed",
        "MANIFEST_EFFECT_SEALED",
      );
      await expect(
        fixture.store.sealManifestEffect(fixture.prepared.session.sessionId),
      ).rejects.toThrow("TEST_ABORT_CONTINUATION_TRANSITION");
      expect(
        continuationManifest(state.storage, fixture.prepared.session.sessionId),
      ).toBeUndefined();
      expect(continuationSelection(state.storage).state).toBe("COMPONENTS_CONFIRMED");
      removeTestTrigger(state.storage, "activation_component_test_manifest_sealed");
      const manifestSeal = await sealManifest(fixture);

      installSelectionAbort(
        state.storage,
        "activation_component_test_final_confirmed",
        "CONFIRMED",
      );
      await expect(confirmManifest(fixture, manifestSeal)).rejects.toThrow(
        "TEST_ABORT_CONTINUATION_TRANSITION",
      );
      expect(continuationManifest(state.storage, fixture.prepared.session.sessionId)).toMatchObject(
        { pointer_bytes: null, result_bytes: null, status: "SEALED" },
      );
      expect(continuationSelection(state.storage).state).toBe("MANIFEST_EFFECT_SEALED");
      removeTestTrigger(state.storage, "activation_component_test_final_confirmed");
      await expect(confirmManifest(fixture, manifestSeal)).resolves.toMatchObject({
        outcome: "CONFIRMED",
      });
    });
  });
});

type ManifestCorruptionField =
  | "effect_id"
  | "manifest_bytes"
  | "manifest_sha256"
  | "pointer_bytes"
  | "pointer_sha256"
  | "result_bytes"
  | "result_sha256";
type ManifestCorruptionValue = ArrayBuffer | string | Uint8Array;

function corruption(
  field: ManifestCorruptionField,
  invalid: ManifestCorruptionValue,
  original: ArrayBuffer | string,
) {
  return { field, invalid, original } as const;
}

function updateManifestField(
  storage: DurableObjectStorage,
  sessionId: string,
  field: ManifestCorruptionField,
  value: ManifestCorruptionValue,
): void {
  storage.sql.exec(
    `UPDATE activation_component_manifest_authority_v2 SET ${field} = ? WHERE session_id = ?`,
    value,
    sessionId,
  );
}

function updateConfirmedEntryField(
  storage: DurableObjectStorage,
  sessionId: string,
  field: "result_bytes" | "result_sha256",
  value: ManifestCorruptionValue,
): void {
  storage.sql.exec(
    `UPDATE activation_component_session_entries_v2 SET ${field} = ?
     WHERE session_id = ? AND ordinal = 0`,
    value,
    sessionId,
  );
}

function flipped(value: ArrayBuffer): Uint8Array {
  const bytes = Uint8Array.from(new Uint8Array(value));
  bytes[0] = required(bytes[0]) ^ 1;
  return bytes;
}

function fakeDigest(ordinal: number): string {
  return `sha256:${ordinal.toString(16).padStart(64, "f")}`;
}

function required<T>(value: T | undefined | null): T {
  if (value === undefined || value === null) throw new Error("continuation fixture value missing");
  return value;
}

function withStore(
  fixture: SelectedContinuationFixture,
  store: SelectedContinuationFixture["store"],
): SelectedContinuationFixture {
  return { ...fixture, store };
}
