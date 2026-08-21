import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { snapshotConfirmedActivationComponentJournalAuthority } from "../src/activation-component-journal-confirmed-authority";
import { snapshotJournalPins } from "../src/activation-component-journal-validation";
import {
  componentResults,
  componentVersion,
  confirmComponents,
  confirmManifest,
  confirmedContinuationFixture,
  continuationResultBytes,
  manifestResultBytes,
  sealManifest,
  selectedContinuationFixture,
  type SelectedContinuationFixture,
} from "./activation-component-journal-continuation.fixtures";
import { JOURNAL_EFFECT_PINS } from "./activation-component-journal.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal post-audit boundaries", () => {
  it("uses intrinsic Uint8Array length and copy operations before any result allocation", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-intrinsic-bytes-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const effect = required(fixture.sealed.effects[0]);
      let iteratorUsed = false;
      const hiddenOversize = new Uint8Array(65_537);
      Object.defineProperty(hiddenOversize, "byteLength", { value: 1 });
      Object.defineProperty(hiddenOversize, Symbol.iterator, {
        value: function* () {
          iteratorUsed = true;
          yield 0;
        },
      });
      await expect(
        fixture.store.confirmComponentEffect(
          fixture.prepared.session.sessionId,
          effect.effectId,
          hiddenOversize,
        ),
      ).rejects.toMatchObject({
        code: "ACTIVATION_COMPONENT_JOURNAL_BYTES_INVALID",
        status: 413,
      });
      expect(iteratorUsed).toBe(false);

      const valid = continuationResultBytes(effect, componentVersion(0), 1_000);
      Object.defineProperty(valid, "byteLength", {
        get: () => {
          throw new Error("own byteLength must not run");
        },
      });
      Object.defineProperty(valid, Symbol.iterator, {
        value: () => {
          iteratorUsed = true;
          throw new Error("own iterator must not run");
        },
      });
      const pending = await fixture.store.confirmComponentEffect(
        fixture.prepared.session.sessionId,
        effect.effectId,
        valid,
      );
      expect(pending.effects).toHaveLength(14);
      expect(iteratorUsed).toBe(false);
      expect(
        state.storage.sql
          .exec<{ readonly result_bytes: ArrayBuffer | null }>(
            `SELECT result_bytes FROM activation_component_session_entries_v2
             WHERE session_id = ? AND ordinal = 0`,
            fixture.prepared.session.sessionId,
          )
          .one().result_bytes,
      ).not.toBeNull();
    });
  });

  it("owns exactly four plain data-only WORM pins and rejects exotic records", () => {
    const mutable = { ...JOURNAL_EFFECT_PINS };
    const owned = snapshotJournalPins(mutable);
    mutable.executorVersionId = "99999999-9999-4999-8999-999999999999";
    expect(owned).toEqual(JOURNAL_EFFECT_PINS);
    expect(Object.isFrozen(owned)).toBe(true);

    const accessor = { ...JOURNAL_EFFECT_PINS };
    Object.defineProperty(accessor, "executorVersionId", {
      enumerable: true,
      get: () => JOURNAL_EFFECT_PINS.executorVersionId,
    });
    const symbol = { ...JOURNAL_EFFECT_PINS, [Symbol("extra")]: true };
    const hidden = { ...JOURNAL_EFFECT_PINS };
    Object.defineProperty(hidden, "extra", { value: true });
    class PinRecord {
      public readonly marker = true;
    }
    const inherited = Object.assign(new PinRecord(), JOURNAL_EFFECT_PINS);
    const proxied = new Proxy({ ...JOURNAL_EFFECT_PINS }, {});
    const throwingProxy = new Proxy(
      { ...JOURNAL_EFFECT_PINS },
      {
        getPrototypeOf: () => {
          throw new Error("proxy trap");
        },
      },
    );
    for (const candidate of [
      accessor,
      symbol,
      hidden,
      inherited,
      proxied,
      throwingProxy,
      { ...JOURNAL_EFFECT_PINS, extra: true },
    ]) {
      expect(() => snapshotJournalPins(candidate)).toThrow(
        "ACTIVATION_COMPONENT_JOURNAL_PIN_INVALID",
      );
    }
  });

  it("replays the original all-15 seal after every successful progress transition", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-progress-replay-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      const results = componentResults(fixture.sealed);
      await fixture.store.confirmComponentEffect(
        fixture.prepared.session.sessionId,
        required(fixture.sealed.effects[0]).effectId,
        required(results[0]),
      );
      await expectOriginalSealReplay(fixture);

      await confirmComponents(fixture);
      await expectOriginalSealReplay(fixture);
      const manifestSeal = await sealManifest(fixture);
      await expectOriginalSealReplay(fixture);
      await confirmManifest(fixture, manifestSeal);
      await expectOriginalSealReplay(fixture);
    });
  });

  it("replays the original all-15 seal in both terminal HOLD shapes", async () => {
    const componentStub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-hold-replay-0001");
    await runInDurableObject(componentStub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      await confirmComponents(fixture, undefined, (ordinal) =>
        ordinal < 2 ? "4_z-journal-component-collision" : componentVersion(ordinal),
      );
      await fixture.store.sealManifestEffect(fixture.prepared.session.sessionId);
      await expectOriginalSealReplay(fixture);
    });

    const manifestStub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-hold-replay-0002");
    await runInDurableObject(manifestStub, async (_instance, state) => {
      const fixture = await selectedContinuationFixture(state.storage);
      await confirmComponents(fixture);
      const manifestSeal = await sealManifest(fixture);
      await confirmManifest(
        fixture,
        manifestSeal,
        manifestResultBytes(manifestSeal, componentVersion(0)),
      );
      await expectOriginalSealReplay(fixture);
    });
  });

  it("requires the private confirmed-authority brand and returns fresh exact byte snapshots", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-authority-brand-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await confirmedContinuationFixture(state.storage);
      const authority = fixture.authority;
      const descriptorBytes = authority.canonicalDescriptorBytes;
      const pointerBytes = authority.canonicalPointerBytes;
      authority.canonicalDescriptorBytes.fill(0);
      authority.canonicalPointerBytes.fill(0);
      const snapshot = await snapshotConfirmedActivationComponentJournalAuthority(authority);
      expect(snapshot.canonicalDescriptorBytes).toEqual(descriptorBytes);
      expect(snapshot.canonicalPointerBytes).toEqual(pointerBytes);
      expect(snapshot.pins).toEqual(JOURNAL_EFFECT_PINS);
      expect(Object.isFrozen(snapshot.pins)).toBe(true);
      snapshot.canonicalDescriptorBytes.fill(1);
      snapshot.canonicalPointerBytes.fill(1);
      await expect(
        snapshotConfirmedActivationComponentJournalAuthority(snapshot),
      ).resolves.toMatchObject({
        descriptor: authority.descriptor,
        pointerSha256: authority.pointerSha256,
        session: authority.session,
        trust: "CONFIRMED_JOURNAL",
      });

      const structural = {
        canonicalDescriptorBytes: descriptorBytes,
        canonicalPointerBytes: pointerBytes,
        descriptor: authority.descriptor,
        pointerSha256: authority.pointerSha256,
        session: authority.session,
        trust: "CONFIRMED_JOURNAL",
      };
      const prototype = Reflect.getPrototypeOf(authority);
      if (prototype === null) throw new Error("authority prototype missing");
      const constructorDescriptor = Object.getOwnPropertyDescriptor(prototype, "constructor");
      if (constructorDescriptor === undefined || !("value" in constructorDescriptor)) {
        throw new Error("authority constructor missing");
      }
      const Extracted = constructorDescriptor.value as new (value: object) => object;
      const forgeries = [
        { ...authority },
        Object.assign(Object.create(prototype) as object, structural),
        new Proxy(authority, {}),
        new Extracted(structural),
        structural,
      ];
      for (const forgery of forgeries) {
        await expect(snapshotConfirmedActivationComponentJournalAuthority(forgery)).rejects.toThrow(
          "ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID",
        );
      }
    });
  });

  it("prevents deletion of every selected or confirmed SQL authority row", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-delete-guards-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await confirmedContinuationFixture(state.storage);
      const sessionId = fixture.prepared.session.sessionId;
      const deletes = [
        {
          code: "ACTIVATION_COMPONENT_SELECTED_ENTRY_DELETE_INVALID",
          sql: `DELETE FROM activation_component_session_entries_v2
                WHERE session_id = '${sessionId}' AND ordinal = 0`,
        },
        {
          code: "ACTIVATION_COMPONENT_MANIFEST_DELETE_INVALID",
          sql: `DELETE FROM activation_component_manifest_authority_v2
                WHERE session_id = '${sessionId}'`,
        },
        {
          code: "ACTIVATION_COMPONENT_SELECTION_DELETE_INVALID",
          sql: `DELETE FROM activation_component_selection_v2 WHERE singleton = 1`,
        },
        {
          code: "ACTIVATION_COMPONENT_SELECTED_SESSION_DELETE_INVALID",
          sql: `DELETE FROM activation_component_sessions_v2 WHERE session_id = '${sessionId}'`,
        },
      ];
      for (const operation of deletes) {
        expect(() => state.storage.sql.exec(operation.sql)).toThrow(operation.code);
      }
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>(
            `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
             WHERE session_id = ?`,
            sessionId,
          )
          .one().count,
      ).toBe(15);
      expect(await fixture.store.confirmedAuthority(sessionId)).toMatchObject({
        trust: "CONFIRMED_JOURNAL",
      });
    });
  });
});

async function expectOriginalSealReplay(fixture: SelectedContinuationFixture): Promise<void> {
  const replay = await fixture.store.selectAndSeal(fixture.prepared.session.sessionId);
  if (replay.outcome !== "SEALED") throw new Error("expected exact sealed replay");
  expect(replay.sealed.effects.map(({ effectId }) => effectId)).toEqual(
    fixture.sealed.effects.map(({ effectId }) => effectId),
  );
}

function required<T>(value: T | undefined | null): T {
  if (value === undefined || value === null) throw new Error("post-audit fixture value missing");
  return value;
}
