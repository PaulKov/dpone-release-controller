import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ActivationOperationRecordLifecycle } from "../src/activation-operation-record-lifecycle";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { JsonObject } from "../src/types";
import {
  confirmedRecordWormResult,
  readyRecordJournal,
  recordMaterializer,
} from "./activation-operation-record-lifecycle.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation operation record lifecycle", () => {
  it("atomically freezes one linked record and reuses exact bytes after response loss", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-lifecycle-append-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      const first = await lifecycle.freezeAndAppend(journal.issuanceId);
      const retry = await lifecycle.freezeAndAppend(journal.issuanceId);
      const issuance = state.storage.sql
        .exec<{
          readonly state: string;
        }>(
          `SELECT state FROM activation_operation_issuances WHERE issuance_id = ?`,
          journal.issuanceId,
        )
        .one();
      return {
        calls: fixture.calls(),
        first: new Uint8Array(first.canonical_bytes),
        issuanceState: issuance.state,
        linkedIssuance: first.operation_issuance_id,
        retry: new Uint8Array(retry.canonical_bytes),
      };
    });

    expect(result.calls).toBe(1);
    expect(result.first).toEqual(result.retry);
    expect(result.issuanceState).toBe("RECORD_APPENDED");
    expect(result.linkedIssuance).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it("collapses overlapping identical freeze-and-append calls after the winner commits", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-overlap-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      const [first, second] = await Promise.all([
        lifecycle.freezeAndAppend(journal.issuanceId),
        lifecycle.freezeAndAppend(journal.issuanceId),
      ]);
      return {
        count: state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
        first: new Uint8Array(first.canonical_bytes),
        second: new Uint8Array(second.canonical_bytes),
      };
    });

    expect(result.count).toBe(1);
    expect(result.first).toEqual(result.second);
  });

  it("rejects a source mutation across materialization without appending a record", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-lifecycle-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer(() => {
        state.storage.sql.exec(
          `UPDATE activation_operation_slots SET result_bytes = x'7b7d'
           WHERE issuance_id = ? AND slot_id = 'CLOUDFLARE_BATCH'`,
          journal.issuanceId,
        );
      });
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT",
      );
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      ).toBe(0);
    });
  });

  it("rejects materializer mutations of the owned anchor snapshot", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-anchor-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer((source) => {
        const first = source.anchors[0];
        if (first === undefined) throw new Error("missing anchor fixture");
        first.record_id = `sha256:${"f".repeat(64)}`;
      });
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT",
      );
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      ).toBe(0);
    });
  });

  it("rejects materializer mutations of the decoded semantic request", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-semantic-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer((source) => {
        source.semanticRequest.evidence = { attacker: true };
      });
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT",
      );
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      ).toBe(0);
    });
  });

  it("rejects materializer mutations of the owned record clock", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-clock-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer((source) => {
        Object.assign(source.issuance, { record_committed_at: "2026-08-15T12:00:59.000Z" });
      });
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT",
      );
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      ).toBe(0);
    });
  });

  it("rejects materializer mutations of the owned issuance window", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-window-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer((source) => {
        Object.assign(source.issuance, { issued_at: "2026-08-15T11:59:59.000Z" });
      });
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_RECORD_SOURCE_CONFLICT",
      );
    });
  });

  it("rolls back a self-consistent record with the wrong internal request id", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-request-fence-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, {
        materialize: async (source) => {
          const materialized = await fixture.materializer.materialize(source);
          const withoutId: JsonObject = {
            ...materialized,
            request_id: "activation-wrong-request-0001",
          };
          delete withoutId.record_id;
          return {
            ...withoutId,
            record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
          };
        },
      });

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_RECORD_CONTEXT_CONFLICT",
      );
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>("SELECT COUNT(*) AS count FROM activation_records")
          .one().count,
      ).toBe(0);
      expect(
        state.storage.sql
          .exec<{
            readonly state: string;
          }>(
            "SELECT state FROM activation_operation_issuances WHERE issuance_id = ?",
            journal.issuanceId,
          )
          .one().state,
      ).toBe("READY_TO_APPEND");
    });
  });

  it("stores the exact generic-WORM result and confirms record, issuance, and intent atomically", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-lifecycle-confirm-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      await lifecycle.freezeAndAppend(journal.issuanceId);
      const next = await lifecycle.nextRecordWorm(journal.issuanceId);
      const resultBytes = confirmedRecordWormResult(next.effect);
      const confirmed = await lifecycle.confirmRecordWorm(journal.issuanceId, resultBytes);
      const retry = await lifecycle.confirmRecordWorm(journal.issuanceId, resultBytes);
      const complete = await lifecycle.nextRecordWorm(journal.issuanceId);
      const operation = state.storage.sql
        .exec<{
          readonly intent_state: string;
          readonly result_bytes: ArrayBuffer;
          readonly state: string;
        }>(
          `SELECT issuance.state, issuance.record_worm_result_bytes AS result_bytes,
                  intent.state AS intent_state
           FROM activation_operation_issuances AS issuance
           JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
           WHERE issuance.issuance_id = ?`,
          journal.issuanceId,
        )
        .one();
      return {
        action: next.action,
        completeAction: complete.action,
        effectId: next.effect.effectId,
        expectedResultBytes: resultBytes,
        intentState: operation.intent_state,
        recordVersion: confirmed.worm_version_id,
        requestId: next.requestId,
        resultBytes: new Uint8Array(operation.result_bytes),
        retryVersion: retry.worm_version_id,
        state: operation.state,
      };
    });

    expect(result).toMatchObject({
      action: "EXECUTE_EFFECT",
      completeAction: "COMPLETE",
      intentState: "CONFIRMED",
      recordVersion: "4_z-activation-record-0001",
      retryVersion: "4_z-activation-record-0001",
      state: "CONFIRMED",
    });
    expect(result.requestId).toMatch(/^activation-[0-9a-f]{64}$/u);
    expect(result.resultBytes).toEqual(result.expectedResultBytes);
  });

  it("rejects a different exact result after confirmation", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-lifecycle-result-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      await lifecycle.freezeAndAppend(journal.issuanceId);
      const next = await lifecycle.nextRecordWorm(journal.issuanceId);
      const resultBytes = confirmedRecordWormResult(next.effect);
      await lifecycle.confirmRecordWorm(journal.issuanceId, resultBytes);
      const drift = JSON.parse(new TextDecoder().decode(resultBytes)) as JsonObject;
      drift.absence_inventory_sha256 = `sha256:${"f".repeat(64)}`;

      await expect(
        lifecycle.confirmRecordWorm(journal.issuanceId, canonicalBytes(drift)),
      ).rejects.toThrow("ACTIVATION_RECORD_WORM_RESULT_CONFLICT");
    });
  });

  it("rejects a linked record whose durable operation context was changed", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-context-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      await lifecycle.freezeAndAppend(journal.issuanceId);
      state.storage.sql.exec(
        `UPDATE activation_records SET request_digest = ? WHERE operation_issuance_id = ?`,
        `sha256:${"f".repeat(64)}`,
        journal.issuanceId,
      );

      await expect(lifecycle.freezeAndAppend(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_RECORD_CONTEXT_CONFLICT",
      );
      expect(fixture.calls()).toBe(1);
    });
  });

  it("rejects disagreement between confirmed issuance and intent states", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-intent-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      await lifecycle.freezeAndAppend(journal.issuanceId);
      state.storage.sql.exec(
        `UPDATE activation_operation_intents SET state = 'CONFIRMED' WHERE attempt_id = ?`,
        journal.issuance.attemptId,
      );

      await expect(lifecycle.nextRecordWorm(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_OPERATION_INTENT_STATE_CONFLICT",
      );
    });
  });

  it("cross-checks the stored activation WORM tuple on a completed retry", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("activation-record-worm-drift-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await readyRecordJournal(state.storage);
      const fixture = recordMaterializer();
      const lifecycle = new ActivationOperationRecordLifecycle(state.storage, fixture.materializer);
      await lifecycle.freezeAndAppend(journal.issuanceId);
      const next = await lifecycle.nextRecordWorm(journal.issuanceId);
      await lifecycle.confirmRecordWorm(journal.issuanceId, confirmedRecordWormResult(next.effect));
      state.storage.sql.exec(
        `UPDATE activation_records SET worm_version_id = ? WHERE operation_issuance_id = ?`,
        "4_z-tampered-activation-version",
        journal.issuanceId,
      );

      await expect(lifecycle.nextRecordWorm(journal.issuanceId)).rejects.toThrow(
        "ACTIVATION_WORM_VERSION_CONFLICT",
      );
    });
  });
});
