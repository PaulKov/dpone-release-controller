import { canonicalBytes, canonicalJson } from "./canonical";
import type { ActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import type { CloudflareEvidenceBatchResumeV2 } from "./cloudflare-evidence-batch-resume-v2";
import {
  decodeCloudflareEvidenceBatchContext,
  validateCloudflareEvidenceBatchExecution,
  type CloudflareEvidenceBatchRow,
} from "./cloudflare-evidence-batch-context";
import {
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  isCloudflareEvidenceBatchBindingV2,
  type AnyCloudflareEvidenceBatchBinding,
  type CloudflareEvidenceBatchAction,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchExecution,
  type CloudflareEvidenceBatchSlot,
  type CloudflareEvidenceBatchSlotInput,
} from "./cloudflare-evidence-batch-contract";
import {
  assertCloudflareEvidenceBatchBinding,
  assertStoredCloudflareEvidenceSlots,
  assertStoredCloudflareEvidenceWorm,
  batchConflict,
  decodeCloudflareEvidenceSlot,
  expectedCloudflareEvidenceWormKey,
  requireBatchDigest,
  requireCloudflareEvidenceBatch,
  requireCloudflareEvidenceSlot,
  validateCloudflareEvidenceWorm,
  type CloudflareEvidenceSlotRow,
} from "./cloudflare-evidence-batch-validation";
import { initializeCloudflareEvidenceBatchSchema } from "./cloudflare-evidence-batch-schema";
import { prepareCloudflareEvidenceBatchSeal } from "./cloudflare-evidence-batch-seal";
import type { ActivationWorm, JsonObject } from "./types";

/** Sanitized-only durable state for one fixed fifteen-slot mirror attempt. */
export class CloudflareEvidenceBatchStore {
  private readonly sql: SqlStorage;

  public constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    initializeCloudflareEvidenceBatchSchema(this.sql);
  }

  public async seal(
    binding: AnyCloudflareEvidenceBatchBinding,
    observedAt: string,
    committedAt: string,
    observation: JsonObject,
    execution: CloudflareEvidenceBatchExecution,
    inputs: readonly CloudflareEvidenceBatchSlotInput[],
    operation?: ActivationOperationCloudflareRequest,
  ): Promise<void> {
    const prepared = await prepareCloudflareEvidenceBatchSeal({
      binding,
      committedAt,
      execution,
      observation,
      observedAt,
      ...(operation === undefined ? {} : { operation }),
      slots: inputs,
    });
    this.storage.transactionSync(() => {
      const current = this.batch();
      if (current !== undefined) {
        assertCloudflareEvidenceBatchBinding(current, binding);
        if (
          current.b2_observer_service_identity !== execution.b2ObserverServiceIdentity ||
          current.b2_observer_worker_version_id !== execution.b2ObserverWorkerVersionId ||
          current.observed_at !== prepared.observedAt ||
          current.committed_at !== prepared.committedAt ||
          canonicalJson(decodeCloudflareEvidenceBatchContext(current).observation) !==
            canonicalJson(prepared.observation) ||
          current.seal_sha256 !== prepared.sealSha256 ||
          current.provider_observation_sha256 !== prepared.providerObservationSha256 ||
          current.worm_service_identity !== execution.wormServiceIdentity ||
          current.worm_worker_version_id !== execution.wormWorkerVersionId
        ) {
          throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_SEAL_CONFLICT");
        }
        assertStoredCloudflareEvidenceSlots(prepared.slots, this.slots());
        return;
      }
      this.sql.exec(
        `INSERT INTO cloudflare_evidence_batch(
          singleton, batch_id, binding_schema_version, activation_issuance_id,
          activation_issuance_ordinal, activation_sequence,
          b2_observer_service_identity, b2_observer_worker_version_id,
          cloudflare_observer_service_identity, delegation_sha256,
          delegation_committed_at, delegation_issued_at, delegation_fresh_until,
          expectation_sha256,
          observer_worker_version_id, phase, observed_at, committed_at,
          observation_canonical_bytes, provider_observation_sha256, seal_sha256,
          status, worm_service_identity, worm_worker_version_id
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SEALED', ?, ?)`,
        binding.batchId,
        isCloudflareEvidenceBatchBindingV2(binding) ? 2 : 1,
        isCloudflareEvidenceBatchBindingV2(binding) ? binding.activationIssuanceId : null,
        isCloudflareEvidenceBatchBindingV2(binding) ? binding.activationIssuanceOrdinal : null,
        isCloudflareEvidenceBatchBindingV2(binding) ? binding.activationSequence : null,
        execution.b2ObserverServiceIdentity,
        execution.b2ObserverWorkerVersionId,
        operation?.pins.cloudflareObserverServiceIdentity ?? null,
        operation?.delegationSha256 ?? null,
        operation?.committedAt ?? null,
        operation?.issuance.issuedAt ?? null,
        operation?.freshUntil ?? null,
        binding.expectationSha256,
        binding.observerWorkerVersionId,
        binding.phase,
        prepared.observedAt,
        prepared.committedAt,
        prepared.observationBytes.buffer,
        prepared.providerObservationSha256,
        prepared.sealSha256,
        execution.wormServiceIdentity,
        execution.wormWorkerVersionId,
      );
      for (const slot of prepared.slots) {
        const bytes = canonicalBytes(slot.sanitized.record);
        this.sql.exec(
          `INSERT INTO cloudflare_evidence_slots(
            slot_index, authority_role, kind, record_id, record_sha256, expected_worm_key,
            canonical_bytes, committed_at, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')`,
          slot.slotIndex,
          slot.authorityRole,
          slot.kind,
          slot.sanitized.recordId,
          slot.sanitized.recordSha256,
          expectedCloudflareEvidenceWormKey(binding, slot.kind, slot.sanitized.recordId),
          Uint8Array.from(bytes).buffer,
          prepared.committedAt,
        );
      }
    });
  }

  /** Return the one sealed context only when the current executor pins match. */
  public resume(
    expectedBatchId: string,
    execution: CloudflareEvidenceBatchExecution,
  ): CloudflareEvidenceBatchContext | undefined {
    validateCloudflareEvidenceBatchExecution(execution);
    const row = this.batch();
    if (row === undefined) return undefined;
    if (
      row.batch_id !== expectedBatchId ||
      row.b2_observer_service_identity !== execution.b2ObserverServiceIdentity ||
      row.b2_observer_worker_version_id !== execution.b2ObserverWorkerVersionId ||
      row.worm_service_identity !== execution.wormServiceIdentity ||
      row.worm_worker_version_id !== execution.wormWorkerVersionId
    ) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_EXECUTION_CONFLICT");
    }
    return decodeCloudflareEvidenceBatchContext(row);
  }

  /** Resume one v2 batch from its signed identity without raw provider bytes. */
  public resumeV2(
    expected: CloudflareEvidenceBatchResumeV2,
    execution: CloudflareEvidenceBatchExecution,
  ): CloudflareEvidenceBatchContext | undefined {
    const context = this.resume(expected.binding.batchId, execution);
    if (context === undefined) return undefined;
    if (
      !isCloudflareEvidenceBatchBindingV2(context.binding) ||
      context.operation === null ||
      context.binding.activationIssuanceId !== expected.binding.activationIssuanceId ||
      context.binding.activationIssuanceOrdinal !== expected.binding.activationIssuanceOrdinal ||
      context.binding.activationSequence !== expected.binding.activationSequence ||
      context.operation.delegationSha256 !== expected.delegationSha256
    ) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_BINDING_CONFLICT");
    }
    return context;
  }

  public next(slotIndex: number): CloudflareEvidenceBatchAction {
    const batch = requireCloudflareEvidenceBatch(this.batch());
    const row = requireCloudflareEvidenceSlot(this.slot(slotIndex));
    if (batch.status === "HOLD") {
      if (row.status === "IN_FLIGHT" || row.status === "ACCEPTED") {
        return { action: "RECONCILE", slot: decodeCloudflareEvidenceSlot(row) };
      }
      if (row.status === "CONFIRMED") {
        return { action: "COMPLETE", slot: decodeCloudflareEvidenceSlot(row) };
      }
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_NOT_DISPATCHABLE");
    }
    if (row.status === "PREPARED") {
      return { action: "CHECK_ABSENCE", slot: decodeCloudflareEvidenceSlot(row) };
    }
    if (row.status === "ABSENT") {
      this.sql.exec(
        `UPDATE cloudflare_evidence_slots SET status = 'IN_FLIGHT'
         WHERE slot_index = ? AND status = 'ABSENT'`,
        slotIndex,
      );
      return {
        action: "DISPATCH",
        slot: decodeCloudflareEvidenceSlot(requireCloudflareEvidenceSlot(this.slot(slotIndex))),
      };
    }
    if (row.status === "IN_FLIGHT" || row.status === "ACCEPTED") {
      return { action: "RECONCILE", slot: decodeCloudflareEvidenceSlot(row) };
    }
    if (row.status === "CONFIRMED") {
      return { action: "COMPLETE", slot: decodeCloudflareEvidenceSlot(row) };
    }
    throw batchConflict("CLOUDFLARE_EVIDENCE_SLOT_STATE_CONFLICT");
  }

  public markAbsent(slotIndex: number, inventorySha256: string): void {
    requireBatchDigest(inventorySha256);
    this.storage.transactionSync(() => {
      const row = requireCloudflareEvidenceSlot(this.slot(slotIndex));
      if (row.status === "ABSENT" && row.worm_digest === null) {
        if (row.absence_inventory_sha256 !== inventorySha256) {
          throw batchConflict("CLOUDFLARE_EVIDENCE_ABSENCE_CONFLICT");
        }
        return;
      }
      if (row.status !== "PREPARED") {
        throw batchConflict("CLOUDFLARE_EVIDENCE_SLOT_STATE_CONFLICT");
      }
      this.sql.exec(
        `UPDATE cloudflare_evidence_slots
         SET absence_inventory_sha256 = ?, status = 'ABSENT'
         WHERE slot_index = ? AND status = 'PREPARED'`,
        inventorySha256,
        slotIndex,
      );
    });
  }

  public accept(slotIndex: number, writerVersionId: string): void {
    if (writerVersionId.length === 0 || writerVersionId.length > 512) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WRITER_VERSION_INVALID");
    }
    this.storage.transactionSync(() => {
      const row = requireCloudflareEvidenceSlot(this.slot(slotIndex));
      if (row.status === "ACCEPTED") {
        if (row.writer_version_id !== writerVersionId) {
          throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WRITER_VERSION_CONFLICT");
        }
        return;
      }
      if (row.status !== "IN_FLIGHT") {
        throw batchConflict("CLOUDFLARE_EVIDENCE_SLOT_STATE_CONFLICT");
      }
      const alias = this.sql
        .exec<{ readonly count: number }>(
          `SELECT COUNT(*) AS count FROM cloudflare_evidence_slots
           WHERE writer_version_id = ? OR worm_version_id = ?`,
          writerVersionId,
          writerVersionId,
        )
        .one().count;
      if (alias !== 0) {
        throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WRITER_VERSION_CONFLICT");
      }
      this.sql.exec(
        `UPDATE cloudflare_evidence_slots
         SET writer_version_id = ?, status = 'ACCEPTED'
         WHERE slot_index = ? AND status = 'IN_FLIGHT'`,
        writerVersionId,
        slotIndex,
      );
    });
  }

  public confirm(slotIndex: number, worm: ActivationWorm): void {
    this.storage.transactionSync(() => {
      const row = requireCloudflareEvidenceSlot(this.slot(slotIndex));
      const accepted = validateCloudflareEvidenceWorm(row, worm);
      if (row.status === "CONFIRMED") {
        assertStoredCloudflareEvidenceWorm(row, accepted);
        return;
      }
      if (row.status !== "IN_FLIGHT" && row.status !== "ACCEPTED") {
        throw batchConflict("CLOUDFLARE_EVIDENCE_SLOT_STATE_CONFLICT");
      }
      if (row.status === "ACCEPTED" && row.writer_version_id !== accepted.versionId) {
        throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_WRITER_VERSION_CONFLICT");
      }
      this.updateWorm(slotIndex, accepted, "CONFIRMED");
      const remaining = this.sql
        .exec<{
          readonly count: number;
        }>(`SELECT COUNT(*) AS count FROM cloudflare_evidence_slots WHERE status != 'CONFIRMED'`)
        .one().count;
      if (remaining === 0) {
        this.sql.exec(
          `UPDATE cloudflare_evidence_batch SET status = 'CONFIRMED'
           WHERE singleton = 1 AND status = 'SEALED'`,
        );
      }
    });
  }

  public hold(slotIndex: number): void {
    this.storage.transactionSync(() => {
      this.sql.exec(
        `UPDATE cloudflare_evidence_slots SET status = 'HOLD'
         WHERE slot_index = ? AND status != 'CONFIRMED'`,
        slotIndex,
      );
      this.sql.exec(
        `UPDATE cloudflare_evidence_batch SET status = 'HOLD'
         WHERE singleton = 1 AND status != 'CONFIRMED'`,
      );
    });
  }

  public confirmed(): readonly CloudflareEvidenceBatchSlot[] {
    const batch = requireCloudflareEvidenceBatch(this.batch());
    const rows = this.slots();
    if (batch.status !== "CONFIRMED" || rows.length !== CLOUDFLARE_EVIDENCE_SLOT_COUNT) {
      throw batchConflict("CLOUDFLARE_EVIDENCE_BATCH_PENDING");
    }
    return Object.freeze(rows.map(decodeCloudflareEvidenceSlot));
  }

  private updateWorm(slotIndex: number, worm: ActivationWorm, status: string): void {
    this.sql.exec(
      `UPDATE cloudflare_evidence_slots
       SET worm_digest = ?, worm_key = ?, worm_version_id = ?,
           worm_retention_until = ?, status = ?
       WHERE slot_index = ?`,
      worm.digest,
      worm.key,
      worm.versionId,
      worm.retentionUntil,
      status,
      slotIndex,
    );
  }

  private batch(): CloudflareEvidenceBatchRow | undefined {
    return this.sql
      .exec<CloudflareEvidenceBatchRow>(`SELECT * FROM cloudflare_evidence_batch`)
      .toArray()[0];
  }

  private slot(slotIndex: number): CloudflareEvidenceSlotRow | undefined {
    return this.sql
      .exec<CloudflareEvidenceSlotRow>(
        `SELECT * FROM cloudflare_evidence_slots WHERE slot_index = ?`,
        slotIndex,
      )
      .toArray()[0];
  }

  private slots(): readonly CloudflareEvidenceSlotRow[] {
    return this.sql
      .exec<CloudflareEvidenceSlotRow>(
        `SELECT * FROM cloudflare_evidence_slots ORDER BY slot_index ASC`,
      )
      .toArray();
  }
}
