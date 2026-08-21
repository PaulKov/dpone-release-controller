import { ActivationOperationEffectQueries } from "./activation-operation-effect-queries";
import { ActivationOperationCloudflareConfirmation } from "./activation-operation-cloudflare-confirmation";
import { parseActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import { ActivationOperationReadiness } from "./activation-operation-readiness";
import {
  ActivationOperationProvisionDelegation,
  type ProvisionEffectDelegation,
} from "./activation-operation-provision-delegation";
import {
  assertCloudflareBatchDelegation,
  assertOperationDelegation,
  cloudflareBatchPinsSnapshot,
  validateCloudflareBatchPins,
  validateOperationPins,
  type ActivationOperationExecutorPins,
} from "./activation-operation-pins";
import {
  assertConfirmedOperationEffect,
  assertOperationDelegationChronology,
  operationEffectDigest,
  operationEffectFail,
  operationExactResultSnapshot,
  operationRequestSnapshot,
  requireOperationSlot,
  requireOperationTimestamp,
} from "./activation-operation-effects-validation";
import {
  prepareDirectOperationEffect,
  rebuildDirectOperationEffect,
} from "./activation-operation-direct-effect";
import {
  assertStoredOperationBytes,
  operationBytesEqual,
} from "./activation-operation-store-validation";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import { initializeActivationRegistrySchema } from "./activation-registry-schema";
import { parseWormExactObjectEffectResult } from "./worm-exact-object-effect-result";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

export type { ActivationCloudflareAnchor } from "./activation-operation-effects-validation";
export type {
  ActivationCloudflareBatchPins,
  ActivationOperationExecutorPins,
} from "./activation-operation-pins";

export type ActivationCloudflareDelegationAction = "COMPLETE" | "OBSERVE_AND_SEAL" | "RESUME_BATCH";
export type ActivationDirectDelegationAction = "COMPLETE" | "EXECUTE_EFFECT";

/** Durable delegated-effect and result transitions for operation slots. */
export class ActivationOperationEffects {
  private readonly sql: SqlStorage;
  private readonly cloudflareConfirmation: ActivationOperationCloudflareConfirmation;
  private readonly provisionDelegation: ActivationOperationProvisionDelegation;
  private readonly queries: ActivationOperationEffectQueries;
  private readonly readiness: ActivationOperationReadiness;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly now: () => number = Date.now,
  ) {
    this.sql = storage.sql;
    initializeActivationRegistrySchema(this.sql);
    this.queries = new ActivationOperationEffectQueries(this.sql);
    this.cloudflareConfirmation = new ActivationOperationCloudflareConfirmation(
      storage,
      this.sql,
      this.queries,
    );
    this.provisionDelegation = new ActivationOperationProvisionDelegation(
      storage,
      this.sql,
      this.queries,
      now,
    );
    this.readiness = new ActivationOperationReadiness(this.sql, this.queries);
  }

  /** Seal all four A0 effect authorizations in one SQLite transaction. */
  public delegateProvision(
    issuanceId: string,
    canonicalCloudflareRequestBytes: Uint8Array,
  ): Promise<ProvisionEffectDelegation> {
    return this.provisionDelegation.seal(issuanceId, canonicalCloudflareRequestBytes);
  }

  public async delegate(
    issuanceId: string,
    slotId: string,
    committedAt: string,
    pins: ActivationOperationExecutorPins,
  ): Promise<{
    readonly action: ActivationDirectDelegationAction;
    readonly effect: PreparedWormExactObjectEffect;
    readonly slot: ActivationOperationSlotRow;
  }> {
    validateOperationPins(pins);
    requireOperationTimestamp(committedAt);
    const initial = requireOperationSlot(this.queries.slot(issuanceId, slotId));
    this.queries.requireCurrent(issuanceId, true);
    if (initial.slot_kind !== "DIRECT_WORM") {
      operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
    }
    const effect = await prepareDirectOperationEffect(
      initial,
      this.queries.ingressWorkerVersion(issuanceId),
      committedAt,
      pins,
    );
    const issuance = this.queries.requireCurrent(issuanceId, true);
    const row = requireOperationSlot(this.queries.slot(issuanceId, slotId));
    if (
      row.frozen_payload_sha256 !== effect.digest ||
      row.frozen_payload_bytes === null ||
      !operationBytesEqual(new Uint8Array(row.frozen_payload_bytes), effect.canonicalBytes)
    ) {
      operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT");
    }
    const nowMs = this.now();
    if (row.state === "DELEGATED_IN_FLIGHT" || row.state === "CONFIRMED") {
      assertOperationDelegation(row, effect.effectId, committedAt, pins);
      return {
        action: row.state === "CONFIRMED" ? "COMPLETE" : "EXECUTE_EFFECT",
        effect,
        slot: row,
      };
    }
    if (issuance.state === "DISPATCHED_HOLD" || row.state !== "FROZEN") {
      operationEffectFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
    }
    if (
      nowMs > Date.parse(issuance.fresh_until) ||
      Date.parse(committedAt) > Date.parse(issuance.fresh_until)
    ) {
      this.queries.expireIssuance(issuanceId);
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_EXPIRED");
    }
    assertOperationDelegationChronology(issuance, row, committedAt, nowMs);
    this.storage.transactionSync(() => {
      this.queries.requireCurrent(issuanceId, false);
      const fenced = requireOperationSlot(this.queries.slot(issuanceId, slotId));
      if (fenced.state !== "FROZEN" || fenced.frozen_payload_sha256 !== effect.digest) {
        operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT");
      }
      this.sql.exec(
        `UPDATE activation_operation_slots SET
           batch_id = ?, effect_id = ?, committed_at = ?,
           expected_worm_key = ?,
           executor_service_identity = ?, executor_worker_version_id = ?,
           observer_service_identity = ?, observer_worker_version_id = ?,
           state = 'DELEGATED_IN_FLIGHT'
         WHERE issuance_id = ? AND slot_id = ? AND state = ?`,
        null,
        effect.effectId,
        committedAt,
        effect.key,
        pins.executorServiceIdentity,
        pins.executorWorkerVersionId,
        pins.observerServiceIdentity,
        pins.observerWorkerVersionId,
        issuanceId,
        slotId,
        "FROZEN",
      );
      this.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EFFECTS_PENDING'
         WHERE issuance_id = ? AND state IN ('RESERVED', 'COLLECTING', 'FROZEN')`,
        issuanceId,
      );
    });
    return {
      action: "EXECUTE_EFFECT",
      effect,
      slot: requireOperationSlot(this.queries.slot(issuanceId, slotId)),
    };
  }

  /** Atomically seals the outer Cloudflare request before authorizing any provider read. */
  public async delegateCloudflare(
    issuanceId: string,
    canonicalRequestBytes: Uint8Array,
  ): Promise<{
    readonly action: ActivationCloudflareDelegationAction;
    readonly slot: ActivationOperationSlotRow;
  }> {
    const requestBytes = operationRequestSnapshot(canonicalRequestBytes);
    const parsed = await parseActivationOperationCloudflareRequest(
      requestBytes,
      this.queries.cloudflareIssuance(issuanceId),
    );
    const ownedPins = cloudflareBatchPinsSnapshot(parsed.pins);
    const requestSha256 = await operationEffectDigest(requestBytes);
    validateCloudflareBatchPins(ownedPins);
    const { batchId } = parsed.binding;
    const committedAt = parsed.committedAt;
    const issuance = this.queries.requireCurrent(issuanceId, true);
    const row = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
    if (row.state === "DELEGATED_IN_FLIGHT" || row.state === "CONFIRMED") {
      assertStoredOperationBytes(
        row.provider_request_bytes,
        row.provider_request_sha256,
        requestBytes,
        requestSha256,
      );
      assertCloudflareBatchDelegation(row, batchId, committedAt, ownedPins);
      return {
        action: row.state === "CONFIRMED" ? "COMPLETE" : "RESUME_BATCH",
        slot: row,
      };
    }
    if (issuance.state === "DISPATCHED_HOLD" || row.state !== "PREPARED") {
      operationEffectFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
    }
    this.assertCloudflarePredecessors(issuanceId, committedAt);
    const nowMs = this.now();
    if (
      nowMs > Date.parse(issuance.fresh_until) ||
      Date.parse(committedAt) > Date.parse(issuance.fresh_until)
    ) {
      this.queries.expireIssuance(issuanceId);
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_EXPIRED");
    }
    assertOperationDelegationChronology(issuance, row, committedAt, nowMs);
    this.storage.transactionSync(() => {
      this.queries.requireCurrent(issuanceId, false);
      const fenced = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
      if (fenced.state !== "PREPARED") {
        operationEffectFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
      }
      this.assertCloudflarePredecessors(issuanceId, committedAt);
      this.sql.exec(
        `UPDATE activation_operation_slots SET
           provider_request_bytes = ?, provider_request_sha256 = ?, batch_id = ?, committed_at = ?,
           cloudflare_observer_service_identity = ?, cloudflare_observer_worker_version_id = ?,
           worm_service_identity = ?, worm_worker_version_id = ?,
           b2_observer_service_identity = ?, b2_observer_worker_version_id = ?,
           state = 'DELEGATED_IN_FLIGHT'
         WHERE issuance_id = ? AND slot_id = 'CLOUDFLARE_BATCH' AND state = 'PREPARED'`,
        requestBytes.buffer,
        requestSha256,
        batchId,
        committedAt,
        ownedPins.cloudflareObserverServiceIdentity,
        ownedPins.cloudflareObserverWorkerVersionId,
        ownedPins.wormServiceIdentity,
        ownedPins.wormWorkerVersionId,
        ownedPins.b2ObserverServiceIdentity,
        ownedPins.b2ObserverWorkerVersionId,
        issuanceId,
      );
      this.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EFFECTS_PENDING'
         WHERE issuance_id = ? AND state IN ('RESERVED', 'COLLECTING', 'FROZEN')`,
        issuanceId,
      );
    });
    return {
      action: "OBSERVE_AND_SEAL",
      slot: requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH")),
    };
  }

  public async confirmDirect(
    issuanceId: string,
    slotId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationOperationSlotRow> {
    this.queries.requireCurrent(issuanceId, true);
    const resultBytes = operationExactResultSnapshot(canonicalResultBytes);
    const initial = requireOperationSlot(this.queries.slot(issuanceId, slotId));
    const expected = await rebuildDirectOperationEffect(
      initial,
      this.queries.ingressWorkerVersion(issuanceId),
    );
    const confirmed = parseWormExactObjectEffectResult(resultBytes, expected);
    const resultSha256 = await operationEffectDigest(resultBytes);
    this.queries.requireCurrent(issuanceId, true);
    let resolved: ActivationOperationSlotRow | undefined;
    this.storage.transactionSync(() => {
      this.queries.requireCurrent(issuanceId, true);
      const row = requireOperationSlot(this.queries.slot(issuanceId, slotId));
      if (row.slot_kind !== "DIRECT_WORM")
        operationEffectFail("ACTIVATION_OPERATION_SLOT_KIND_INVALID");
      if (row.state === "CONFIRMED") {
        assertConfirmedOperationEffect(row, resultBytes, resultSha256, confirmed.worm);
        resolved = row;
        return;
      }
      if (row.state !== "DELEGATED_IN_FLIGHT") {
        operationEffectFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
      }
      this.queries.confirmDirect(row, resultBytes, resultSha256, confirmed.worm);
      resolved = requireOperationSlot(this.queries.slot(issuanceId, slotId));
    });
    return requireOperationSlot(resolved);
  }

  public async confirmCloudflare(
    issuanceId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationOperationSlotRow> {
    return this.cloudflareConfirmation.confirm(issuanceId, canonicalResultBytes);
  }

  public readyToAppend(issuanceId: string): boolean {
    return this.readiness.readyToAppend(issuanceId);
  }

  private assertCloudflarePredecessors(issuanceId: string, committedAt: string): void {
    if (this.queries.sequence(issuanceId) === 1) return;
    const rows = this.queries.slots(issuanceId);
    const controller = rows.find((row) => row.slot_id === "CONTROLLER_ACTION");
    const direct = rows.filter((row) => row.slot_kind === "DIRECT_WORM");
    if (
      controller?.state !== "FROZEN" ||
      direct.length !== 3 ||
      direct.some(
        (row) =>
          (row.state !== "DELEGATED_IN_FLIGHT" && row.state !== "CONFIRMED") ||
          row.observed_at === null ||
          row.committed_at === null ||
          Date.parse(row.observed_at) > Date.parse(row.committed_at) ||
          Date.parse(row.committed_at) > Date.parse(committedAt),
      )
    ) {
      operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_PREDECESSOR_INVALID");
    }
  }
}
