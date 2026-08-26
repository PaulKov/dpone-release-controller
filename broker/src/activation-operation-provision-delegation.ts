import { parseActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import { prepareDirectOperationEffect } from "./activation-operation-direct-effect";
import type { ActivationOperationEffectQueries } from "./activation-operation-effect-queries";
import {
  assertOperationDelegationChronology,
  operationEffectDigest,
  operationEffectFail,
  operationRequestSnapshot,
  requireOperationSlot,
} from "./activation-operation-effects-validation";
import {
  assertCloudflareBatchDelegation,
  assertOperationDelegation,
  type ActivationCloudflareBatchPins,
  type ActivationOperationExecutorPins,
} from "./activation-operation-pins";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import {
  assertStoredOperationBytes,
  operationBytesEqual,
} from "./activation-operation-store-validation";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

const DIRECT_SLOT_IDS = ["CONTROLLER_OIDC", "TARGET_OIDC", "TARGET_RULESET"] as const;

export interface ProvisionDirectDelegation {
  readonly action: "COMPLETE" | "EXECUTE_EFFECT";
  readonly effect: PreparedWormExactObjectEffect;
  readonly slotId: (typeof DIRECT_SLOT_IDS)[number];
}

export interface ProvisionEffectDelegation {
  readonly cloudflareAction: "COMPLETE" | "OBSERVE_AND_SEAL" | "RESUME_BATCH";
  readonly direct: readonly ProvisionDirectDelegation[];
}

/** Atomically seals the complete A0 external-effect plan before any remote call. */
export class ActivationOperationProvisionDelegation {
  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly sql: SqlStorage,
    private readonly queries: ActivationOperationEffectQueries,
    private readonly now: () => number,
  ) {}

  public async seal(
    issuanceId: string,
    canonicalCloudflareRequestBytes: Uint8Array,
  ): Promise<ProvisionEffectDelegation> {
    const requestBytes = operationRequestSnapshot(canonicalCloudflareRequestBytes);
    const delegation = await parseActivationOperationCloudflareRequest(
      requestBytes,
      this.queries.cloudflareIssuance(issuanceId),
    );
    const requestSha256 = await operationEffectDigest(requestBytes);
    const directPins = pinsFromDelegation(delegation.pins);
    this.queries.requireCurrent(issuanceId, true);
    const initial = this.rows(issuanceId);
    const prepared = await Promise.all(
      initial.direct.map(async (row) => ({
        effect: await prepareDirectOperationEffect(
          row,
          this.queries.ingressWorkerVersion(issuanceId),
          delegation.committedAt,
          directPins,
        ),
        row,
      })),
    );
    const issuance = this.queries.requireCurrent(issuanceId, true);
    const rows = this.rows(issuanceId);
    const sealed = rows.direct.every((row) => isDelegated(row)) && isDelegated(rows.cloudflare);
    if (sealed) {
      return this.assertSealed(
        rows,
        prepared.map(({ effect }) => effect),
        delegation.binding.batchId,
        delegation.committedAt,
        delegation.pins,
        directPins,
        requestBytes,
        requestSha256,
        false,
      );
    }
    if (
      issuance.state === "DISPATCHED_HOLD" ||
      rows.direct.some((row) => row.state !== "FROZEN") ||
      rows.cloudflare.state !== "PREPARED"
    ) {
      operationEffectFail("ACTIVATION_OPERATION_PROVISION_DELEGATION_PARTIAL");
    }
    const nowMs = this.now();
    if (
      nowMs > Date.parse(issuance.fresh_until) ||
      Date.parse(delegation.committedAt) > Date.parse(issuance.fresh_until)
    ) {
      this.queries.expireIssuance(issuanceId);
      operationEffectFail("ACTIVATION_OPERATION_ISSUANCE_EXPIRED");
    }
    this.assertChronology(issuanceId, rows, delegation.committedAt, nowMs);
    let concurrent = false;
    this.storage.transactionSync(() => {
      this.queries.requireCurrent(issuanceId, false);
      const fenced = this.rows(issuanceId);
      if (fenced.direct.every((row) => isDelegated(row)) && isDelegated(fenced.cloudflare)) {
        concurrent = true;
        return;
      }
      if (
        fenced.direct.some((row) => row.state !== "FROZEN") ||
        fenced.cloudflare.state !== "PREPARED"
      ) {
        operationEffectFail("ACTIVATION_OPERATION_PROVISION_DELEGATION_PARTIAL");
      }
      prepared.forEach(({ effect, row }) => this.sealDirect(row, effect, directPins));
      this.sealCloudflare(
        issuanceId,
        requestBytes,
        requestSha256,
        delegation.binding.batchId,
        delegation.committedAt,
        delegation.pins,
      );
      this.sql.exec(
        `UPDATE activation_operation_issuances SET state = 'EFFECTS_PENDING'
         WHERE issuance_id = ? AND state IN ('RESERVED', 'COLLECTING', 'FROZEN')`,
        issuanceId,
      );
    });
    const sealedRows = this.rows(issuanceId);
    return this.assertSealed(
      sealedRows,
      prepared.map(({ effect }) => effect),
      delegation.binding.batchId,
      delegation.committedAt,
      delegation.pins,
      directPins,
      requestBytes,
      requestSha256,
      !concurrent,
    );
  }

  private rows(issuanceId: string): ProvisionRows {
    const rows = this.queries.slots(issuanceId);
    const controller = requireOperationSlot(
      rows.find((row) => row.slot_id === "CONTROLLER_ACTION"),
    );
    const direct = DIRECT_SLOT_IDS.map((slotId) =>
      requireOperationSlot(rows.find((row) => row.slot_id === slotId)),
    );
    const cloudflare = requireOperationSlot(rows.find((row) => row.slot_id === "CLOUDFLARE_BATCH"));
    if (controller.state !== "FROZEN" || direct.some((row) => row.slot_kind !== "DIRECT_WORM")) {
      operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_PREDECESSOR_INVALID");
    }
    return { cloudflare, controller, direct };
  }

  private assertChronology(
    issuanceId: string,
    rows: ProvisionRows,
    committedAt: string,
    nowMs: number,
  ): void {
    const issuance = this.queries.requireCurrent(issuanceId, false);
    if (
      rows.controller.observed_at === null ||
      Date.parse(rows.controller.observed_at) > Date.parse(committedAt)
    ) {
      operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_PREDECESSOR_INVALID");
    }
    rows.direct.forEach((row) =>
      assertOperationDelegationChronology(issuance, row, committedAt, nowMs),
    );
  }

  private sealDirect(
    row: ActivationOperationSlotRow,
    effect: PreparedWormExactObjectEffect,
    pins: ActivationOperationExecutorPins,
  ): void {
    if (
      row.frozen_payload_sha256 !== effect.digest ||
      row.frozen_payload_bytes === null ||
      !operationBytesEqual(new Uint8Array(row.frozen_payload_bytes), effect.canonicalBytes)
    ) {
      operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_CONFLICT");
    }
    this.sql.exec(
      `UPDATE activation_operation_slots SET
         effect_id = ?, committed_at = ?, expected_worm_key = ?,
         executor_service_identity = ?, executor_worker_version_id = ?,
         observer_service_identity = ?, observer_worker_version_id = ?,
         state = 'DELEGATED_IN_FLIGHT'
       WHERE issuance_id = ? AND slot_id = ? AND state = 'FROZEN'`,
      effect.effectId,
      effect.committedAt,
      effect.key,
      pins.executorServiceIdentity,
      pins.executorWorkerVersionId,
      pins.observerServiceIdentity,
      pins.observerWorkerVersionId,
      row.issuance_id,
      row.slot_id,
    );
  }

  private sealCloudflare(
    issuanceId: string,
    bytes: Uint8Array,
    digest: string,
    batchId: string,
    committedAt: string,
    pins: ActivationCloudflareBatchPins,
  ): void {
    this.sql.exec(
      `UPDATE activation_operation_slots SET
         provider_request_bytes = ?, provider_request_sha256 = ?, batch_id = ?, committed_at = ?,
         cloudflare_observer_service_identity = ?, cloudflare_observer_worker_version_id = ?,
         worm_service_identity = ?, worm_worker_version_id = ?,
         b2_observer_service_identity = ?, b2_observer_worker_version_id = ?,
         state = 'DELEGATED_IN_FLIGHT'
       WHERE issuance_id = ? AND slot_id = 'CLOUDFLARE_BATCH' AND state = 'PREPARED'`,
      bytes.buffer,
      digest,
      batchId,
      committedAt,
      pins.cloudflareObserverServiceIdentity,
      pins.cloudflareObserverWorkerVersionId,
      pins.wormServiceIdentity,
      pins.wormWorkerVersionId,
      pins.b2ObserverServiceIdentity,
      pins.b2ObserverWorkerVersionId,
      issuanceId,
    );
  }

  private assertSealed(
    rows: ProvisionRows,
    effects: readonly PreparedWormExactObjectEffect[],
    batchId: string,
    committedAt: string,
    pins: ActivationCloudflareBatchPins,
    directPins: ActivationOperationExecutorPins,
    requestBytes: Uint8Array,
    requestSha256: string,
    newlySealed: boolean,
  ): ProvisionEffectDelegation {
    const direct = rows.direct.map((row, index) => {
      const effect = effects[index];
      if (effect === undefined) operationEffectFail("ACTIVATION_OPERATION_SLOT_MISSING", 500);
      assertOperationDelegation(row, effect.effectId, committedAt, directPins);
      return {
        action: row.state === "CONFIRMED" ? "COMPLETE" : "EXECUTE_EFFECT",
        effect,
        slotId: DIRECT_SLOT_IDS[index] ?? operationEffectFail("ACTIVATION_OPERATION_SLOT_MISSING"),
      } as const;
    });
    assertStoredOperationBytes(
      rows.cloudflare.provider_request_bytes,
      rows.cloudflare.provider_request_sha256,
      requestBytes,
      requestSha256,
    );
    assertCloudflareBatchDelegation(rows.cloudflare, batchId, committedAt, pins);
    return {
      cloudflareAction:
        rows.cloudflare.state === "CONFIRMED"
          ? "COMPLETE"
          : newlySealed
            ? "OBSERVE_AND_SEAL"
            : "RESUME_BATCH",
      direct,
    };
  }
}

interface ProvisionRows {
  readonly cloudflare: ActivationOperationSlotRow;
  readonly controller: ActivationOperationSlotRow;
  readonly direct: readonly ActivationOperationSlotRow[];
}

function pinsFromDelegation(pins: ActivationCloudflareBatchPins): ActivationOperationExecutorPins {
  return {
    executorServiceIdentity: pins.wormServiceIdentity,
    executorWorkerVersionId: pins.wormWorkerVersionId,
    observerServiceIdentity: pins.b2ObserverServiceIdentity,
    observerWorkerVersionId: pins.b2ObserverWorkerVersionId,
  };
}

function isDelegated(row: ActivationOperationSlotRow): boolean {
  return row.state === "CONFIRMED" || row.state === "DELEGATED_IN_FLIGHT";
}
