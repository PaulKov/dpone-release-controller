import { parseActivationOperationCloudflareRequest } from "./activation-operation-cloudflare-request";
import type { ActivationOperationEffectQueries } from "./activation-operation-effect-queries";
import { assertCloudflareBatchDelegation } from "./activation-operation-pins";
import {
  assertStoredOperationAnchors,
  assertStoredOperationResult,
  operationEffectDigest,
  operationEffectFail,
  operationEffectSnapshot,
  requireOperationAnchor,
  requireOperationSlot,
  validateOperationAnchors,
  type ActivationCloudflareAnchor,
} from "./activation-operation-effects-validation";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import { parseCloudflareEvidenceBatchResultV2 } from "./cloudflare-evidence-batch-result-v2";

/** Atomic import of a single-source v2 batch result into the operation journal. */
export class ActivationOperationCloudflareConfirmation {
  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly sql: SqlStorage,
    private readonly queries: ActivationOperationEffectQueries,
  ) {}

  public async confirm(
    issuanceId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationOperationSlotRow> {
    this.queries.requireCurrent(issuanceId, true);
    const resultBytes = operationEffectSnapshot(canonicalResultBytes);
    const initial = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
    if (initial.provider_request_bytes === null) {
      operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
    }
    const delegation = await parseActivationOperationCloudflareRequest(
      new Uint8Array(initial.provider_request_bytes),
      this.queries.cloudflareIssuance(issuanceId),
    );
    const confirmed = await parseCloudflareEvidenceBatchResultV2(resultBytes, delegation);
    const anchors: readonly ActivationCloudflareAnchor[] = confirmed.records.map(
      ({ authorityRole, evidence }) => ({
        authorityRole,
        recordId: evidence.recordId,
        recordSha256: evidence.recordSha256,
        worm: evidence.worm,
      }),
    );
    const resultSha256 = await operationEffectDigest(resultBytes);
    this.queries.requireCurrent(issuanceId, true);
    const delegated = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
    assertCloudflareBatchDelegation(
      delegated,
      delegation.binding.batchId,
      delegation.committedAt,
      delegation.pins,
    );
    validateOperationAnchors(
      anchors,
      confirmed.batchSealedAt,
      delegation.binding.observerWorkerVersionId,
      delegation.binding.batchId,
    );
    let resolved: ActivationOperationSlotRow | undefined;
    this.storage.transactionSync(() => {
      const issuance = this.queries.requireCurrent(issuanceId, true);
      const row = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
      if (row.state === "CONFIRMED") {
        assertStoredOperationResult(row, resultBytes, resultSha256);
        assertStoredOperationAnchors(this.queries.anchors(issuanceId), anchors);
        if (issuance.record_committed_at !== confirmed.batchSealedAt) {
          operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_CONFLICT");
        }
        resolved = row;
        return;
      }
      if (row.slot_kind !== "CLOUDFLARE_BATCH" || row.state !== "DELEGATED_IN_FLIGHT") {
        operationEffectFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
      }
      this.insertAnchors(issuanceId, anchors);
      this.sql.exec(
        `UPDATE activation_operation_slots
         SET result_bytes = ?, result_sha256 = ?, state = 'CONFIRMED'
         WHERE issuance_id = ? AND slot_id = 'CLOUDFLARE_BATCH'
           AND state = 'DELEGATED_IN_FLIGHT'`,
        resultBytes.buffer,
        resultSha256,
        issuanceId,
      );
      this.sql.exec(
        `UPDATE activation_operation_issuances SET record_committed_at = ?
         WHERE issuance_id = ? AND record_committed_at IS NULL`,
        confirmed.batchSealedAt,
        issuanceId,
      );
      const updated = this.queries.requireCurrent(issuanceId, true);
      if (updated.record_committed_at !== confirmed.batchSealedAt) {
        operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_CONFLICT");
      }
      resolved = requireOperationSlot(this.queries.slot(issuanceId, "CLOUDFLARE_BATCH"));
    });
    return requireOperationSlot(resolved);
  }

  private insertAnchors(issuanceId: string, anchors: readonly ActivationCloudflareAnchor[]): void {
    for (let index = 0; index < anchors.length; index += 1) {
      const anchor = requireOperationAnchor(anchors[index]);
      this.sql.exec(
        `INSERT INTO activation_cloudflare_anchors(
           issuance_id, slot_index, authority_role, record_id, record_sha256,
           worm_key, worm_version_id, worm_retention_until
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        issuanceId,
        index,
        anchor.authorityRole,
        anchor.recordId,
        anchor.recordSha256,
        anchor.worm.key,
        anchor.worm.versionId,
        anchor.worm.retentionUntil,
      );
    }
  }
}
