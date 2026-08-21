import {
  type ActivationOperationIdentity,
  type ActivationOperationIssuance,
  type ActivationOperationSequence,
  type ActivationOperationSlotId,
} from "./activation-operation-contract";
import { activationOperationIssuanceIdentity } from "./activation-operation-identity";
import { ActivationOperationEffectQueries } from "./activation-operation-effect-queries";
import {
  assertActivationIssuanceExpired,
  classifyStaleActivationIssuance,
} from "./activation-operation-reissue-policy";
import {
  type ActivationOperationIntentRow,
  type ActivationOperationIssuanceRow,
  type ActivationOperationSlotRow,
} from "./activation-operation-schema";
import { initializeActivationRegistrySchema } from "./activation-registry-schema";
import {
  assertSameOperationIntent,
  assertStoredOperationBytes,
  boundedOperationSnapshot,
  canonicalOperationTimestamp,
  operationBytesDigest,
  operationIssuanceView,
  operationStoreFail,
  requireCanonicalOperationTimestamp,
  requireOperationIssuance,
  requireOperationStoreSlot,
  validateOperationIdentity,
} from "./activation-operation-store-validation";
import {
  collectActivationOperationIssuance,
  insertActivationOperationIssuance,
} from "./activation-operation-store-writes";
import { WORM_EXACT_OBJECT_MAX_BYTES } from "./worm-exact-object-effect-contract";

const ISSUANCE_FRESHNESS_MS = 60_000;

/** Version-local durable authority for semantic attempts and fixed evidence slots. */
export class ActivationOperationStore {
  private readonly sql: SqlStorage;
  private readonly queries: ActivationOperationEffectQueries;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly now: () => number = Date.now,
  ) {
    this.sql = storage.sql;
    initializeActivationRegistrySchema(this.sql);
    this.queries = new ActivationOperationEffectQueries(this.sql);
  }

  public async reserve(
    identity: ActivationOperationIdentity,
    nowMs: number,
  ): Promise<ActivationOperationIssuance> {
    const ownedSemanticBytes = boundedOperationSnapshot(identity.semanticRequestBytes, 65_536);
    const normalizedIdentity = await validateOperationIdentity(identity, ownedSemanticBytes);
    const issuedAt = canonicalOperationTimestamp(nowMs);
    const freshUntil = canonicalOperationTimestamp(nowMs + ISSUANCE_FRESHNESS_MS);
    const current = this.intent(normalizedIdentity.sequence);
    if (current !== undefined) assertSameOperationIntent(current, normalizedIdentity);
    const existing = this.latest(normalizedIdentity.attemptId);
    if (existing !== undefined) return operationIssuanceView(existing, normalizedIdentity.sequence);
    const ordinal = 1;
    const issuanceIdentity = await activationOperationIssuanceIdentity(
      normalizedIdentity.attemptId,
      ordinal,
    );
    this.storage.transactionSync(() => {
      const concurrentIntent = this.intent(normalizedIdentity.sequence);
      if (concurrentIntent === undefined) {
        this.sql.exec(
          `INSERT INTO activation_operation_intents(
             sequence, attempt_id, intent_sha256, semantic_request_bytes,
             worker_version_id, created_at, state
           ) VALUES (?, ?, ?, ?, ?, ?, 'OPEN')`,
          normalizedIdentity.sequence,
          normalizedIdentity.attemptId,
          normalizedIdentity.intentSha256,
          normalizedIdentity.semanticRequestBytes.buffer,
          normalizedIdentity.workerVersionId,
          issuedAt,
        );
      } else {
        assertSameOperationIntent(concurrentIntent, normalizedIdentity);
      }
      const concurrent = this.latest(normalizedIdentity.attemptId);
      if (concurrent !== undefined) return;
      insertActivationOperationIssuance(
        this.sql,
        normalizedIdentity,
        ordinal,
        issuanceIdentity,
        issuedAt,
        freshUntil,
      );
    });
    return operationIssuanceView(
      requireOperationIssuance(this.latest(normalizedIdentity.attemptId)),
      normalizedIdentity.sequence,
    );
  }

  /** Issue the next broker-owned ordinal only after the prior issuance is stale and safe. */
  public async reissueStale(
    identity: ActivationOperationIdentity,
    nowMs: number,
  ): Promise<ActivationOperationIssuance> {
    const ownedSemanticBytes = boundedOperationSnapshot(identity.semanticRequestBytes, 65_536);
    const normalizedIdentity = await validateOperationIdentity(identity, ownedSemanticBytes);
    const issuedAt = canonicalOperationTimestamp(nowMs);
    const freshUntil = canonicalOperationTimestamp(nowMs + ISSUANCE_FRESHNESS_MS);
    const intent = this.intent(normalizedIdentity.sequence);
    if (intent === undefined) operationStoreFail("ACTIVATION_OPERATION_INTENT_MISSING");
    assertSameOperationIntent(intent, normalizedIdentity);
    const stale = requireOperationIssuance(this.latest(normalizedIdentity.attemptId));
    assertActivationIssuanceExpired(stale, nowMs);
    const disposition = classifyStaleActivationIssuance(stale.state, this.slots(stale.issuance_id));
    const ordinal = stale.ordinal + 1;
    const issuanceIdentity = await activationOperationIssuanceIdentity(
      normalizedIdentity.attemptId,
      ordinal,
    );
    let resolved: ActivationOperationIssuanceRow | undefined;
    this.storage.transactionSync(() => {
      const current = requireOperationIssuance(this.latest(normalizedIdentity.attemptId));
      if (current.ordinal !== stale.ordinal) {
        resolved = current;
        return;
      }
      assertActivationIssuanceExpired(current, nowMs);
      const currentDisposition = classifyStaleActivationIssuance(
        current.state,
        this.slots(current.issuance_id),
      );
      if (currentDisposition !== disposition) {
        operationStoreFail("ACTIVATION_OPERATION_REISSUE_CONFLICT");
      }
      this.sql.exec(
        `UPDATE activation_operation_issuances
         SET state = ?, superseded_by_ordinal = ?
         WHERE attempt_id = ? AND ordinal = ? AND state = ?`,
        disposition,
        disposition === "SUPERSEDED_STALE" ? ordinal : null,
        current.attempt_id,
        current.ordinal,
        current.state,
      );
      insertActivationOperationIssuance(
        this.sql,
        normalizedIdentity,
        ordinal,
        issuanceIdentity,
        issuedAt,
        freshUntil,
      );
      resolved = requireOperationIssuance(this.latest(normalizedIdentity.attemptId));
    });
    return operationIssuanceView(requireOperationIssuance(resolved), normalizedIdentity.sequence);
  }

  public async prepareRead(
    issuanceId: string,
    slotId: ActivationOperationSlotId,
    canonicalRequestBytes: Uint8Array,
  ): Promise<{ readonly callProvider: boolean; readonly slot: ActivationOperationSlotRow }> {
    this.requireFreshIssuance(issuanceId);
    const ownedBytes = boundedOperationSnapshot(canonicalRequestBytes, 65_536);
    const digest = await operationBytesDigest(ownedBytes);
    this.requireFreshIssuance(issuanceId);
    let resolved: ActivationOperationSlotRow | undefined;
    let callProvider = false;
    this.storage.transactionSync(() => {
      this.requireFreshIssuance(issuanceId);
      const row = requireOperationStoreSlot(this.slot(issuanceId, slotId));
      if (row.slot_kind === "CLOUDFLARE_BATCH") {
        operationStoreFail("ACTIVATION_OPERATION_CLOUDFLARE_DELEGATION_REQUIRED");
      }
      if (row.state === "FROZEN" || row.state === "CONFIRMED") {
        assertStoredOperationBytes(
          row.provider_request_bytes,
          row.provider_request_sha256,
          ownedBytes,
          digest,
        );
        resolved = row;
        return;
      }
      if (row.state === "READ_IN_FLIGHT") {
        assertStoredOperationBytes(
          row.provider_request_bytes,
          row.provider_request_sha256,
          ownedBytes,
          digest,
        );
        resolved = row;
        callProvider = true;
        return;
      }
      if (row.state !== "PREPARED") operationStoreFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
      this.sql.exec(
        `UPDATE activation_operation_slots
         SET provider_request_bytes = ?, provider_request_sha256 = ?, state = 'READ_IN_FLIGHT'
         WHERE issuance_id = ? AND slot_id = ? AND state = 'PREPARED'`,
        ownedBytes.buffer,
        digest,
        issuanceId,
        slotId,
      );
      collectActivationOperationIssuance(this.sql, issuanceId);
      resolved = requireOperationStoreSlot(this.slot(issuanceId, slotId));
      callProvider = true;
    });
    return { callProvider, slot: requireOperationStoreSlot(resolved) };
  }

  public async freezeRead(
    issuanceId: string,
    slotId: ActivationOperationSlotId,
    canonicalPayloadBytes: Uint8Array,
    observedAt: string,
  ): Promise<ActivationOperationSlotRow> {
    this.requireFreshIssuance(issuanceId, observedAt);
    const initialSlot = requireOperationStoreSlot(this.slot(issuanceId, slotId));
    if (initialSlot.slot_kind === "CLOUDFLARE_BATCH") {
      operationStoreFail("ACTIVATION_OPERATION_CLOUDFLARE_DELEGATION_REQUIRED");
    }
    const maximumBytes =
      initialSlot.slot_kind === "DIRECT_WORM" ? WORM_EXACT_OBJECT_MAX_BYTES : 1_048_576;
    const ownedBytes = boundedOperationSnapshot(canonicalPayloadBytes, maximumBytes);
    const digest = await operationBytesDigest(ownedBytes);
    requireCanonicalOperationTimestamp(observedAt);
    this.requireFreshIssuance(issuanceId, observedAt);
    let resolved: ActivationOperationSlotRow | undefined;
    this.storage.transactionSync(() => {
      this.requireFreshIssuance(issuanceId, observedAt);
      const row = requireOperationStoreSlot(this.slot(issuanceId, slotId));
      if (row.slot_kind === "CLOUDFLARE_BATCH") {
        operationStoreFail("ACTIVATION_OPERATION_CLOUDFLARE_DELEGATION_REQUIRED");
      }
      if (row.state === "FROZEN") {
        assertStoredOperationBytes(
          row.frozen_payload_bytes,
          row.frozen_payload_sha256,
          ownedBytes,
          digest,
        );
        if (row.observed_at !== observedAt)
          operationStoreFail("ACTIVATION_OPERATION_SLOT_RESULT_CONFLICT");
        resolved = row;
        return;
      }
      if (row.state !== "READ_IN_FLIGHT")
        operationStoreFail("ACTIVATION_OPERATION_SLOT_STATE_CONFLICT");
      this.sql.exec(
        `UPDATE activation_operation_slots
         SET frozen_payload_bytes = ?, frozen_payload_sha256 = ?, observed_at = ?, state = 'FROZEN'
         WHERE issuance_id = ? AND slot_id = ? AND state = 'READ_IN_FLIGHT'`,
        ownedBytes.buffer,
        digest,
        observedAt,
        issuanceId,
        slotId,
      );
      resolved = requireOperationStoreSlot(this.slot(issuanceId, slotId));
    });
    return requireOperationStoreSlot(resolved);
  }

  public slots(issuanceId: string): readonly ActivationOperationSlotRow[] {
    return this.queries.slots(issuanceId);
  }

  private requireCurrentLiveIssuance(issuanceId: string): ActivationOperationIssuanceRow {
    const row = requireOperationIssuance(
      this.sql
        .exec<ActivationOperationIssuanceRow>(
          `SELECT * FROM activation_operation_issuances WHERE issuance_id = ?`,
          issuanceId,
        )
        .toArray()[0],
    );
    const latest = requireOperationIssuance(this.latest(row.attempt_id));
    if (
      latest.issuance_id !== row.issuance_id ||
      !["COLLECTING", "EFFECTS_PENDING", "FROZEN", "RESERVED"].includes(row.state)
    ) {
      operationStoreFail("ACTIVATION_OPERATION_ISSUANCE_STALE");
    }
    return row;
  }

  private requireFreshIssuance(
    issuanceId: string,
    observedAt?: string,
  ): ActivationOperationIssuanceRow {
    const issuance = this.requireCurrentLiveIssuance(issuanceId);
    const nowMs = this.now();
    const issuedAt = Date.parse(issuance.issued_at);
    const freshUntil = Date.parse(issuance.fresh_until);
    const observedMs = observedAt === undefined ? nowMs : Date.parse(observedAt);
    if (
      !Number.isSafeInteger(nowMs) ||
      !Number.isFinite(observedMs) ||
      issuedAt > observedMs ||
      observedMs > nowMs ||
      nowMs - observedMs > ISSUANCE_FRESHNESS_MS ||
      nowMs > freshUntil
    ) {
      this.queries.expireIssuance(issuanceId);
      operationStoreFail("ACTIVATION_OPERATION_ISSUANCE_EXPIRED");
    }
    return issuance;
  }

  private intent(sequence: ActivationOperationSequence): ActivationOperationIntentRow | undefined {
    return this.sql
      .exec<ActivationOperationIntentRow>(
        `SELECT * FROM activation_operation_intents WHERE sequence = ?`,
        sequence,
      )
      .toArray()[0];
  }

  private latest(attemptId: string): ActivationOperationIssuanceRow | undefined {
    return this.sql
      .exec<ActivationOperationIssuanceRow>(
        `SELECT * FROM activation_operation_issuances
         WHERE attempt_id = ? ORDER BY ordinal DESC LIMIT 1`,
        attemptId,
      )
      .toArray()[0];
  }

  private slot(
    issuanceId: string,
    slotId: ActivationOperationSlotId,
  ): ActivationOperationSlotRow | undefined {
    return this.sql
      .exec<ActivationOperationSlotRow>(
        `SELECT * FROM activation_operation_slots WHERE issuance_id = ? AND slot_id = ?`,
        issuanceId,
        slotId,
      )
      .toArray()[0];
  }
}
