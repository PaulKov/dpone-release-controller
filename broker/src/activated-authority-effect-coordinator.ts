import { buildActivationProofEffectReservation } from "./activated-authority-effect";
import {
  AUTHORITY_EFFECT_STATUS_SCHEMA,
  buildAuthorityEffectReserveResult,
  parseAuthorityEffectReserveRequest,
  parseAuthorityEffectTransitionRequest,
} from "./activated-authority-effect-rpc";
import type {
  ActivatedAuthorityEffectStore,
  AuthorityEffectRow,
} from "./activated-authority-effect-store";
import { assertCurrentHeadMatchesRequest } from "./activated-authority-head-proof";
import { assertFreshHeadRequest } from "./activated-authority-head-rpc";
import type {
  ActivatedAuthorityHeadStore,
  ActivatedAuthorityHeadRow,
} from "./activated-authority-head-store";
import { effectReplayBindingBody } from "./auth-replay-ledger";
import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject, LiveConfigEnv } from "./types";

type HeadProofBuilder = (
  row: ActivatedAuthorityHeadRow,
  requestId: string,
  requestedAt: string,
  nowMs: number,
) => Promise<JsonObject>;

/** Coordinates replay-ledger and head-journal transitions for one proof effect. */
export class ActivatedAuthorityEffectCoordinator {
  public constructor(
    private readonly effects: ActivatedAuthorityEffectStore,
    private readonly heads: ActivatedAuthorityHeadStore,
    private readonly env: LiveConfigEnv,
    private readonly buildHeadProof: HeadProofBuilder,
  ) {}

  public async reserve(canonicalRequest: string): Promise<string> {
    const request = parseAuthorityEffectReserveRequest(canonicalRequest);
    const now = Date.now();
    assertFreshHeadRequest(request.requestedAt, now);
    if (Date.parse(request.expiresAt) < now) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_REQUEST_STALE", 409, false);
    }
    if (this.heads.pending() !== undefined) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ADVANCE_PENDING", 503, true);
    }
    const current = this.heads.current();
    if (current === undefined) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_UNAVAILABLE", 503, true);
    }
    const proof = await this.buildHeadProof(current, request.requestId, request.requestedAt, now);
    await assertCurrentHeadMatchesRequest(proof, request.readRequest);
    const reservation = await buildActivationProofEffectReservation({
      createdAt: request.requestedAt,
      expiresAt: request.expiresAt,
      headGeneration: current.generation,
      headProof: proof,
      headRecordId: current.record_id,
      headRecordSha256: current.record_sha256,
      intentSha256: request.intentSha256,
      replayClaimsSha256: request.replayClaimsSha256,
      replayExpiresAt: request.replayExpiresAt,
      replayJtiSha256: request.replayJtiSha256,
      requestId: request.requestId,
    });
    let row = await this.effects.reserve(reservation);
    if (row.status === "SEALED" || row.status === "DISPATCHED_HOLD") {
      row = await this.reconcile(row, reservation);
    }
    const acceptedReservation = await this.effects.reservation(row);
    if (!isReturnableStatus(row.status)) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503, false);
    }
    if (row.status === "CONFIRMED") {
      await this.replayLedger().markEffectJournalTerminalExact(await this.replayBinding(row));
    }
    return buildAuthorityEffectReserveResult(
      proof,
      acceptedReservation,
      row.status,
      this.effects.resultCanonical(row),
    );
  }

  public async transition(canonicalRequest: string): Promise<string> {
    const request = parseAuthorityEffectTransitionRequest(canonicalRequest);
    assertFreshHeadRequest(request.requestedAt, Date.now());
    const existing = this.effects.find(request.reservationId);
    if (existing?.request_id !== request.requestId) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_MISSING", 409, false);
    }
    if (request.action === "SEAL") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_TRANSITION_INVALID", 409, false);
    }
    const row =
      request.action === "DISPATCH"
        ? await this.prepareAndDispatch(existing)
        : request.action === "CONFIRM"
          ? await this.commitAndConfirm(existing, requiredResult(request.resultSha256))
          : this.effects.cancelUndispatched(request.reservationId);
    return statusCanonical(row);
  }

  public async seal(canonicalRequest: string, canonicalResult: string): Promise<string> {
    const request = parseAuthorityEffectTransitionRequest(canonicalRequest);
    assertFreshHeadRequest(request.requestedAt, Date.now());
    if (request.action !== "SEAL") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_TRANSITION_INVALID", 409, false);
    }
    const existing = this.effects.find(request.reservationId);
    if (existing?.request_id !== request.requestId) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_MISSING", 409, false);
    }
    return statusCanonical(await this.effects.seal(request.reservationId, canonicalResult));
  }

  private async reconcile(
    row: AuthorityEffectRow,
    replacement: JsonObject,
  ): Promise<AuthorityEffectRow> {
    const ledger = this.replayLedger();
    const binding = await this.replayBinding(row);
    const observed = await ledger.observePreparedEffectExact(binding);
    if (row.status === "DISPATCHED_HOLD" && observed.state === "CONSUMED") {
      if (row.result_sha256 === null) {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID", 503, false);
      }
      return this.effects.confirm(row.reservation_id, row.result_sha256);
    }
    if (observed.state === "PREPARED") {
      const cancelled = await ledger.cancelPreparedEffectExact(binding);
      if (cancelled.state !== "CANCELLED") {
        throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_CONFLICT", 409, false);
      }
      const rearmed = await this.effects.rearmAfterObservedAbsent(row.reservation_id, replacement);
      await ledger.markEffectJournalTerminalExact(binding);
      return rearmed;
    }
    if (
      observed.state === "CANCELLED" ||
      (row.status === "SEALED" && observed.state === "ABSENT")
    ) {
      const rearmed = await this.effects.rearmAfterObservedAbsent(row.reservation_id, replacement);
      if (observed.state === "CANCELLED") {
        await ledger.markEffectJournalTerminalExact(binding);
      }
      return rearmed;
    }
    if (observed.state === "CONSUMED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_CONFLICT", 409, false);
    }
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_AMBIGUOUS", 503, false);
  }

  private async prepareAndDispatch(row: AuthorityEffectRow): Promise<AuthorityEffectRow> {
    if (row.status === "DISPATCHED_HOLD" || row.status === "CONFIRMED") return row;
    if (row.status !== "SEALED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_NOT_DISPATCHABLE", 409, false);
    }
    const prepared = await this.replayLedger().prepareEffectExact(await this.replayBinding(row));
    if (prepared.state !== "PREPARED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_CONFLICT", 409, false);
    }
    return this.effects.dispatch(row.reservation_id, Date.now());
  }

  private async commitAndConfirm(
    row: AuthorityEffectRow,
    resultSha256: string,
  ): Promise<AuthorityEffectRow> {
    if (row.status !== "DISPATCHED_HOLD" && row.status !== "CONFIRMED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_NOT_DISPATCHED", 409, false);
    }
    const binding = await this.replayBinding(row);
    const committed = await this.replayLedger().commitPreparedEffectExact(binding);
    if (committed.state !== "CONSUMED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RECONCILIATION_CONFLICT", 409, false);
    }
    const confirmed = this.effects.confirm(row.reservation_id, resultSha256);
    await this.replayLedger().markEffectJournalTerminalExact(binding);
    return confirmed;
  }

  private async replayBinding(row: AuthorityEffectRow): Promise<JsonObject> {
    const replay = requiredObject(
      await this.effects.reservation(row),
      "replay",
      "ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID",
    );
    return effectReplayBindingBody(
      requiredString(replay, "jti_sha256"),
      requiredNumber(replay, "expires_at"),
      row.request_id,
      requiredString(replay, "claims_sha256"),
      row.reservation_id,
    );
  }

  private replayLedger() {
    const ledger = this.env.AUTH_REPLAY_LEDGER?.getByName("github-oidc-v1");
    if (ledger === undefined) {
      throw new BrokerError("AUTH_REPLAY_LEDGER_UNAVAILABLE", 503, true);
    }
    return ledger;
  }
}

function isReturnableStatus(
  status: AuthorityEffectRow["status"],
): status is "CONFIRMED" | "DISPATCHED_HOLD" | "RESERVED" | "SEALED" {
  return (
    status === "RESERVED" ||
    status === "SEALED" ||
    status === "DISPATCHED_HOLD" ||
    status === "CONFIRMED"
  );
}

function statusCanonical(row: AuthorityEffectRow): string {
  return canonicalJson({
    reservation_id: row.reservation_id,
    result_sha256: row.result_sha256,
    schema: AUTHORITY_EFFECT_STATUS_SCHEMA,
    schema_version: 1,
    status: row.status,
  });
}

function requiredObject(value: JsonObject, key: string, code: string): JsonObject {
  const candidate = value[key];
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new BrokerError(code, 503, false);
  }
  return candidate;
}

function requiredString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID", 503, false);
  }
  return candidate;
}

function requiredNumber(value: JsonObject, key: string): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STORED_INVALID", 503, false);
  }
  return candidate as number;
}

function requiredResult(value: string | undefined): string {
  if (value === undefined) {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 409, false);
  }
  return value;
}
