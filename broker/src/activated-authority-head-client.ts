import {
  assertCurrentHeadMatchesRequest,
  buildHeadReadRequest,
  parseCurrentHeadProofCanonical,
} from "./activated-authority-head-proof";
import {
  assertReserveResultMatchesRequest,
  buildAuthorityEffectReserveRequest,
  buildAuthorityEffectTransitionRequest,
  parseAuthorityEffectReserveRequest,
  parseAuthorityEffectReserveResult,
  parseAuthorityEffectStatus,
} from "./activated-authority-effect-rpc";
import { buildHeadAdvanceRequestCanonical } from "./activated-authority-head-rpc";
import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import {
  GLOBAL_ACTIVATED_AUTHORITY_HEAD_NAME,
  type GlobalActivatedAuthorityHead,
} from "./global-activated-authority-head";
import type { VerifiedActivationSnapshot } from "./activation-snapshot-verifier";
import type { ActivationSnapshot, JsonObject } from "./types";

/** Fixed-name client for the account-global activated-authority oracle. */
export class ActivatedAuthorityHeadClient {
  public constructor(
    private readonly namespace: DurableObjectNamespace<GlobalActivatedAuthorityHead>,
  ) {}

  public async advance(
    snapshot: ActivationSnapshot,
    verified: VerifiedActivationSnapshot,
    requestId: string,
    nowMs: number,
  ): Promise<JsonObject> {
    const requestedAt = new Date(nowMs).toISOString();
    const canonical = await this.stub().advance(
      buildHeadAdvanceRequestCanonical(snapshot, requestId, requestedAt),
    );
    return this.parseAndBind(canonical, verified, requestId, requestedAt);
  }

  public async current(
    verified: VerifiedActivationSnapshot,
    requestId: string,
    nowMs: number,
  ): Promise<JsonObject> {
    const requestedAt = new Date(nowMs).toISOString();
    const request = readRequest(verified, requestId, requestedAt);
    const canonical = await this.stub().currentCanonical(canonicalJson(request));
    return this.parseAndBind(canonical, verified, requestId, requestedAt);
  }

  public async reserveActivationProof(
    verified: VerifiedActivationSnapshot,
    intentSha256: string,
    replay: {
      readonly claimsSha256: string;
      readonly expiresAt: number;
      readonly jtiSha256: string;
    },
    requestId: string,
    nowMs: number,
  ): Promise<{
    readonly headProof: JsonObject;
    readonly originalRequestId: string;
    readonly reservationId: string;
    readonly sealedResult: JsonObject | null;
    readonly sealedResultSha256: string | null;
    readonly status: "CONFIRMED" | "DISPATCHED_HOLD" | "RESERVED" | "SEALED";
  }> {
    const requestedAt = new Date(nowMs).toISOString();
    const canonicalRequest = buildAuthorityEffectReserveRequest({
      activatedRecordId: verified.activated.recordId,
      activatedRecordSha256: verified.activated.digest,
      activatedServiceAuthoritiesSha256: verified.activatedServiceAuthoritiesSha256,
      expiresAt: new Date(nowMs + 60_000).toISOString(),
      ingressWorkerVersionId: verified.activation.workerVersionId,
      intentSha256,
      replayClaimsSha256: replay.claimsSha256,
      replayExpiresAt: replay.expiresAt,
      replayJtiSha256: replay.jtiSha256,
      requestId,
      requestedAt,
    });
    const request = parseAuthorityEffectReserveRequest(canonicalRequest);
    const accepted = await parseAuthorityEffectReserveResult(
      await this.stub().reserveActivationProofEffect(canonicalRequest),
    );
    await assertReserveResultMatchesRequest(accepted, request);
    const reservationId = accepted.reservation.reservation_id;
    if (typeof reservationId !== "string") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 503, false);
    }
    return {
      headProof: accepted.headProof,
      originalRequestId: requireJsonString(accepted.reservation, "request_id"),
      reservationId,
      sealedResult: accepted.sealedResult,
      sealedResultSha256: accepted.sealedResultSha256,
      status: accepted.status,
    };
  }

  public async dispatchActivationProof(
    reservationId: string,
    requestId: string,
    nowMs: number,
  ): Promise<void> {
    const status = await this.transition("DISPATCH", reservationId, requestId, nowMs);
    if (status.status !== "DISPATCHED_HOLD") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503, false);
    }
  }

  public async sealActivationProof(
    reservationId: string,
    requestId: string,
    canonicalProof: string,
    nowMs: number,
  ): Promise<string> {
    const canonicalRequest = buildAuthorityEffectTransitionRequest({
      action: "SEAL",
      requestId,
      requestedAt: new Date(nowMs).toISOString(),
      reservationId,
    });
    const status = parseAuthorityEffectStatus(
      await this.stub().sealActivationProofEffect(canonicalRequest, canonicalProof),
      reservationId,
    );
    if (status.status !== "SEALED" || status.resultSha256 === null) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503, false);
    }
    return status.resultSha256;
  }

  public async confirmActivationProof(
    reservationId: string,
    requestId: string,
    resultSha256: string,
    nowMs: number,
  ): Promise<void> {
    const status = await this.transition("CONFIRM", reservationId, requestId, nowMs, resultSha256);
    if (status.status !== "CONFIRMED" || status.resultSha256 !== resultSha256) {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503, false);
    }
  }

  public async cancelActivationProof(
    reservationId: string,
    requestId: string,
    nowMs: number,
  ): Promise<void> {
    const status = await this.transition("CANCEL", reservationId, requestId, nowMs);
    if (status.status !== "CANCELLED_UNDISPATCHED") {
      throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503, false);
    }
  }

  private stub(): DurableObjectStub<GlobalActivatedAuthorityHead> {
    return this.namespace.getByName(GLOBAL_ACTIVATED_AUTHORITY_HEAD_NAME);
  }

  private async parseAndBind(
    canonical: string,
    verified: VerifiedActivationSnapshot,
    requestId: string,
    requestedAt: string,
  ): Promise<JsonObject> {
    const proof = await parseCurrentHeadProofCanonical(canonical);
    await assertCurrentHeadMatchesRequest(proof, readRequest(verified, requestId, requestedAt));
    return proof;
  }

  private async transition(
    action: "CANCEL" | "CONFIRM" | "DISPATCH",
    reservationId: string,
    requestId: string,
    nowMs: number,
    resultSha256?: string,
  ) {
    const canonical = buildAuthorityEffectTransitionRequest({
      action,
      requestId,
      requestedAt: new Date(nowMs).toISOString(),
      reservationId,
      ...(resultSha256 === undefined ? {} : { resultSha256 }),
    });
    return parseAuthorityEffectStatus(
      await this.stub().transitionActivationProofEffect(canonical),
      reservationId,
    );
  }
}

function readRequest(
  verified: VerifiedActivationSnapshot,
  requestId: string,
  requestedAt: string,
): JsonObject {
  return buildHeadReadRequest({
    activatedRecordId: verified.activated.recordId,
    activatedRecordSha256: verified.activated.digest,
    activatedServiceAuthoritiesSha256: verified.activatedServiceAuthoritiesSha256,
    ingressWorkerVersionId: verified.activation.workerVersionId,
    requestId,
    requestedAt,
  });
}

function requireJsonString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") {
    throw new BrokerError("ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID", 503, false);
  }
  return candidate;
}
