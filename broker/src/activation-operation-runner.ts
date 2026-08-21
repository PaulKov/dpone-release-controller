import { ActivationRecordStore, type ActivationRow } from "./activation-record-store";
import {
  authorityObserverRequest,
  finalizeAuthorityPlan,
  provisionAuthorityPlan,
  type ActivationOperationAuthorityPlan,
} from "./activation-operation-authority-plan";
import {
  buildActivationOperationCloudflareRequest,
  parseActivationOperationCloudflareRequest,
  type ActivationOperationCloudflareExpectedIssuance,
} from "./activation-operation-cloudflare-request";
import type {
  ActivationOperationIdentity,
  ActivationOperationIssuance,
  ActivationOperationSequence,
} from "./activation-operation-contract";
import { durableActivationRequestBody } from "./activation-operation-durable-request";
import { ActivationOperationEffects } from "./activation-operation-effects";
import { activationOperationIdentity } from "./activation-operation-identity";
import type { ActivationOperationPort } from "./activation-operation-port";
import { provisionReadPlan } from "./activation-operation-read-plan";
import { ActivationOperationRecordLifecycle } from "./activation-operation-record-lifecycle";
import { StoredActivationOperationRecordMaterializer } from "./activation-operation-record-materializer";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import { ActivationOperationStore } from "./activation-operation-store";
import {
  assertStoredOperationBytes,
  canonicalOperationTimestamp,
  operationBytesDigest,
} from "./activation-operation-store-validation";
import {
  assertObservedAtBounded,
  parseFinalizeRequest,
  parseProvisionRequest,
  verifyAdminAccessPrincipalDigests,
  verifyProvisionEvidenceDigests,
  type FinalizeRequest,
  type ProvisionRequest,
} from "./activation-schema";
import { decodeCanonicalObject } from "./activation-registry-codec";
import { BrokerError } from "./errors";
import type { JsonObject, TrustedRuntimeConfig } from "./types";

export interface ActivationOperationRunResult {
  readonly internalRequestId: string;
  readonly record: ActivationRow;
}

/** Durable, transport-independent A0/A1 coordinator. */
export class ActivationOperationRunner {
  private readonly effects: ActivationOperationEffects;
  private readonly lifecycle: ActivationOperationRecordLifecycle;
  private readonly records: ActivationRecordStore;
  private readonly store: ActivationOperationStore;

  public constructor(
    storage: DurableObjectStorage,
    private readonly config: TrustedRuntimeConfig,
    private readonly port: ActivationOperationPort,
    private readonly now: () => number = Date.now,
  ) {
    this.store = new ActivationOperationStore(storage, now);
    this.effects = new ActivationOperationEffects(storage, now);
    this.records = new ActivationRecordStore(storage);
    this.lifecycle = new ActivationOperationRecordLifecycle(
      storage,
      new StoredActivationOperationRecordMaterializer(storage, config),
    );
  }

  public async run(
    body: JsonObject,
    sequence: ActivationOperationSequence,
  ): Promise<ActivationOperationRunResult> {
    const admittedAt = this.now();
    await this.validateAdmission(body, sequence, admittedAt);
    const identity = await activationOperationIdentity(body, sequence, this.config.workerVersionId);
    const issuance = await this.currentIssuance(identity, admittedAt);
    const context = await this.context(identity, issuance);
    if (!isRecordState(issuance.state)) {
      await this.executeEvidence(context);
      if (!this.effects.readyToAppend(issuance.issuanceId)) {
        runnerFail("ACTIVATION_OPERATION_RECORD_NOT_READY", 503, true);
      }
    }
    const record = await this.lifecycle.freezeAndAppend(issuance.issuanceId);
    const next = await this.lifecycle.nextRecordWorm(issuance.issuanceId);
    if (next.action === "COMPLETE") {
      return { internalRequestId: next.requestId, record };
    }
    const resultBytes = await this.port.executeWorm(
      next.effect,
      context.plan.wormPin,
      context.plan.wormObserverPin,
      next.requestId,
    );
    return {
      internalRequestId: next.requestId,
      record: await this.lifecycle.confirmRecordWorm(issuance.issuanceId, resultBytes),
    };
  }

  private async validateAdmission(
    body: JsonObject,
    sequence: ActivationOperationSequence,
    admittedAt: number,
  ): Promise<void> {
    if (sequence === 0) {
      const request = parseProvisionRequest(body, this.config);
      assertObservedAtBounded(request.observedAt, admittedAt);
      await verifyAdminAccessPrincipalDigests(request, this.config);
      await verifyProvisionEvidenceDigests(request);
      await provisionAuthorityPlan(request, this.config);
      return;
    }
    const request = parseFinalizeRequest(body);
    assertObservedAtBounded(request.observedAt, admittedAt);
    const provisioned = this.records.requireConfirmed(0);
    assertProvisionedPointer(request, provisioned, this.config.workerVersionId);
    await finalizeAuthorityPlan(
      request,
      decodeCanonicalObject(new Uint8Array(provisioned.canonical_bytes)),
      this.config,
    );
  }

  private async currentIssuance(
    identity: ActivationOperationIdentity,
    nowMs: number,
  ): Promise<ActivationOperationIssuance> {
    const current = await this.store.reserve(identity, nowMs);
    if (
      nowMs > Date.parse(current.freshUntil) &&
      ["COLLECTING", "EXPIRED_UNDISPATCHED", "FROZEN", "RESERVED"].includes(current.state)
    ) {
      return this.store.reissueStale(identity, nowMs);
    }
    if (current.state === "HOLD" || current.state === "SUPERSEDED_STALE") {
      runnerFail("ACTIVATION_OPERATION_HOLD");
    }
    return current;
  }

  private async context(
    identity: ActivationOperationIdentity,
    issuance: ActivationOperationIssuance,
  ): Promise<ActivationOperationRunContext> {
    const durableBody = durableActivationRequestBody(identity.semanticRequestBytes, issuance);
    if (identity.sequence === 0) {
      const request = parseProvisionRequest(durableBody, this.config);
      await verifyAdminAccessPrincipalDigests(request, this.config);
      await verifyProvisionEvidenceDigests(request);
      return {
        issuance,
        plan: await provisionAuthorityPlan(request, this.config),
        provisionRequest: request,
        sequence: 0,
      };
    }
    const request = parseFinalizeRequest(durableBody);
    const provisioned = this.records.requireConfirmed(0);
    assertProvisionedPointer(request, provisioned, this.config.workerVersionId);
    const provisionedEnvelope = decodeCanonicalObject(new Uint8Array(provisioned.canonical_bytes));
    return {
      finalizeRequest: request,
      issuance,
      plan: await finalizeAuthorityPlan(request, provisionedEnvelope, this.config),
      sequence: 1,
    };
  }

  private async executeEvidence(context: ActivationOperationRunContext): Promise<void> {
    if (context.sequence === 0) await this.collectProvisionReads(context);
    const delegated =
      context.sequence === 0
        ? await this.delegateProvision(context)
        : { cloudflare: await this.delegateCloudflare(context), direct: [] };
    const tasks = [
      ...delegated.direct.map(({ action, effect, slotId }) =>
        action === "COMPLETE"
          ? Promise.resolve()
          : this.port
              .executeWorm(
                effect,
                context.plan.wormPin,
                context.plan.wormObserverPin,
                context.issuance.internalRequestId,
              )
              .then((bytes) =>
                this.effects.confirmDirect(context.issuance.issuanceId, slotId, bytes),
              )
              .then(() => undefined),
      ),
      delegated.cloudflare.action === "COMPLETE"
        ? Promise.resolve()
        : this.port
            .observeCloudflare(delegated.cloudflare.delegation, context.plan.cloudflareObserverPin)
            .then((bytes) => this.effects.confirmCloudflare(context.issuance.issuanceId, bytes))
            .then(() => undefined),
    ];
    await settleAuthorizedEffects(tasks);
  }

  private async collectProvisionReads(context: ProvisionRunContext): Promise<void> {
    const plans = provisionReadPlan(context.provisionRequest, context.issuance.internalRequestId);
    const rows = this.store.slots(context.issuance.issuanceId);
    const prepared = await Promise.all(
      plans.map(async (plan) => {
        const row = requireSlot(rows, plan.slotId);
        if (row.state !== "PREPARED" && row.state !== "READ_IN_FLIGHT") {
          assertStoredOperationBytes(
            row.provider_request_bytes,
            row.provider_request_sha256,
            plan.canonicalRequestBytes,
            await operationBytesDigest(plan.canonicalRequestBytes),
          );
          return { callProvider: false, plan };
        }
        const preparedRead = await this.store.prepareRead(
          context.issuance.issuanceId,
          plan.slotId,
          plan.canonicalRequestBytes,
        );
        return { callProvider: preparedRead.callProvider, plan };
      }),
    );
    await settleAuthorizedEffects(
      prepared.map(({ callProvider, plan }) =>
        callProvider
          ? this.port
              .readProvisionEvidence(plan, context.provisionRequest)
              .then((result) =>
                this.store.freezeRead(
                  context.issuance.issuanceId,
                  plan.slotId,
                  result.canonicalPayloadBytes,
                  result.observedAt,
                ),
              )
              .then(() => undefined)
          : Promise.resolve(),
      ),
    );
  }

  private async delegateProvision(context: ProvisionRunContext) {
    const cloudflare = await this.cloudflareRequest(context);
    const sealed = await this.effects.delegateProvision(
      context.issuance.issuanceId,
      cloudflare.requestBytes,
    );
    return {
      cloudflare: {
        action: sealed.cloudflareAction,
        delegation: cloudflare.delegation,
      },
      direct: sealed.direct,
    };
  }

  private async delegateCloudflare(context: ActivationOperationRunContext) {
    const cloudflare = await this.cloudflareRequest(context);
    const action = await this.effects.delegateCloudflare(
      context.issuance.issuanceId,
      cloudflare.requestBytes,
    );
    return { action: action.action, delegation: cloudflare.delegation };
  }

  private async cloudflareRequest(context: ActivationOperationRunContext) {
    const row = requireSlot(this.store.slots(context.issuance.issuanceId), "CLOUDFLARE_BATCH");
    const requestBytes =
      row.provider_request_bytes === null
        ? await this.newCloudflareRequest(context)
        : new Uint8Array(row.provider_request_bytes);
    return {
      delegation: await parseActivationOperationCloudflareRequest(
        requestBytes,
        expectedCloudflareIssuance(context.issuance, this.config.workerVersionId),
      ),
      requestBytes,
    };
  }

  private async newCloudflareRequest(context: ActivationOperationRunContext): Promise<Uint8Array> {
    const committedAt = canonicalOperationTimestamp(this.now());
    return buildActivationOperationCloudflareRequest({
      committedAt,
      issuance: expectedCloudflareIssuance(context.issuance, this.config.workerVersionId),
      observerRequest: authorityObserverRequest(context.plan, context.issuance, committedAt),
      pins: context.plan.pins,
    });
  }
}

interface BaseRunContext {
  readonly issuance: ActivationOperationIssuance;
  readonly plan: ActivationOperationAuthorityPlan;
}

interface ProvisionRunContext extends BaseRunContext {
  readonly provisionRequest: ProvisionRequest;
  readonly sequence: 0;
}

interface FinalizeRunContext extends BaseRunContext {
  readonly finalizeRequest: FinalizeRequest;
  readonly sequence: 1;
}

type ActivationOperationRunContext = FinalizeRunContext | ProvisionRunContext;

function isRecordState(state: ActivationOperationIssuance["state"]): boolean {
  return state === "CONFIRMED" || state === "READY_TO_APPEND" || state === "RECORD_APPENDED";
}

function expectedCloudflareIssuance(
  issuance: ActivationOperationIssuance,
  ingressWorkerVersionId: string,
): ActivationOperationCloudflareExpectedIssuance {
  return { ...issuance, ingressWorkerVersionId };
}

function requireSlot(
  rows: readonly ActivationOperationSlotRow[],
  slotId: string,
): ActivationOperationSlotRow {
  const row = rows.find((candidate) => candidate.slot_id === slotId);
  if (row === undefined) runnerFail("ACTIVATION_OPERATION_SLOT_MISSING", 500);
  return row;
}

function assertProvisionedPointer(
  request: FinalizeRequest,
  provisioned: ActivationRow,
  workerVersionId: string,
): void {
  if (
    request.provisioned.record_id !== provisioned.record_id ||
    request.provisioned.digest !== provisioned.record_digest ||
    request.provisioned.worm_key !== provisioned.worm_key ||
    request.provisioned.worm_version_id !== provisioned.worm_version_id ||
    request.provisioned.worker_version_id !== workerVersionId
  ) {
    runnerFail("ACTIVATION_PROVISIONED_POINTER_MISMATCH");
  }
}

async function settleAuthorizedEffects(tasks: readonly Promise<void>[]): Promise<void> {
  const results = await Promise.allSettled(tasks);
  const failure = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (failure === undefined) return;
  if (failure.reason instanceof Error) throw failure.reason;
  throw new BrokerError("ACTIVATION_OPERATION_EFFECT_FAILED", 503, true);
}

function runnerFail(code: string, status = 409, retryable = false): never {
  throw new BrokerError(code, status, retryable);
}
