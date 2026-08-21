import { ActivationRecordStore, type ActivationRow } from "./activation-record-store";
import {
  buildActivatedRecord,
  buildProvisionedRecord,
  parseFinalizeRequest,
  parseProvisionRequest,
  provisionRequestServicePin,
  verifyAdminAccessPrincipalDigests,
  verifyProvisionEvidenceDigests,
} from "./activation-schema";
import {
  assertActivationChronology,
  assertAuthorityObservationCommitFreshness,
  decodeCanonicalObject,
  requireStringField,
} from "./activation-registry-codec";
import {
  operationControllerActionObservation,
  operationMirroredProviderEvidence,
  operationTargetRulesetObservation,
  requireOperationRecordSlot,
} from "./activation-operation-record-evidence";
import {
  assertStoredOperationAnchors,
  assertStoredOperationResult,
  operationEffectDigest,
  type ActivationCloudflareAnchor,
} from "./activation-operation-effects-validation";
import { assertCloudflareBatchDelegation } from "./activation-operation-pins";
import { assertStoredOperationBytes } from "./activation-operation-store-validation";
import { durableActivationRequestBody } from "./activation-operation-durable-request";
import type { ActivationOperationRecordMaterializer } from "./activation-operation-record-lifecycle";
import type { ActivationOperationRecordSource } from "./activation-operation-record-source";
import {
  parseActivationOperationCloudflareRequest,
  type ActivationOperationCloudflareExpectedIssuance,
} from "./activation-operation-cloudflare-request";
import { parseCloudflareEvidenceBatchResultV2 } from "./cloudflare-evidence-batch-result-v2";
import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import {
  GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
  RAW_PROVIDER_EVIDENCE_KIND,
} from "./provider-evidence";
import { buildServiceAuthorityObservationFromV2 } from "./service-authority-observation-v2";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
  type ServiceAuthorityExpectation,
} from "./service-authority-activation";
import type { JsonObject, TrustedRuntimeConfig } from "./types";

/** Materialize A0/A1 only from the operation journal's exact owned snapshots. */
export class StoredActivationOperationRecordMaterializer
  implements ActivationOperationRecordMaterializer
{
  private readonly records: ActivationRecordStore;

  public constructor(
    storage: DurableObjectStorage,
    private readonly config: TrustedRuntimeConfig,
  ) {
    this.records = new ActivationRecordStore(storage);
  }

  public async materialize(source: ActivationOperationRecordSource): Promise<JsonObject> {
    return source.sequence === 0 ? this.provisioned(source) : this.activated(source);
  }

  private async provisioned(source: ActivationOperationRecordSource): Promise<JsonObject> {
    const request = parseProvisionRequest(durableRequestBody(source), this.config);
    await verifyAdminAccessPrincipalDigests(request, this.config);
    await verifyProvisionEvidenceDigests(request);
    const expectation = await parseServiceAuthorityExpectation(
      request.serviceAuthorities.expectation,
      request.serviceAuthorities.expectation_sha256,
      this.config.cloudflareAccountId,
      requireStringField(request.broker, "source_commit_sha"),
    );
    assertServiceAuthorityExpectationMatchesBroker(expectation, request.broker);
    const controllerAction = await operationControllerActionObservation(source, request);
    const controllerOidc = await operationMirroredProviderEvidence(
      source,
      request,
      "CONTROLLER_OIDC",
      RAW_PROVIDER_EVIDENCE_KIND,
      provisionRequestServicePin(request, "controller_run_reader"),
    );
    const targetOidc = await operationMirroredProviderEvidence(
      source,
      request,
      "TARGET_OIDC",
      RAW_PROVIDER_EVIDENCE_KIND,
      provisionRequestServicePin(request, "governance_reader"),
    );
    const targetRuleset = await operationMirroredProviderEvidence(
      source,
      request,
      "TARGET_RULESET",
      GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
      provisionRequestServicePin(request, "governance_reader"),
    );
    const rulesetObservation = await operationTargetRulesetObservation(
      source,
      request,
      targetRuleset,
    );
    const authorityObservation = await operationServiceAuthorityObservation(
      source,
      expectation,
      expectation.a0PreDeployments,
    );
    assertAuthorityObservationCommitFreshness(
      authorityObservation,
      Date.parse(requiredRecordCommittedAt(source)),
    );
    return buildProvisionedRecord(
      request,
      requiredRecordCommittedAt(source),
      controllerAction,
      { controller: controllerOidc, target: targetOidc },
      rulesetObservation,
      targetRuleset,
      authorityObservation,
    );
  }

  private async activated(source: ActivationOperationRecordSource): Promise<JsonObject> {
    const request = parseFinalizeRequest(durableRequestBody(source));
    const provisioned = this.records.requireConfirmed(0);
    assertProvisionedPointer(request.provisioned, provisioned, this.config.workerVersionId);
    const provisionedEnvelope = decodeCanonicalObject(new Uint8Array(provisioned.canonical_bytes));
    const broker = requireRecordObject(
      requireRecordObject(provisionedEnvelope.evidence, "ACTIVATION_EVIDENCE_INVALID").broker,
      "ACTIVATION_BROKER_EVIDENCE_INVALID",
    );
    const serviceAuthorities = requireRecordObject(
      requireRecordObject(provisionedEnvelope.evidence, "ACTIVATION_EVIDENCE_INVALID")
        .service_authorities,
      "SERVICE_AUTHORITY_EXPECTATION_REQUIRED",
    );
    const expectation = await parseServiceAuthorityExpectation(
      serviceAuthorities.expectation,
      serviceAuthorities.expectation_sha256,
      this.config.cloudflareAccountId,
      requireStringField(broker, "source_commit_sha"),
    );
    assertServiceAuthorityExpectationMatchesBroker(expectation, broker);
    const promotedDeploymentId = requireStringField(request.promotion, "deployment_id");
    const expectedDeployments = materializeA1PrecommitDeployments(
      expectation.a1PrecommitDeployments,
      promotedDeploymentId,
    );
    assertPromotionBinding(request, expectedDeployments, this.config.workerVersionId);
    const authorityObservation = await operationServiceAuthorityObservation(
      source,
      expectation,
      expectedDeployments,
    );
    assertActivationChronology(
      provisioned.committed_at,
      request.promotion,
      authorityObservation,
      Date.parse(requiredRecordCommittedAt(source)),
    );
    return buildActivatedRecord(
      request,
      requiredRecordCommittedAt(source),
      provisioned.record_id,
      provisionedEnvelope,
      authorityObservation,
    );
  }
}

async function operationServiceAuthorityObservation(
  source: ActivationOperationRecordSource,
  expectation: ServiceAuthorityExpectation,
  expectedDeployments: ServiceAuthorityExpectation["a0PreDeployments"],
): Promise<JsonObject> {
  const slot = requireOperationRecordSlot(source, "CLOUDFLARE_BATCH");
  if (slot.provider_request_bytes === null || slot.result_bytes === null) {
    materializerFail("ACTIVATION_OPERATION_CLOUDFLARE_RESULT_MISSING", 500);
  }
  const requestBytes = new Uint8Array(slot.provider_request_bytes);
  const resultBytes = new Uint8Array(slot.result_bytes);
  assertStoredOperationBytes(
    slot.provider_request_bytes,
    slot.provider_request_sha256,
    requestBytes,
    await operationEffectDigest(requestBytes),
  );
  const delegation = await parseActivationOperationCloudflareRequest(
    requestBytes,
    expectedIssuance(source),
  );
  assertCloudflareBatchDelegation(
    slot,
    delegation.binding.batchId,
    delegation.committedAt,
    delegation.pins,
  );
  const confirmed = await parseCloudflareEvidenceBatchResultV2(resultBytes, delegation);
  assertStoredOperationResult(slot, resultBytes, await operationEffectDigest(resultBytes));
  const anchors: readonly ActivationCloudflareAnchor[] = confirmed.records.map(
    ({ authorityRole, evidence }) => ({
      authorityRole,
      recordId: evidence.recordId,
      recordSha256: evidence.recordSha256,
      worm: evidence.worm,
    }),
  );
  assertStoredOperationAnchors(source.anchors, anchors);
  if (
    confirmed.batchSealedAt !== requiredRecordCommittedAt(source) ||
    confirmed.binding.expectationSha256 !== expectation.expectationSha256 ||
    canonicalJson({ value: delegation.observerRequest.expectedDeployments }) !==
      canonicalJson({ value: expectedDeployments }) ||
    canonicalJson({ value: delegation.observerRequest.inventory }) !==
      canonicalJson({ value: expectation.authorities }) ||
    canonicalJson({ value: delegation.observerRequest.expectedNetworkSurface }) !==
      canonicalJson({ value: expectation.networkSurface })
  ) {
    materializerFail("ACTIVATION_OPERATION_RECORD_TIME_CONFLICT", 500);
  }
  return buildServiceAuthorityObservationFromV2(confirmed);
}

function assertPromotionBinding(
  request: ReturnType<typeof parseFinalizeRequest>,
  deployments: ServiceAuthorityExpectation["a1PrecommitDeployments"],
  workerVersionId: string,
): void {
  const promotedDeploymentId = requireStringField(request.promotion, "deployment_id");
  const ingress = deployments.find(
    (deployment) => deployment.authority_role === "release_authority_ingress",
  );
  const ingressVersion = ingress?.deployment_versions[0];
  if (
    ingress?.deployment_id !== promotedDeploymentId ||
    ingressVersion?.worker_version_id !==
      requireStringField(request.promotion, "worker_version_id") ||
    ingressVersion.worker_version_id !== workerVersionId
  ) {
    materializerFail("ACTIVATION_PROMOTION_BINDING_MISMATCH");
  }
}

function requireRecordObject(value: unknown, code: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    materializerFail(code, 500);
  }
  return value as JsonObject;
}

function expectedIssuance(
  source: ActivationOperationRecordSource,
): ActivationOperationCloudflareExpectedIssuance {
  return {
    freshUntil: source.issuance.fresh_until,
    ingressWorkerVersionId: source.intent.worker_version_id,
    internalRequestId: source.issuance.internal_request_id,
    issuanceId: source.issuance.issuance_id,
    issuedAt: source.issuance.issued_at,
    ordinal: source.issuance.ordinal,
    sequence: source.sequence,
  };
}

function durableRequestBody(source: ActivationOperationRecordSource): JsonObject {
  return durableActivationRequestBody(source.semanticRequestBytes, {
    internalRequestId: source.issuance.internal_request_id,
    issuedAt: source.issuance.issued_at,
  });
}

function requiredRecordCommittedAt(source: ActivationOperationRecordSource): string {
  const value = source.issuance.record_committed_at;
  if (value === null) materializerFail("ACTIVATION_OPERATION_RECORD_TIME_MISSING", 500);
  return value;
}

function assertProvisionedPointer(
  supplied: JsonObject,
  provisioned: ActivationRow,
  workerVersionId: string,
): void {
  if (
    supplied.record_id !== provisioned.record_id ||
    supplied.digest !== provisioned.record_digest ||
    supplied.worm_key !== provisioned.worm_key ||
    supplied.worm_version_id !== provisioned.worm_version_id ||
    supplied.worker_version_id !== workerVersionId
  ) {
    materializerFail("ACTIVATION_PROVISIONED_POINTER_MISMATCH");
  }
}

function materializerFail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
