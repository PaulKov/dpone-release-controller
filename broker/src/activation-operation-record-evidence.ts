import {
  controllerActionBundleAppPin,
  parseControllerActionBundleObservation,
  type ControllerActionBundleObservation,
} from "./controller-action-bundle-client";
import { decodeCanonicalObject } from "./activation-registry-codec";
import type { ActivationOperationRecordSource } from "./activation-operation-record-source";
import { rebuildDirectOperationEffect } from "./activation-operation-direct-effect";
import type { ActivationOperationSlotId } from "./activation-operation-contract";
import type { ActivationOperationSlotRow } from "./activation-operation-schema";
import {
  assertConfirmedOperationEffect,
  operationEffectDigest,
} from "./activation-operation-effects-validation";
import {
  provisionReadPlan,
  requireProvisionReadPlan,
  type ActivationOperationReadSlotId,
} from "./activation-operation-read-plan";
import { assertStoredOperationBytes } from "./activation-operation-store-validation";
import {
  assertRetainableProviderEvidence,
  type RawProviderEvidenceKind,
} from "./provider-evidence";
import { provisionRequestServicePin } from "./activation-schema";
import type { MirroredProviderEvidence, ProvisionRequest } from "./activation-schema";
import { sha256Hex } from "./canonical";
import { BrokerError } from "./errors";
import {
  parseTargetRulesetObservation,
  type TargetRulesetObservation,
} from "./target-ruleset-client";
import type { PrivateServicePin } from "./types";
import { requireObject, requireString } from "./validation";
import { parseWormExactObjectEffectResult } from "./worm-exact-object-effect-result";

/** Reconstruct the frozen, read-only controller action observation from SQL bytes. */
export async function operationControllerActionObservation(
  source: ActivationOperationRecordSource,
  request: ProvisionRequest,
): Promise<ControllerActionBundleObservation> {
  const slot = requireSlot(source, "CONTROLLER_ACTION");
  const payload = requireBuffer(slot.frozen_payload_bytes);
  const githubApps = requireObject(request.evidence.github_apps, "ACTIVATION_APPS_REQUIRED");
  const app = controllerActionBundleAppPin(
    requireObject(githubApps.controller_run_reader, "ACTIVATION_CONTROLLER_APP_REQUIRED"),
  );
  await assertExactProviderRequest(
    slot,
    expectedProviderRequest(source, request, "CONTROLLER_ACTION"),
  );
  assertReadChronology(source, slot);
  if (`sha256:${await sha256Hex(payload)}` !== slot.frozen_payload_sha256) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_BINDING_INVALID");
  }
  const observation = decodeCanonicalObject(payload);
  return parseControllerActionBundleObservation(observation, {
    app,
    commitSha: requireString(request.controller, "controller_action_commit_sha", 40),
    pin: provisionRequestServicePin(request, "controller_run_reader"),
    requestId: source.issuance.internal_request_id,
  });
}

/** Reconstruct one confirmed provider-evidence mirror from its exact slot/result bytes. */
export async function operationMirroredProviderEvidence(
  source: ActivationOperationRecordSource,
  request: ProvisionRequest,
  slotId: "CONTROLLER_OIDC" | "TARGET_OIDC" | "TARGET_RULESET",
  kind: RawProviderEvidenceKind,
  providerPin: PrivateServicePin,
): Promise<MirroredProviderEvidence> {
  const slot = requireSlot(source, slotId);
  await assertExactProviderRequest(slot, expectedProviderRequest(source, request, slotId));
  assertReadChronology(source, slot);
  const evidenceBytes = requireBuffer(slot.frozen_payload_bytes);
  const evidence = await assertRetainableProviderEvidence(
    decodeCanonicalObject(evidenceBytes),
    kind,
  );
  const canonicalSha256 = `sha256:${await sha256Hex(evidenceBytes)}`;
  if (
    canonicalSha256 !== slot.frozen_payload_sha256 ||
    normalizeTimestamp(requireString(evidence, "observed_at", 32)) !== slot.observed_at ||
    evidence.request_id !== source.issuance.internal_request_id ||
    evidence.observer_service_identity !== providerPin.serviceIdentity ||
    evidence.observer_worker_version_id !== providerPin.versionId
  ) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_BINDING_INVALID");
  }
  const worm = provisionRequestServicePin(request, "worm_mirror");
  const observer = provisionRequestServicePin(request, "worm_version_observer");
  if (
    slot.executor_service_identity !== worm.serviceIdentity ||
    slot.executor_worker_version_id !== worm.versionId ||
    slot.observer_service_identity !== observer.serviceIdentity ||
    slot.observer_worker_version_id !== observer.versionId
  ) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_BINDING_INVALID");
  }
  const effect = await rebuildDirectOperationEffect(slot, source.intent.worker_version_id);
  const resultBytes = requireBuffer(slot.result_bytes);
  const result = parseWormExactObjectEffectResult(resultBytes, effect);
  assertConfirmedOperationEffect(
    slot,
    resultBytes,
    await operationEffectDigest(resultBytes),
    result.worm,
  );
  return { canonicalSha256, evidence, worm: result.worm };
}

/** Reconstruct the typed ruleset observation used by the A0 record builder. */
export async function operationTargetRulesetObservation(
  source: ActivationOperationRecordSource,
  request: ProvisionRequest,
  mirrored: MirroredProviderEvidence,
): Promise<TargetRulesetObservation> {
  const governance = requireObject(
    request.evidence.target_governance,
    "ACTIVATION_TARGET_GOVERNANCE_REQUIRED",
  );
  const parsed = await parseTargetRulesetObservation(mirrored.evidence, {
    branchRulesetId: requireString(governance, "branch_ruleset_id", 32),
    expectedProjection: requireObject(
      governance.branch_ruleset_projection,
      "ACTIVATION_TARGET_RULESET_PROJECTION_REQUIRED",
    ),
    expectedProjectionSha256: requireString(governance, "branch_ruleset_projection_sha256", 71),
    pin: provisionRequestServicePin(request, "governance_reader"),
    requestId: source.issuance.internal_request_id,
  });
  if (parsed.evidenceCanonicalSha256 !== mirrored.canonicalSha256) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_BINDING_INVALID");
  }
  return parsed;
}

export function requireOperationRecordSlot(
  source: ActivationOperationRecordSource,
  slotId: ActivationOperationSlotId,
): ActivationOperationSlotRow {
  return requireSlot(source, slotId);
}

function requireSlot(
  source: ActivationOperationRecordSource,
  slotId: ActivationOperationSlotId,
): ActivationOperationSlotRow {
  const slot = source.slots.find((candidate) => candidate.slot_id === slotId);
  if (slot === undefined) evidenceFail("ACTIVATION_OPERATION_SLOT_MISSING", 500);
  return slot;
}

function requireBuffer(value: ArrayBuffer | null): Uint8Array {
  if (value === null) evidenceFail("ACTIVATION_OPERATION_SLOT_RESULT_MISSING", 500);
  return new Uint8Array(value);
}

async function assertExactProviderRequest(
  slot: ActivationOperationSlotRow,
  expected: Uint8Array,
): Promise<void> {
  assertStoredOperationBytes(
    slot.provider_request_bytes,
    slot.provider_request_sha256,
    expected,
    await operationEffectDigest(expected),
  );
}

function expectedProviderRequest(
  source: ActivationOperationRecordSource,
  request: ProvisionRequest,
  slotId: ActivationOperationReadSlotId,
): Uint8Array {
  return requireProvisionReadPlan(
    provisionReadPlan(request, source.issuance.internal_request_id),
    slotId,
  ).canonicalRequestBytes;
}

function assertReadChronology(
  source: ActivationOperationRecordSource,
  slot: ActivationOperationSlotRow,
): void {
  const observedAt = slot.observed_at;
  const committedAt = source.issuance.record_committed_at;
  if (
    observedAt === null ||
    committedAt === null ||
    normalizeTimestamp(observedAt) !== observedAt ||
    Date.parse(source.issuance.issued_at) > Date.parse(observedAt) ||
    Date.parse(observedAt) > Date.parse(committedAt) ||
    Date.parse(observedAt) > Date.parse(source.issuance.fresh_until)
  ) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_CHRONOLOGY_INVALID");
  }
}

function normalizeTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    evidenceFail("ACTIVATION_OPERATION_PROVIDER_EVIDENCE_CHRONOLOGY_INVALID");
  }
  return new Date(milliseconds).toISOString();
}

function evidenceFail(code: string, status = 503): never {
  throw new BrokerError(code, status, false);
}
