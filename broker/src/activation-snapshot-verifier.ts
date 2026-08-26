import {
  assertActivationRecordDigest,
  parseActivatedEnvelope,
  parseProvisionedEnvelope,
} from "./activation-records";
import {
  activationTrustFromSnapshot,
  parseFinalizeRequest,
  parseProvisionRequest,
  verifyAdminAccessPrincipalDigests,
  verifyProvisionEvidenceDigests,
} from "./activation-schema";
import { canonicalBytes, sha256Hex } from "./canonical";
import { LIMITS } from "./config";
import { assert, BrokerError } from "./errors";
import {
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
} from "./service-authority-activation";
import { parseServiceAuthorityObservation } from "./service-authority-observation";
import {
  exactActivatedEnvelope,
  exactProvisionedEnvelope,
  reconstructedFinalizeRequest,
  reconstructedProvisionRequest,
} from "./activation-snapshot-reconstruction";
import type {
  ActivationRecordView,
  ActivationSnapshot,
  ActivationTrust,
  JsonObject,
  TrustedRuntimeConfig,
} from "./types";
import { exactObject, requireString } from "./validation";

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RETENTION_MILLISECONDS = 2557 * 86_400_000;

export interface VerifiedActivationSnapshot {
  readonly activated: ActivationRecordView;
  readonly activatedServiceAuthoritiesSha256: string;
  readonly activation: ActivationTrust;
  readonly provisioned: ActivationRecordView;
  readonly snapshot: ActivationSnapshot;
}

/** Fully verify actual A0/A1 envelopes before they can seed a global head. */
export async function verifyActivationSnapshot(
  snapshot: ActivationSnapshot,
  config: TrustedRuntimeConfig,
): Promise<VerifiedActivationSnapshot> {
  const activated = snapshot.activated;
  if (activated === null) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_INVALID", 409, false);
  }
  await verifyRecord(snapshot.provisioned, 0, config.workerVersionId);
  await verifyRecord(activated, 1, config.workerVersionId);
  const provisionedEnvelope = exactProvisionedEnvelope(snapshot.provisioned.envelope);
  const activatedEnvelope = exactActivatedEnvelope(activated.envelope);

  const provisionRequest = parseProvisionRequest(
    reconstructedProvisionRequest(provisionedEnvelope),
    config,
  );
  await Promise.all([
    verifyProvisionEvidenceDigests(provisionRequest),
    verifyAdminAccessPrincipalDigests(provisionRequest, config),
  ]);
  parseFinalizeRequest(reconstructedFinalizeRequest(activatedEnvelope));
  const activation = activationTrustFromSnapshot(snapshot, config.workerVersionId);

  const provisioned = parseProvisionedEnvelope(provisionedEnvelope);
  const broker = provisioned.broker;
  const authorityFields = exactObject(provisioned.serviceAuthorities, [
    "a0_pre_observation",
    "expectation",
    "expectation_sha256",
  ]);
  const expectation = await parseServiceAuthorityExpectation(
    authorityFields.expectation,
    authorityFields.expectation_sha256,
    requireString(broker, "cloudflare_account_id", 32, /^[0-9a-f]{32}$/u),
    requireString(broker, "source_commit_sha", 40, /^[0-9a-f]{40}$/u),
  );
  const a0Observation = await parseServiceAuthorityObservation(
    authorityFields.a0_pre_observation,
    expectation,
    expectation.a0PreDeployments,
    "A0_PRE",
  );

  const activatedFields = parseActivatedEnvelope(activatedEnvelope);
  const activatedAuthorities = exactObject(activatedFields.serviceAuthorities, [
    "a1_precommit_observation",
    "expectation_sha256",
  ]);
  literal(activatedAuthorities, "expectation_sha256", expectation.expectationSha256);
  const promotion = exactObject(activatedFields.promotion, [
    "completed_at",
    "deployment_id",
    "promotion_report_record_id",
    "promotion_report_record_sha256",
    "promotion_report_worm",
    "provider_observation_sha256",
    "started_at",
    "worker_version_id",
  ]);
  const finalDeployments = materializeA1PrecommitDeployments(
    expectation.a1PrecommitDeployments,
    requireString(promotion, "deployment_id", 36),
  );
  const a1Observation = await parseServiceAuthorityObservation(
    activatedAuthorities.a1_precommit_observation,
    expectation,
    finalDeployments,
    "A1_PRECOMMIT",
  );
  assertChronology(
    provisionedEnvelope,
    activatedEnvelope,
    promotion,
    a0Observation.document,
    a1Observation.document,
  );
  assertPromotionBinding(promotion, expectation, a1Observation.document);
  return {
    activated,
    activatedServiceAuthoritiesSha256: a1Observation.providerObservationSha256,
    activation,
    provisioned: snapshot.provisioned,
    snapshot,
  };
}

async function verifyRecord(
  record: ActivationRecordView,
  sequence: 0 | 1,
  ingressWorkerVersionId: string,
): Promise<void> {
  const bytes = canonicalBytes(record.envelope);
  if (bytes.byteLength === 0 || bytes.byteLength > LIMITS.bodyBytes) {
    throw new BrokerError("ACTIVATION_SNAPSHOT_RECORD_SIZE_INVALID", 413, false);
  }
  assert(record.sequence === sequence, "ACTIVATION_SNAPSHOT_SEQUENCE_INVALID", 503);
  await assertActivationRecordDigest(record.envelope, record.recordId);
  const digest = `sha256:${await sha256Hex(bytes)}`;
  const committedAt = timestamp(record.envelope, "committed_at");
  const expectedKey =
    `receipts/v1/activation/${ingressWorkerVersionId}/` +
    `${sequence}-${digest.slice("sha256:".length)}.json`;
  assert(
    record.digest === digest &&
      record.worm.digest === digest &&
      record.worm.key === expectedKey &&
      canonicalTimestamp(record.worm.retentionUntil) &&
      Date.parse(record.worm.retentionUntil) >= Date.parse(committedAt) + RETENTION_MILLISECONDS,
    "ACTIVATION_SNAPSHOT_WORM_INVALID",
    503,
  );
}

function assertChronology(
  provisioned: JsonObject,
  activated: JsonObject,
  promotion: JsonObject,
  a0: JsonObject,
  a1: JsonObject,
): void {
  const a0Committed = Date.parse(timestamp(provisioned, "committed_at"));
  const a0Accepted = Date.parse(timestamp(a0, "broker_accepted_at"));
  const started = Date.parse(timestamp(promotion, "started_at"));
  const completed = Date.parse(timestamp(promotion, "completed_at"));
  const observed = Date.parse(timestamp(a1, "observed_at"));
  const accepted = Date.parse(timestamp(a1, "broker_accepted_at"));
  const committed = Date.parse(timestamp(activated, "committed_at"));
  assert(
    a0Accepted <= a0Committed &&
      a0Committed - a0Accepted <= 60_000 &&
      a0Committed < started &&
      started <= completed &&
      completed <= observed &&
      observed <= accepted &&
      accepted <= committed &&
      committed - accepted <= 60_000 &&
      activated.observed_at === activated.committed_at &&
      provisioned.observed_at === provisioned.committed_at,
    "ACTIVATION_CHRONOLOGY_INVALID",
    503,
  );
}

function assertPromotionBinding(
  promotion: JsonObject,
  expectation: Awaited<ReturnType<typeof parseServiceAuthorityExpectation>>,
  observation: JsonObject,
): void {
  const ingress = expectation.authorities.find(
    (row) => row.authority_role === "release_authority_ingress",
  );
  const services = observation.services;
  const observedIngress = Array.isArray(services)
    ? services.find(
        (entry) =>
          entry !== null &&
          typeof entry === "object" &&
          !Array.isArray(entry) &&
          entry.authority_role === "release_authority_ingress",
      )
    : undefined;
  const ingressEntry = exactObject(observedIngress, [
    "authority_role",
    "deployment_observation_record_id",
    "deployment_observation_record_sha256",
    "deployment_observation_sha256",
    "deployment_projection",
    "deployment_projection_sha256",
    "worm",
  ]);
  const projection = exactObject(ingressEntry.deployment_projection, [
    "authority_role",
    "current_deployment_id",
    "deployment_created_on",
    "deployment_source",
    "deployment_strategy",
    "deployment_versions",
    "script_settings",
    "service",
    "subdomain",
    "versions",
  ]);
  assert(
    requireString(promotion, "worker_version_id", 36) === ingress?.worker_version_id &&
      promotion.deployment_id === projection.current_deployment_id,
    "ACTIVATION_PROMOTION_BINDING_INVALID",
    503,
  );
}

function timestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 32, TIMESTAMP);
  assert(canonicalTimestamp(value), "ACTIVATION_TIMESTAMP_INVALID", 503);
  return value;
}

function canonicalTimestamp(value: string): boolean {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "ACTIVATION_SNAPSHOT_LITERAL_INVALID",
    503,
  );
}
