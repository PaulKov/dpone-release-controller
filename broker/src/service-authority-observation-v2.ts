import type { AcceptedCloudflareDeploymentObservation } from "./cloudflare-deployment-observer-client";
import type {
  ConfirmedCloudflareEvidenceBatchV2,
  ConfirmedCloudflareEvidenceRecordV2,
} from "./cloudflare-evidence-batch-result-v2";
import { BrokerError } from "./errors";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import { buildServiceAuthorityObservation } from "./service-authority-observation-build";
import type { JsonObject } from "./types";
import { requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;

/**
 * Adapt one independently parsed v2 batch into the existing compact authority
 * observation. Every anchor, pin, and clock is derived from that parsed result;
 * callers cannot provide a detached legacy-style authority projection.
 */
export async function buildServiceAuthorityObservationFromV2(
  confirmed: ConfirmedCloudflareEvidenceBatchV2,
): Promise<JsonObject> {
  if (confirmed.records.length !== SERVICE_AUTHORITY_ROLES.length + 1) {
    throw invalidResult();
  }
  const serviceEvidenceEntries = confirmed.records.slice(0, -1).map(serviceEntry);
  const network = confirmed.records.at(-1);
  if (network?.authorityRole !== null || network.kind !== "cloudflare_network_surface") {
    throw invalidResult();
  }
  const accepted: AcceptedCloudflareDeploymentObservation = {
    b2ObserverServiceIdentity: confirmed.pins.b2ObserverServiceIdentity,
    brokerAcceptedAt: confirmed.batchSealedAt,
    networkSurfaceEvidenceEntry: networkEntry(network),
    observation: confirmed.observation,
    serviceEvidenceEntries,
    wormServiceIdentity: confirmed.pins.wormServiceIdentity,
  };
  return buildServiceAuthorityObservation(accepted, confirmed.binding.expectationSha256);
}

function serviceEntry(record: ConfirmedCloudflareEvidenceRecordV2, index: number): JsonObject {
  const expectedRole = SERVICE_AUTHORITY_ROLES[index];
  if (
    expectedRole === undefined ||
    record.authorityRole !== expectedRole ||
    record.kind !== "cloudflare_service_deployments"
  ) {
    throw invalidResult();
  }
  return {
    authority_role: expectedRole,
    deployment_observation_record: record.evidence.record,
    deployment_observation_record_id: record.evidence.recordId,
    deployment_observation_record_sha256: record.evidence.recordSha256,
    deployment_observation_sha256: requireString(
      record.evidence.record,
      "deployment_observation_sha256",
      71,
      DIGEST,
    ),
    worm: wormProjection(record),
  };
}

function networkEntry(record: ConfirmedCloudflareEvidenceRecordV2): JsonObject {
  return {
    network_surface_observation_record: record.evidence.record,
    network_surface_observation_record_id: record.evidence.recordId,
    network_surface_observation_record_sha256: record.evidence.recordSha256,
    network_surface_observation_sha256: requireString(
      record.evidence.record,
      "network_surface_observation_sha256",
      71,
      DIGEST,
    ),
    worm: wormProjection(record),
  };
}

function wormProjection(record: ConfirmedCloudflareEvidenceRecordV2): JsonObject {
  const worm = record.evidence.worm;
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}

function invalidResult(): BrokerError {
  return new BrokerError("SERVICE_AUTHORITY_V2_RESULT_INVALID", 503, false);
}
