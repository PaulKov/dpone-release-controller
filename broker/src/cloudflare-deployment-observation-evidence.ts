import { canonicalJson, digestObject } from "./canonical";
import {
  ACCOUNT_ID,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA,
  CLOUDFLARE_NETWORK_EVIDENCE_KIND,
  CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA,
  CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA,
  CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA,
  DIGEST,
  MAX_EVIDENCE_ENTRY_BYTES,
  SERVICE_IDENTITY,
  VERSION,
  type SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation-contract";
import {
  assertSanitizedText,
  requireExactInteger,
  requireJsonObject,
  requireLiteral,
  requireTimestamp,
  sanitizePersistedProviderCalls,
} from "./cloudflare-deployment-observation-common";
import {
  parseEvidenceSetBinding,
  parseNetworkEvidenceBinding,
  reproduceNetworkSurfaceObservation,
  reproduceServiceObservation,
} from "./cloudflare-deployment-observation-reproduction";
import { assert, BrokerError } from "./errors";
import {
  isServiceAuthorityRole,
  SERVICE_AUTHORITY_DEFINITIONS,
  SERVICE_AUTHORITY_ROLES,
} from "./service-authority";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireString } from "./validation";

/**
 * Transient WORM boundary: reparse every Cloudflare response and reproduce the
 * single sanitized observation before any activation/head record can commit.
 */
export async function assertCloudflareDeploymentEvidenceSet(
  observation: JsonObject,
  evidenceEntries: readonly JsonObject[],
  networkEvidenceEntry: JsonObject,
): Promise<void> {
  const unsigned = exactObject(observation, [
    "cloudflare_account_id",
    "expectation_sha256",
    "network_surface",
    "observed_at",
    "observer_service_identity",
    "observer_worker_version_id",
    "phase",
    "provider_observation_sha256",
    "schema",
    "schema_version",
    "services",
  ]);
  requireLiteral(unsigned, "schema", CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA);
  requireExactInteger(unsigned, "schema_version", 1);
  const expectedDigest = requireString(unsigned, "provider_observation_sha256", 71, DIGEST);
  const digestBody = { ...unsigned };
  delete digestBody.provider_observation_sha256;
  assert(
    expectedDigest === (await digestObject(digestBody)),
    "CLOUDFLARE_OBSERVATION_DIGEST_INVALID",
    500,
  );
  if (
    !Array.isArray(unsigned.services) ||
    unsigned.services.length !== SERVICE_AUTHORITY_ROLES.length
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVATION_INVALID", 500, false);
  }
  if (evidenceEntries.length !== SERVICE_AUTHORITY_ROLES.length) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_SET_INVALID", 500, false);
  }
  for (let index = 0; index < evidenceEntries.length; index += 1) {
    const evidence = await assertTransientCloudflareServiceEvidence(evidenceEntries[index]);
    parseEvidenceSetBinding(evidence, index, unsigned);
    const reproduced = await reproduceServiceObservation(evidence);
    const supplied = unsigned.services[index];
    if (canonicalJson(reproduced) !== canonicalJson(requireJsonObject(supplied))) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_MISMATCH", 500, false);
    }
  }
  const networkEvidence = await assertTransientCloudflareNetworkEvidence(networkEvidenceEntry);
  parseNetworkEvidenceBinding(networkEvidence, unsigned);
  const reproducedNetwork = await reproduceNetworkSurfaceObservation(networkEvidence);
  if (
    canonicalJson(reproducedNetwork) !== canonicalJson(requireJsonObject(unsigned.network_surface))
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_MISMATCH", 500, false);
  }
}

/** Transient raw network evidence; this object is never WORM-retainable. */
export async function assertTransientCloudflareNetworkEvidence(
  value: unknown,
): Promise<JsonObject> {
  const evidence = exactObject(value, [
    "cloudflare_account_id",
    "evidence_kind",
    "expectation_sha256",
    "network_surface_observation",
    "observed_at",
    "observer_service_identity",
    "observer_worker_version_id",
    "phase",
    "provider_observation_sha256",
    "raw_responses",
    "schema",
    "schema_version",
  ]);
  requireLiteral(evidence, "schema", CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA);
  requireExactInteger(evidence, "schema_version", 1);
  requireLiteral(evidence, "evidence_kind", CLOUDFLARE_NETWORK_EVIDENCE_KIND);
  requireString(evidence, "cloudflare_account_id", 32, ACCOUNT_ID);
  requireString(evidence, "expectation_sha256", 71, DIGEST);
  requireString(evidence, "provider_observation_sha256", 71, DIGEST);
  requireString(evidence, "observer_service_identity", 512, SERVICE_IDENTITY);
  requireString(evidence, "observer_worker_version_id", 36, VERSION);
  requireTimestamp(evidence, "observed_at");
  const phase = requireString(evidence, "phase", 12);
  if (phase !== "A0_PRE" && phase !== "A1_PRECOMMIT") {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_PHASE_INVALID", 500, false);
  }
  const reproduced = await reproduceNetworkSurfaceObservation(evidence);
  if (
    canonicalJson(reproduced) !==
    canonicalJson(requireJsonObject(evidence.network_surface_observation))
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_MISMATCH", 500, false);
  }
  return evidence;
}

/** Closed transient discriminant for one independently bounded service entry. */
export async function assertTransientCloudflareServiceEvidence(
  value: unknown,
): Promise<JsonObject> {
  const evidence = exactObject(value, [
    "authority_role",
    "cloudflare_account_id",
    "evidence_kind",
    "expectation_sha256",
    "observed_at",
    "observer_service_identity",
    "observer_worker_version_id",
    "phase",
    "provider_observation_sha256",
    "raw_responses",
    "schema",
    "schema_version",
    "service",
    "service_observation",
  ]);
  requireLiteral(evidence, "schema", CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA);
  requireExactInteger(evidence, "schema_version", 1);
  requireLiteral(evidence, "evidence_kind", CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND);
  const role = requireString(evidence, "authority_role", 64);
  if (!isServiceAuthorityRole(role)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_ROLE_INVALID", 500, false);
  }
  if (requireString(evidence, "service", 128) !== SERVICE_AUTHORITY_DEFINITIONS[role].service) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_SERVICE_INVALID", 500, false);
  }
  const accountId = requireString(evidence, "cloudflare_account_id", 32, ACCOUNT_ID);
  const observerVersion = requireString(evidence, "observer_worker_version_id", 36, VERSION);
  if (
    requireString(evidence, "observer_service_identity", 512, SERVICE_IDENTITY) !==
    `cloudflare-worker:${accountId}/dpone-release-cloudflare-deployment-observer@${observerVersion}`
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_OBSERVER_INVALID", 500, false);
  }
  const phase = requireString(evidence, "phase", 12);
  if (phase !== "A0_PRE" && phase !== "A1_PRECOMMIT") {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_PHASE_INVALID", 500, false);
  }
  requireString(evidence, "expectation_sha256", 71, DIGEST);
  requireString(evidence, "provider_observation_sha256", 71, DIGEST);
  requireTimestamp(evidence, "observed_at");
  const reproduced = await reproduceServiceObservation(evidence);
  if (
    canonicalJson(reproduced) !== canonicalJson(requireJsonObject(evidence.service_observation))
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_MISMATCH", 500, false);
  }
  assert(
    new TextEncoder().encode(canonicalJson(evidence)).byteLength <= MAX_EVIDENCE_ENTRY_BYTES,
    "CLOUDFLARE_DEPLOYMENT_EVIDENCE_TOO_LARGE",
    500,
  );
  return evidence;
}

/**
 * Validate the only Cloudflare control-plane evidence representation that may
 * cross the WORM persistence boundary. It contains exact projections and raw
 * response digests, never raw provider bytes or author identities.
 */
export async function assertSanitizedCloudflareEvidenceRecord(
  value: unknown,
): Promise<SanitizedCloudflareEvidence> {
  const candidate = requireJsonObject(value as JsonValue);
  const schema = requireString(candidate, "schema", 96);
  const service = schema === CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA;
  const network = schema === CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA;
  if (!service && !network) {
    throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_SCHEMA_INVALID", 500, false);
  }
  const fields = service
    ? [
        "authority_role",
        "cloudflare_account_id",
        "deployment_observation_sha256",
        "evidence_kind",
        "expectation_sha256",
        "observed_at",
        "observer_service_identity",
        "observer_worker_version_id",
        "phase",
        "provider_calls",
        "provider_observation_sha256",
        "record_id",
        "schema",
        "schema_version",
        "service",
        "service_observation",
      ]
    : [
        "cloudflare_account_id",
        "evidence_kind",
        "expectation_sha256",
        "network_surface_observation",
        "network_surface_observation_sha256",
        "observed_at",
        "observer_service_identity",
        "observer_worker_version_id",
        "phase",
        "provider_calls",
        "provider_observation_sha256",
        "record_id",
        "schema",
        "schema_version",
      ];
  const record = exactObject(candidate, fields);
  requireExactInteger(record, "schema_version", 1);
  requireString(record, "cloudflare_account_id", 32, ACCOUNT_ID);
  requireString(record, "expectation_sha256", 71, DIGEST);
  requireString(record, "provider_observation_sha256", 71, DIGEST);
  requireString(record, "observer_service_identity", 512, SERVICE_IDENTITY);
  requireString(record, "observer_worker_version_id", 36, VERSION);
  requireTimestamp(record, "observed_at");
  const phase = requireString(record, "phase", 12);
  if (phase !== "A0_PRE" && phase !== "A1_PRECOMMIT") {
    throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_PHASE_INVALID", 500, false);
  }
  const providerCalls = sanitizePersistedProviderCalls(record.provider_calls);
  if (service) {
    requireLiteral(record, "evidence_kind", "cloudflare_service_deployment_observation");
    const role = requireString(record, "authority_role", 64);
    if (!isServiceAuthorityRole(role)) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_ROLE_INVALID", 500, false);
    }
    requireLiteral(record, "service", SERVICE_AUTHORITY_DEFINITIONS[role].service);
    const observation = requireJsonObject(record.service_observation);
    if (
      requireString(record, "deployment_observation_sha256", 71, DIGEST) !==
      (await digestObject(observation))
    ) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_DIGEST_INVALID", 500, false);
    }
    if (providerCalls.length < 5 || providerCalls.length > 6) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_CALLS_INVALID", 500, false);
    }
  } else {
    requireLiteral(record, "evidence_kind", "cloudflare_network_surface_observation");
    const observation = requireJsonObject(record.network_surface_observation);
    if (
      requireString(record, "network_surface_observation_sha256", 71, DIGEST) !==
      (await digestObject(observation))
    ) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_DIGEST_INVALID", 500, false);
    }
    if (providerCalls.length !== 3) {
      throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_CALLS_INVALID", 500, false);
    }
  }
  const recordId = requireString(record, "record_id", 71, DIGEST);
  const withoutId = { ...record };
  delete withoutId.record_id;
  if ((await digestObject(withoutId)) !== recordId) {
    throw new BrokerError("CLOUDFLARE_SANITIZED_EVIDENCE_RECORD_ID_INVALID", 500, false);
  }
  const recordSha256 = await digestObject(record);
  assertSanitizedText(canonicalJson(record));
  return { record, recordId, recordSha256 };
}
