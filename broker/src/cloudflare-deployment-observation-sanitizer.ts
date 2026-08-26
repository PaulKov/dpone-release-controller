import { digestObject } from "./canonical";
import {
  CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA,
  CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA,
  type SanitizedCloudflareEvidence,
} from "./cloudflare-deployment-observation-contract";
import {
  finalizeSanitizedRecord,
  requireJsonObject,
  sanitizeProviderCalls,
} from "./cloudflare-deployment-observation-common";
import {
  assertTransientCloudflareNetworkEvidence,
  assertTransientCloudflareServiceEvidence,
} from "./cloudflare-deployment-observation-evidence";
import type { JsonObject } from "./types";

/**
 * Convert transient provider bytes into the only Cloudflare evidence shape
 * that may be persisted. Raw bodies and provider author identity fields are
 * deliberately absent; WORM calls this after independently reparsing bytes.
 */
export async function sanitizeCloudflareServiceEvidence(
  value: unknown,
): Promise<SanitizedCloudflareEvidence> {
  const transient = await assertTransientCloudflareServiceEvidence(value);
  const serviceObservation = requireJsonObject(transient.service_observation);
  const withoutId: JsonObject = {
    authority_role: transient.authority_role ?? null,
    cloudflare_account_id: transient.cloudflare_account_id ?? null,
    deployment_observation_sha256: await digestObject(serviceObservation),
    evidence_kind: "cloudflare_service_deployment_observation",
    expectation_sha256: transient.expectation_sha256 ?? null,
    observed_at: transient.observed_at ?? null,
    observer_service_identity: transient.observer_service_identity ?? null,
    observer_worker_version_id: transient.observer_worker_version_id ?? null,
    phase: transient.phase ?? null,
    provider_calls: sanitizeProviderCalls(transient.raw_responses),
    provider_observation_sha256: transient.provider_observation_sha256 ?? null,
    schema: CLOUDFLARE_SANITIZED_SERVICE_EVIDENCE_SCHEMA,
    schema_version: 1,
    service: transient.service ?? null,
    service_observation: serviceObservation,
  };
  return finalizeSanitizedRecord(withoutId);
}

/** Sanitized account-global Custom Domain/Routes evidence record. */
export async function sanitizeCloudflareNetworkEvidence(
  value: unknown,
): Promise<SanitizedCloudflareEvidence> {
  const transient = await assertTransientCloudflareNetworkEvidence(value);
  const networkObservation = requireJsonObject(transient.network_surface_observation);
  const withoutId: JsonObject = {
    cloudflare_account_id: transient.cloudflare_account_id ?? null,
    evidence_kind: "cloudflare_network_surface_observation",
    expectation_sha256: transient.expectation_sha256 ?? null,
    network_surface_observation: networkObservation,
    network_surface_observation_sha256: await digestObject(networkObservation),
    observed_at: transient.observed_at ?? null,
    observer_service_identity: transient.observer_service_identity ?? null,
    observer_worker_version_id: transient.observer_worker_version_id ?? null,
    phase: transient.phase ?? null,
    provider_calls: sanitizeProviderCalls(transient.raw_responses),
    provider_observation_sha256: transient.provider_observation_sha256 ?? null,
    schema: CLOUDFLARE_SANITIZED_NETWORK_EVIDENCE_SCHEMA,
    schema_version: 1,
  };
  return finalizeSanitizedRecord(withoutId);
}
