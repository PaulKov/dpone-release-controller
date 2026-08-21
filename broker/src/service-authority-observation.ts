import { digestObject } from "./canonical";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { assert, BrokerError } from "./errors";
import {
  SERVICE_AUTHORITY_OBSERVATION_SCHEMA,
  type ServiceAuthorityExpectation,
} from "./service-authority-activation";
import { exactInteger, literal, tagged, timestamp } from "./service-authority-observation-fields";
import {
  assertUniqueObservationAnchors,
  parseNetworkObservationEntry,
  parseServiceObservationEntry,
} from "./service-authority-observation-projections";
import {
  SERVICE_AUTHORITY_ROLES,
  type DeploymentObservationPhase,
  type ExpectedServiceDeployment,
} from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireString } from "./validation";

export interface ParsedServiceAuthorityObservation {
  readonly document: JsonObject;
  readonly providerObservationSha256: string;
}

/**
 * Parse the complete compact 14-service plus network authority observation.
 * The WORM anchors provide durability; the embedded projections provide the
 * independently checkable semantic preimage consumed by offline importers.
 */
export async function parseServiceAuthorityObservation(
  value: unknown,
  expectation: ServiceAuthorityExpectation,
  expectedDeployments: readonly ExpectedServiceDeployment[],
  phase: DeploymentObservationPhase,
): Promise<ParsedServiceAuthorityObservation> {
  const document = exactObject(value, [
    "b2_observer_service_identity",
    "broker_accepted_at",
    "cloudflare_provider_observation_sha256",
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
    "worm_service_identity",
  ]);
  literal(document, "schema", SERVICE_AUTHORITY_OBSERVATION_SCHEMA);
  exactInteger(document, "schema_version", 1);
  literal(document, "phase", phase);
  literal(document, "expectation_sha256", expectation.expectationSha256);
  tagged(document, "cloudflare_provider_observation_sha256");
  const observedAt = timestamp(document, "observed_at");
  const acceptedAt = timestamp(document, "broker_accepted_at");
  const elapsed = Date.parse(acceptedAt) - Date.parse(observedAt);
  assert(elapsed >= 0 && elapsed <= 60_000, "SERVICE_AUTHORITY_OBSERVATION_STALE", 503);

  const observerVersion = requireString(
    document,
    "observer_worker_version_id",
    36,
    CLOUDFLARE_UUID,
  );
  const observerAuthority = expectation.authorities.find(
    (row) => row.authority_role === "cloudflare_deployment_observer",
  );
  assert(
    observerAuthority?.worker_version_id === observerVersion &&
      requireString(document, "observer_service_identity", 512) ===
        observerAuthority.service_identity,
    "SERVICE_AUTHORITY_OBSERVER_PIN_MISMATCH",
    503,
  );
  const wormAuthority = expectation.authorities.find((row) => row.authority_role === "worm_mirror");
  assert(
    requireString(document, "worm_service_identity", 512) === wormAuthority?.service_identity,
    "SERVICE_AUTHORITY_WORM_PIN_MISMATCH",
    503,
  );
  const b2ObserverAuthority = expectation.authorities.find(
    (row) => row.authority_role === "worm_version_observer",
  );
  assert(
    requireString(document, "b2_observer_service_identity", 512) ===
      b2ObserverAuthority?.service_identity,
    "SERVICE_AUTHORITY_B2_OBSERVER_PIN_MISMATCH",
    503,
  );

  if (
    !Array.isArray(document.services) ||
    document.services.length !== SERVICE_AUTHORITY_ROLES.length
  ) {
    throw new BrokerError("SERVICE_AUTHORITY_OBSERVATION_INVALID", 503, false);
  }
  const services = await Promise.all(
    document.services.map((candidate, index) => {
      const expected = expectedDeployments[index];
      const role = SERVICE_AUTHORITY_ROLES[index];
      if (expected === undefined || role === undefined || expected.authority_role !== role) {
        throw new BrokerError("SERVICE_AUTHORITY_OBSERVATION_ORDER_INVALID", 503, false);
      }
      return parseServiceObservationEntry(candidate, expected, observerVersion, observedAt);
    }),
  );
  const network = await parseNetworkObservationEntry(
    document.network_surface,
    expectation,
    observerVersion,
    observedAt,
  );
  assertUniqueObservationAnchors(services, network);
  const aggregate: JsonObject = {
    b2_observer_service_identity: document.b2_observer_service_identity ?? null,
    expectation_sha256: expectation.expectationSha256,
    network_surface: network,
    phase,
    services,
    worm_service_identity: document.worm_service_identity ?? null,
  };
  const expectedDigest = await digestObject(aggregate);
  assert(
    tagged(document, "provider_observation_sha256") === expectedDigest,
    "SERVICE_AUTHORITY_OBSERVATION_DIGEST_INVALID",
    503,
  );
  return { document, providerObservationSha256: expectedDigest };
}
