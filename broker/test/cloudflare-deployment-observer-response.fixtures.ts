import { canonicalJson } from "../src/canonical";
import {
  CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
  sanitizeCloudflareNetworkEvidence,
  sanitizeCloudflareServiceEvidence,
} from "../src/cloudflare-deployment-observation";
import type { JsonObject } from "../src/types";
import {
  ACCOUNT_ID,
  OBSERVER_VERSION,
  authorityInventory,
} from "./cloudflare-deployment-observer-provider.fixtures";

export {
  fetcher,
  requireDefined,
  requireObject,
  requiredString,
} from "./cloudflare-deployment-observer-common.fixtures";
import { privatePin as buildPrivatePin } from "./cloudflare-deployment-observer-common.fixtures";

export async function privateResult(
  result: {
    readonly evidenceEntries: readonly JsonObject[];
    readonly networkEvidenceEntry: JsonObject;
    readonly observation: JsonObject;
  },
  requestId: string,
): Promise<Response> {
  const serviceEntries = await Promise.all(
    result.evidenceEntries.map(async (transient) => {
      const sanitized = await sanitizeCloudflareServiceEvidence(transient);
      return {
        authority_role: sanitized.record.authority_role ?? null,
        deployment_observation_record: sanitized.record,
        deployment_observation_record_id: sanitized.recordId,
        deployment_observation_record_sha256: sanitized.recordSha256,
        deployment_observation_sha256: sanitized.record.deployment_observation_sha256 ?? null,
        worm: wormPointer(
          sanitized.recordId,
          sanitized.recordSha256,
          "cloudflare_service_deployments",
        ),
      };
    }),
  );
  const network = await sanitizeCloudflareNetworkEvidence(result.networkEvidenceEntry);
  const b2Observer = (await authorityInventory()).find(
    ({ authority_role }) => authority_role === "worm_version_observer",
  );
  const worm = (await authorityInventory()).find(
    ({ authority_role }) => authority_role === "worm_mirror",
  );
  if (b2Observer === undefined || worm === undefined) throw new Error("missing WORM fixtures");
  return new Response(
    canonicalJson({
      b2_observer_service_identity: b2Observer.service_identity,
      network_surface_evidence_entry: {
        network_surface_observation_record: network.record,
        network_surface_observation_record_id: network.recordId,
        network_surface_observation_record_sha256: network.recordSha256,
        network_surface_observation_sha256:
          network.record.network_surface_observation_sha256 ?? null,
        worm: wormPointer(network.recordId, network.recordSha256, "cloudflare_network_surface"),
      },
      observation: result.observation,
      schema: CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
      schema_version: 1,
      service_evidence_entries: serviceEntries,
      worm_service_identity: worm.service_identity,
    }),
    { headers: { "content-type": "application/json", "x-request-id": requestId } },
  );
}

function wormPointer(recordId: string, recordSha256: string, kind: string): JsonObject {
  return {
    digest: recordSha256,
    key:
      `receipts/v1/cloudflare-observations/${OBSERVER_VERSION}/${kind}/` +
      `${recordId.slice("sha256:".length)}.json`,
    retention_until: "2033-08-20T12:00:00.000Z",
    version_id: "b2-cloudflare-evidence-version-0001",
  };
}

export function privatePin(serviceName: string, version: number) {
  return buildPrivatePin(ACCOUNT_ID, serviceName, version);
}
