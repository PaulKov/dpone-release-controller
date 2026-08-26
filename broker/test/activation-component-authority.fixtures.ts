import { AUDIENCES } from "../src/activation-contract";
import { digestObject } from "../src/canonical";
import {
  RECEIPT_ROLE_BINDINGS,
  SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
} from "../src/service-authority-activation";
import { SERVICE_AUTHORITY_DEFINITIONS, SERVICE_AUTHORITY_ROLES } from "../src/service-authority";
import type { JsonObject } from "../src/types";
import {
  durableObjects,
  requiredString,
  tagged,
  uuid,
} from "./activation-schema-topology.fixtures";

export const VALID_A0_ACCOUNT_ID = "a".repeat(32);
export const VALID_A0_SOURCE_COMMIT = "b".repeat(40);
export const VALID_A0_WORKER_VERSION = uuid(900);
export const VALID_A0_HOSTNAME = "release.example.test";

export interface ValidServiceAuthorityFixture {
  readonly broker: JsonObject;
  readonly expectationDocument: JsonObject;
  readonly expectationSha256: string;
}

/** Build one broker/expectation pair from a single 14-row authority inventory. */
export async function validServiceAuthorityFixture(): Promise<ValidServiceAuthorityFixture> {
  const authorities = authorityInventory();
  const expectationDocument = authorityExpectation(authorities);
  const expectationSha256 = await digestObject(expectationDocument);
  return {
    broker: brokerEvidence(authorities),
    expectationDocument,
    expectationSha256,
  };
}

function authorityInventory(): JsonObject[] {
  return SERVICE_AUTHORITY_ROLES.map((authorityRole, index) => {
    const definition = SERVICE_AUTHORITY_DEFINITIONS[authorityRole];
    const workerVersionId =
      authorityRole === "release_authority_ingress" ? VALID_A0_WORKER_VERSION : uuid(index + 10);
    return {
      authority_role: authorityRole,
      binding: definition.binding,
      configuration_sha256: tagged(index + 10),
      service: definition.service,
      service_identity: `cloudflare-worker:${VALID_A0_ACCOUNT_ID}/${definition.service}@${workerVersionId}`,
      source_commit_sha: VALID_A0_SOURCE_COMMIT,
      source_sha256: tagged(index + 30),
      version_resource_projection_sha256: tagged(index + 50),
      worker_version_id: workerVersionId,
    };
  });
}

function authorityExpectation(authorities: readonly JsonObject[]): JsonObject {
  const a0 = authorities.map((authority, index) => {
    const role = requiredString(authority, "authority_role");
    const final = deploymentMember(
      "FINAL_AUTHORITY",
      authority,
      role === "release_authority_ingress" ? 0 : 100,
      index + 300,
    );
    const deploymentVersions =
      role === "release_authority_ingress"
        ? [deploymentMember("BOOTSTRAP_DENY", undefined, 100, index + 200), final].sort(
            (left, right) =>
              requiredString(left, "worker_version_id").localeCompare(
                requiredString(right, "worker_version_id"),
              ),
          )
        : [final];
    return {
      authority_role: role,
      deployment_id: uuid(index + 100),
      deployment_versions: deploymentVersions,
      service: requiredString(authority, "service"),
    };
  });
  const a1 = authorities.map((authority, index) => {
    const role = requiredString(authority, "authority_role");
    return {
      authority_role: role,
      deployment_id: role === "release_authority_ingress" ? null : uuid(index + 100),
      deployment_versions: [deploymentMember("FINAL_AUTHORITY", authority, 100, index + 300)],
      service: requiredString(authority, "service"),
    };
  });
  return {
    authorities: authorities.map((authority) => ({ ...authority })),
    broker_source_commit_sha: VALID_A0_SOURCE_COMMIT,
    cloudflare_account_id: VALID_A0_ACCOUNT_ID,
    deployment_expectations: { a0_pre: a0, a1_precommit: a1 },
    network_surface: {
      cert_id: uuid(700),
      domain_id: "c".repeat(32),
      environment: "production",
      hostname: VALID_A0_HOSTNAME,
      service: SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service,
      zone_id: "d".repeat(32),
      zone_name: "example.test",
    },
    receipt_role_bindings: RECEIPT_ROLE_BINDINGS.map((row) => ({ ...row })),
    schema: SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
    schema_version: 1,
  };
}

function deploymentMember(
  artifactKind: "BOOTSTRAP_DENY" | "FINAL_AUTHORITY",
  authority: JsonObject | undefined,
  percentage: number,
  seed: number,
): JsonObject {
  return {
    artifact_kind: artifactKind,
    configuration_sha256:
      authority === undefined
        ? tagged(seed + 1)
        : requiredString(authority, "configuration_sha256"),
    percentage,
    provisioning_record_id: tagged(seed + 2),
    provisioning_record_sha256: tagged(seed + 3),
    script_etag: `etag-${seed}`,
    source_sha256:
      authority === undefined ? tagged(seed + 4) : requiredString(authority, "source_sha256"),
    version_resource_projection_sha256:
      authority === undefined
        ? tagged(seed + 5)
        : requiredString(authority, "version_resource_projection_sha256"),
    worker_version_id:
      authority === undefined ? uuid(1) : requiredString(authority, "worker_version_id"),
  };
}

function brokerEvidence(authorities: readonly JsonObject[]): JsonObject {
  const ingress = authorities.find((row) => row.authority_role === "release_authority_ingress");
  if (ingress === undefined) throw new Error("valid A0 ingress authority missing");
  const privateServices: JsonObject = {};
  for (const authority of authorities) {
    const authorityRole = requiredString(authority, "authority_role");
    if (authorityRole === "release_authority_ingress") continue;
    privateServices[authorityRole] = {
      binding: requiredString(authority, "binding"),
      configuration_sha256: requiredString(authority, "configuration_sha256"),
      service: requiredString(authority, "service"),
      service_identity: requiredString(authority, "service_identity"),
      source_commit_sha: VALID_A0_SOURCE_COMMIT,
      source_sha256: requiredString(authority, "source_sha256"),
      version_resource_projection_sha256: requiredString(
        authority,
        "version_resource_projection_sha256",
      ),
      worker_version_id: requiredString(authority, "worker_version_id"),
    };
  }
  return {
    api_version: "v1",
    audiences: { ...AUDIENCES },
    cloudflare_account_id: VALID_A0_ACCOUNT_ID,
    configuration_sha256: requiredString(ingress, "configuration_sha256"),
    durable_object_migration_tag: "release.2026-08-19_v4",
    durable_object_namespaces: durableObjects(),
    endpoint: `https://${VALID_A0_HOSTNAME}`,
    lockfile_sha256: tagged(201),
    openapi_sha256: tagged(202),
    private_services: privateServices,
    route_schema_sha256: tagged(203),
    service_identity: requiredString(ingress, "service_identity"),
    source_commit_sha: VALID_A0_SOURCE_COMMIT,
    source_path: "broker",
    source_repository: "PaulKov/dpone-release-controller",
    source_repository_id: 1_305_993_853,
    source_sha256: requiredString(ingress, "source_sha256"),
    source_tree_sha: "c".repeat(40),
    version_resource_projection_sha256: requiredString(
      ingress,
      "version_resource_projection_sha256",
    ),
    worker_hostname: VALID_A0_HOSTNAME,
    worker_script: requiredString(ingress, "service"),
    worker_version_id: VALID_A0_WORKER_VERSION,
    worker_version_tag: "release-v4",
  };
}
