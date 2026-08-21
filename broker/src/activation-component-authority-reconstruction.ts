import { APP_PERMISSIONS } from "./activation-contract";
import type { ActivationComponentPayloadMap } from "./activation-component-payload-contract";
import { assert } from "./errors";
import {
  parseServiceAuthorityInventory,
  SERVICE_AUTHORITY_ROLES,
  type ServiceAuthorityInventoryRow,
} from "./service-authority";
import { componentError } from "./activation-component-codec";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  parseServiceAuthorityExpectation,
  SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
  type ServiceAuthorityExpectation,
} from "./service-authority-expectation";
import type { ActivationComponentSemanticTrust, JsonObject, JsonValue } from "./types";
import { requireInteger, requireObject, requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ACCOUNT = /^[0-9a-f]{32}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;

export interface ReconstructedActivationAuthorities {
  readonly broker: JsonObject;
  readonly githubApps: JsonObject;
  readonly expectation: ServiceAuthorityExpectation;
}

/** Rebuild the sole broker/apps/expectation authority from normalized component bytes. */
export async function reconstructActivationAuthorities(
  payloads: ActivationComponentPayloadMap,
  config: ActivationComponentSemanticTrust,
): Promise<ReconstructedActivationAuthorities> {
  const header = payloads.service_authority_header;
  requireLiteral(header.schema, SERVICE_AUTHORITY_EXPECTATION_SCHEMA);
  requireLiteral(header.schema_version, 1);
  const accountId = requireString(header, "cloudflare_account_id", 32, ACCOUNT);
  const sourceCommitSha = requireString(header, "broker_source_commit_sha", 40, GIT_SHA);
  const expectationSha256 = requireString(header, "expectation_sha256", 71, DIGEST);
  assert(accountId === config.cloudflareAccountId, "ACTIVATION_COMPONENT_ACCOUNT_MISMATCH", 409);

  const inventory = inventoryRows(payloads.service_authority_inventory, accountId);
  const ingress = inventory[SERVICE_AUTHORITY_ROLES.indexOf("release_authority_ingress")];
  assert(ingress !== undefined, "ACTIVATION_COMPONENT_INGRESS_MISSING", 500);
  assert(
    ingress.worker_version_id === config.workerVersionId &&
      ingress.service_identity === config.workerServiceIdentity,
    "ACTIVATION_COMPONENT_WORKER_MISMATCH",
    409,
  );
  const broker = reconstructBroker(
    payloads.broker_core,
    inventory,
    ingress,
    accountId,
    sourceCommitSha,
  );
  const githubApps = reconstructApps(payloads.github_apps, inventory);
  const expectationDocument: JsonObject = {
    authorities: inventory.map((row) => ({ ...row })),
    broker_source_commit_sha: sourceCommitSha,
    cloudflare_account_id: accountId,
    deployment_expectations: {
      a0_pre: reconstructDeployments(payloads.service_authority_a0_deployments, inventory),
      a1_precommit: reconstructDeployments(payloads.service_authority_a1_deployments, inventory),
    },
    network_surface: reconstructNetwork(payloads.service_authority_network, ingress.service),
    receipt_role_bindings: structuredClone(
      payloads.service_authority_receipt_bindings.receipt_role_bindings ?? null,
    ),
    schema: SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
    schema_version: 1,
  };
  const expectation = await parseServiceAuthorityExpectation(
    expectationDocument,
    expectationSha256,
    accountId,
    sourceCommitSha,
  );
  assertServiceAuthorityExpectationMatchesBroker(expectation, broker);
  return Object.freeze({ broker, expectation, githubApps });
}

function inventoryRows(
  payload: JsonObject,
  accountId: string,
): readonly ServiceAuthorityInventoryRow[] {
  return parseServiceAuthorityInventory(payload.authorities, accountId);
}

function reconstructBroker(
  core: JsonObject,
  inventory: readonly ServiceAuthorityInventoryRow[],
  ingress: ServiceAuthorityInventoryRow,
  accountId: string,
  sourceCommitSha: string,
): JsonObject {
  requireLiteral(core.authority_role, "release_authority_ingress");
  const privateServices: JsonObject = {};
  for (const row of inventory) {
    if (row.authority_role === "release_authority_ingress") continue;
    privateServices[row.authority_role] = {
      binding: row.binding,
      configuration_sha256: row.configuration_sha256,
      service: row.service,
      service_identity: row.service_identity,
      source_commit_sha: row.source_commit_sha,
      source_sha256: row.source_sha256,
      version_resource_projection_sha256: row.version_resource_projection_sha256,
      worker_version_id: row.worker_version_id,
    };
  }
  const brokerCore = Object.fromEntries(
    Object.entries(core).filter(([field]) => field !== "authority_role"),
  );
  return {
    ...brokerCore,
    cloudflare_account_id: accountId,
    configuration_sha256: ingress.configuration_sha256,
    private_services: privateServices,
    service_identity: ingress.service_identity,
    source_commit_sha: sourceCommitSha,
    source_sha256: ingress.source_sha256,
    version_resource_projection_sha256: ingress.version_resource_projection_sha256,
    worker_script: ingress.service,
    worker_version_id: ingress.worker_version_id,
  };
}

function reconstructApps(
  normalized: JsonObject,
  inventory: readonly ServiceAuthorityInventoryRow[],
): JsonObject {
  const result: JsonObject = {};
  for (const role of Object.keys(APP_PERMISSIONS)) {
    const app = requireObject(normalized[role], "ACTIVATION_COMPONENT_APP_INTERNAL_INVALID");
    const authority = inventory.find((row) => row.authority_role === role);
    assert(authority !== undefined, "ACTIVATION_COMPONENT_APP_AUTHORITY_MISSING", 500);
    result[role] = {
      ...app,
      service_binding: authority.binding,
      worker_version_id: authority.worker_version_id,
    };
  }
  return result;
}

function reconstructDeployments(
  wrapper: JsonObject,
  inventory: readonly ServiceAuthorityInventoryRow[],
): JsonValue[] {
  const rows = wrapper.deployments;
  if (!Array.isArray(rows) || rows.length !== inventory.length) {
    throw componentError("ACTIVATION_COMPONENT_DEPLOYMENTS_INTERNAL_INVALID", 500);
  }
  return rows.map((candidate, index) => {
    const row = requireObject(candidate, "ACTIVATION_COMPONENT_DEPLOYMENTS_INTERNAL_INVALID");
    const authority = inventory[index];
    assert(authority !== undefined, "ACTIVATION_COMPONENT_DEPLOYMENTS_INTERNAL_INVALID", 500);
    requireLiteral(row.authority_role, authority.authority_role);
    const members = row.deployment_versions;
    assert(Array.isArray(members), "ACTIVATION_COMPONENT_DEPLOYMENTS_INTERNAL_INVALID", 500);
    return {
      authority_role: authority.authority_role,
      deployment_id: row.deployment_id ?? null,
      deployment_versions: members.map((candidateMember) => {
        const member = requireObject(
          candidateMember,
          "ACTIVATION_COMPONENT_DEPLOYMENTS_INTERNAL_INVALID",
        );
        return member.artifact_kind === "FINAL_AUTHORITY"
          ? reconstructFinalMember(member, authority)
          : structuredClone(member);
      }),
      service: authority.service,
    };
  });
}

function reconstructFinalMember(
  member: JsonObject,
  authority: ServiceAuthorityInventoryRow,
): JsonObject {
  requireLiteral(member.artifact_kind, "FINAL_AUTHORITY");
  return {
    artifact_kind: "FINAL_AUTHORITY",
    configuration_sha256: authority.configuration_sha256,
    percentage: requireInteger(member, "percentage", 0, 100),
    provisioning_record_id: requireString(member, "provisioning_record_id", 71),
    provisioning_record_sha256: requireString(member, "provisioning_record_sha256", 71),
    script_etag: requireString(member, "script_etag", 128),
    source_sha256: authority.source_sha256,
    version_resource_projection_sha256: authority.version_resource_projection_sha256,
    worker_version_id: authority.worker_version_id,
  };
}

function reconstructNetwork(network: JsonObject, ingressService: string): JsonObject {
  requireLiteral(network.authority_role, "release_authority_ingress");
  const surface = Object.fromEntries(
    Object.entries(network).filter(([field]) => field !== "authority_role"),
  );
  return { ...surface, service: ingressService };
}

function requireLiteral(actual: JsonValue | undefined, expected: JsonValue): void {
  assert(actual === expected, "ACTIVATION_COMPONENT_LITERAL_MISMATCH");
}
