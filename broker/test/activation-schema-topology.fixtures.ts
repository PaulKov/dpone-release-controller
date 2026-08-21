import { APP_PERMISSIONS } from "../src/activation-contract";
import type { JsonObject } from "../src/types";
import { requireObject } from "../src/validation";

export const SOURCE_COMMIT = "a".repeat(40);
export const WORKER_VERSION = uuid(1);
const ROLES = [
  ["attestation_mutator", "ATTESTATION_MUTATOR"],
  ["candidate_reader", "CANDIDATE_READER"],
  ["closed_projector", "CLOSED_PROJECTOR"],
  ["cloudflare_deployment_observer", "CLOUDFLARE_DEPLOYMENT_OBSERVER"],
  ["controller_run_reader", "CONTROLLER_RUN_READER"],
  ["governance_reader", "GOVERNANCE_READER"],
  ["pypi_deployment_gate", "PYPI_DEPLOYMENT_GATE"],
  ["pypi_reader", "PYPI_READER"],
  ["release_mutator", "RELEASE_MUTATOR"],
  ["runtime_deployment_gate", "RUNTIME_DEPLOYMENT_GATE"],
  ["tenant_scanner", "TENANT_SCANNER"],
  ["worm_mirror", "WORM_MIRROR"],
  ["worm_version_observer", "WORM_VERSION_OBSERVER"],
] as const;

export function privateServices(): JsonObject {
  const result: JsonObject = {};
  for (const [index, [role, binding]] of ROLES.entries()) {
    const workerVersionId = uuid(index + 10);
    const serviceName = `dpone-${role.replaceAll("_", "-")}`;
    const item: JsonObject = {
      binding,
      configuration_sha256: tagged(index + 70),
      service: serviceName,
      service_identity: `cloudflare-worker:${"0".repeat(32)}/${serviceName}@${workerVersionId}`,
      source_commit_sha: SOURCE_COMMIT,
      source_sha256: tagged(index + 40),
      version_resource_projection_sha256: tagged(index + 90),
      worker_version_id: workerVersionId,
    };
    result[role] = item;
  }
  return result;
}

export function githubApps(services: JsonObject): JsonObject {
  const result: JsonObject = {};
  for (const [index, [role, permissions]] of Object.entries(APP_PERMISSIONS).entries()) {
    const controllerScoped = role === "controller_run_reader" || role === "pypi_deployment_gate";
    const deploymentGate = role === "pypi_deployment_gate" || role === "runtime_deployment_gate";
    result[role] = {
      app_id: String(1000 + index),
      app_slug: `dpone-${role.replaceAll("_", "-")}`,
      credential_fingerprint_sha256: tagged(130 + index),
      installation_id: String(2000 + index),
      oauth_callback_configured: false,
      permissions: [...permissions],
      provider_observation_sha256: tagged(150 + index),
      repository: controllerScoped ? "PaulKov/dpone-release-controller" : "PaulKov/dpone",
      repository_id: controllerScoped ? 1_305_993_853 : 1_255_975_556,
      repository_selection: "selected",
      repository_selection_evidence_sha256: tagged(170 + index),
      request_on_install_enabled: false,
      service_binding: serviceBinding(role),
      subscriptions: deploymentGate ? ["deployment_protection_rule"] : [],
      user_authorization_enabled: false,
      webhook_active: deploymentGate,
      worker_version_id: requiredString(service(services, role), "worker_version_id"),
    };
  }
  return result;
}

function serviceBinding(role: string): string {
  const binding = ROLES.find(([candidate]) => candidate === role)?.[1];
  if (binding === undefined) throw new Error(`missing service binding for ${role}`);
  return binding;
}

export function durableObjects(): JsonObject {
  return {
    activation_registry: {
      binding_name: "ACTIVATION_REGISTRY",
      class_name: "ActivationRegistry",
      migration_tag: "v2",
      namespace_id: "1".repeat(32),
    },
    auth_replay_ledger: {
      binding_name: "AUTH_REPLAY_LEDGER",
      class_name: "AuthReplayLedger",
      migration_tag: "v1",
      namespace_id: "2".repeat(32),
    },
    global_activated_authority_head: {
      binding_name: "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
      class_name: "GlobalActivatedAuthorityHead",
      migration_tag: "v3",
      namespace_id: "4".repeat(32),
    },
    release_ledgers: {
      binding_name: "RELEASE_LEDGERS",
      class_name: "ReleaseLedger",
      migration_tag: "v1",
      namespace_id: "3".repeat(32),
    },
  };
}

export function service(services: JsonObject, role: string): JsonObject {
  return requireObject(services[role], "TEST_SERVICE_REQUIRED");
}

export function object(parent: JsonObject, key: string): JsonObject {
  return requireObject(parent[key], "TEST_OBJECT_REQUIRED");
}

export function requiredString(parent: JsonObject, key: string): string {
  const value = parent[key];
  if (typeof value !== "string") throw new Error(`missing ${key}`);
  return value;
}

export function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}

export function uuid(value: number): string {
  return `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`;
}
