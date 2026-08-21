import {
  AUDIENCES,
  B2_BUCKET_ID,
  CF_ID,
  controllerSelectedActions,
  SAFE_NAME,
  SERVICE_BINDINGS,
  WORKER_VERSION,
} from "./activation-contract";
import {
  nested,
  requireDigest,
  requireExactInteger,
  requireExactStringArray,
  requireLiteral,
  requireTimestamp,
} from "./activation-fields";
import { SAFE_CLOUDFLARE_MIGRATION_TAG } from "./cloudflare-migration-tag";
import { isGitSha, TRUST } from "./config";
import { assert } from "./errors";
import type { ActivationAdminSemanticTrust, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireBoolean, requireObject, requireString } from "./validation";

export { validateApps } from "./activation-apps";

export function validateBroker(broker: JsonObject): JsonObject {
  requireLiteral(broker, "api_version", "v1");
  const account = requireString(broker, "cloudflare_account_id", 32, CF_ID);
  const script = requireString(broker, "worker_script", 128, SAFE_NAME);
  const hostname = requireString(
    broker,
    "worker_hostname",
    253,
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u,
  );
  const endpoint = requireString(broker, "endpoint", 512);
  assert(endpoint === `https://${hostname}`, "ACTIVATION_ENDPOINT_INVALID");
  const version = requireString(broker, "worker_version_id", 128, WORKER_VERSION);
  requireString(broker, "worker_version_tag", 128, SAFE_NAME);
  assert(
    requireString(broker, "service_identity", 512) ===
      `cloudflare-worker:${account}/${script}@${version}`,
    "ACTIVATION_SERVICE_IDENTITY_INVALID",
  );
  requireLiteral(broker, "source_repository", TRUST.controllerRepository);
  requireExactInteger(broker, "source_repository_id", TRUST.controllerRepositoryId);
  requireLiteral(broker, "source_path", "broker");
  requireString(broker, "source_commit_sha", 40, /^[0-9a-f]{40}$/u);
  requireString(broker, "source_tree_sha", 40, /^[0-9a-f]{40}$/u);
  for (const key of ["lockfile_sha256", "openapi_sha256", "route_schema_sha256", "source_sha256"]) {
    requireDigest(broker, key);
  }
  requireDigest(broker, "configuration_sha256");
  requireDigest(broker, "version_resource_projection_sha256");
  requireString(broker, "durable_object_migration_tag", 128, SAFE_CLOUDFLARE_MIGRATION_TAG);
  validateDurableObjectInventory(broker.durable_object_namespaces);
  const audiences = nested(broker, "audiences", Object.keys(AUDIENCES));
  for (const [key, expected] of Object.entries(AUDIENCES)) {
    requireLiteral(audiences, key, expected);
  }
  validatePrivateServices(
    requireObject(broker.private_services, "ACTIVATION_SERVICES_REQUIRED"),
    account,
    requireString(broker, "source_commit_sha", 40, /^[0-9a-f]{40}$/u),
  );
  return broker;
}

function validatePrivateServices(
  services: JsonObject,
  cloudflareAccountId: string,
  brokerSourceCommitSha: string,
): void {
  const exact = exactObject(services, Object.keys(SERVICE_BINDINGS));
  const names: string[] = [];
  for (const [role, binding] of Object.entries(SERVICE_BINDINGS)) {
    const fields = [
      "binding",
      "configuration_sha256",
      "service",
      "service_identity",
      "source_commit_sha",
      "source_sha256",
      "version_resource_projection_sha256",
      "worker_version_id",
    ];
    const service = nested(exact, role, fields);
    requireLiteral(service, "binding", binding);
    const serviceName = requireString(service, "service", 128, SAFE_NAME);
    names.push(serviceName);
    requireDigest(service, "configuration_sha256");
    requireDigest(service, "version_resource_projection_sha256");
    assert(
      requireString(service, "source_commit_sha", 40, /^[0-9a-f]{40}$/u) === brokerSourceCommitSha,
      "ACTIVATION_SERVICE_SOURCE_MISMATCH",
    );
    requireDigest(service, "source_sha256");
    const workerVersionId = requireString(service, "worker_version_id", 128, WORKER_VERSION);
    assert(
      requireString(service, "service_identity", 512) ===
        `cloudflare-worker:${cloudflareAccountId}/${serviceName}@${workerVersionId}`,
      "ACTIVATION_SERVICE_IDENTITY_INVALID",
    );
  }
  assert(new Set(names).size === names.length, "ACTIVATION_SERVICE_ALIAS_FORBIDDEN");
}

/** Closed A0 validator exported so the security contract is independently testable. */
export function validatePrivateServiceInventory(
  services: unknown,
  brokerSourceCommitSha: string,
  cloudflareAccountId = "0".repeat(32),
): void {
  assert(isGitSha(brokerSourceCommitSha), "ACTIVATION_SERVICE_SOURCE_INVALID");
  validatePrivateServices(
    requireObject(services, "ACTIVATION_SERVICES_REQUIRED"),
    cloudflareAccountId,
    brokerSourceCommitSha,
  );
}

/** Validates the four isolated, migration-pinned authority namespaces. */
export function validateDurableObjectInventory(value: unknown): void {
  const definitions = {
    activation_registry: {
      binding: "ACTIVATION_REGISTRY",
      className: "ActivationRegistry",
      migrationTag: "v2",
    },
    auth_replay_ledger: {
      binding: "AUTH_REPLAY_LEDGER",
      className: "AuthReplayLedger",
      migrationTag: "v1",
    },
    global_activated_authority_head: {
      binding: "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
      className: "GlobalActivatedAuthorityHead",
      migrationTag: "v3",
    },
    release_ledgers: {
      binding: "RELEASE_LEDGERS",
      className: "ReleaseLedger",
      migrationTag: "v1",
    },
  } as const;
  const inventory = exactObject(value, Object.keys(definitions));
  const namespaceIds: string[] = [];
  for (const [role, definition] of Object.entries(definitions)) {
    const item = nested(inventory, role, [
      "binding_name",
      "class_name",
      "migration_tag",
      "namespace_id",
    ]);
    requireLiteral(item, "binding_name", definition.binding);
    requireLiteral(item, "class_name", definition.className);
    requireLiteral(item, "migration_tag", definition.migrationTag);
    namespaceIds.push(requireString(item, "namespace_id", 32, CF_ID));
  }
  assert(
    new Set(namespaceIds).size === namespaceIds.length,
    "ACTIVATION_DURABLE_OBJECT_NAMESPACE_ALIAS_FORBIDDEN",
  );
}

/** Resolve the exact provider-normalized action policy from immutable Commit A. */
export function assertControllerActionsPolicyFrozen(
  controllerActionCommitSha: string,
): readonly string[] {
  assert(isGitSha(controllerActionCommitSha), "ACTIVATION_CONTROLLER_ACTION_COMMIT_INVALID", 503);
  return controllerSelectedActions(controllerActionCommitSha);
}

export function extractPrivateServicePins(broker: JsonObject): {
  readonly attestationMutator: PrivateServicePin;
  readonly candidateReader: PrivateServicePin;
  readonly closedProjector: PrivateServicePin;
  readonly cloudflareDeploymentObserver: PrivateServicePin;
  readonly controllerRunReader: PrivateServicePin;
  readonly governanceReader: PrivateServicePin;
  readonly pypiDeploymentGate: PrivateServicePin;
  readonly pypiReader: PrivateServicePin;
  readonly releaseMutator: PrivateServicePin;
  readonly runtimeDeploymentGate: PrivateServicePin;
  readonly tenantScanner: PrivateServicePin;
  readonly wormMirror: PrivateServicePin;
  readonly wormVersionObserver: PrivateServicePin;
} {
  return {
    attestationMutator: servicePin(broker, "attestation_mutator"),
    candidateReader: servicePin(broker, "candidate_reader"),
    closedProjector: servicePin(broker, "closed_projector"),
    cloudflareDeploymentObserver: servicePin(broker, "cloudflare_deployment_observer"),
    controllerRunReader: servicePin(broker, "controller_run_reader"),
    governanceReader: servicePin(broker, "governance_reader"),
    pypiDeploymentGate: servicePin(broker, "pypi_deployment_gate"),
    pypiReader: servicePin(broker, "pypi_reader"),
    releaseMutator: servicePin(broker, "release_mutator"),
    runtimeDeploymentGate: servicePin(broker, "runtime_deployment_gate"),
    tenantScanner: servicePin(broker, "tenant_scanner"),
    wormMirror: servicePin(broker, "worm_mirror"),
    wormVersionObserver: servicePin(broker, "worm_version_observer"),
  };
}

export function servicePin(
  broker: JsonObject,
  role: keyof typeof SERVICE_BINDINGS,
): PrivateServicePin {
  const accountId = requireString(broker, "cloudflare_account_id", 32, CF_ID);
  const services = requireObject(broker.private_services, "ACTIVATION_SERVICES_REQUIRED");
  const service = requireObject(services[role], "ACTIVATION_SERVICE_PIN_INVALID");
  const serviceName = requireString(service, "service", 128, SAFE_NAME);
  const versionId = requireString(service, "worker_version_id", 128, WORKER_VERSION);
  return {
    serviceIdentity: `cloudflare-worker:${accountId}/${serviceName}@${versionId}`,
    serviceName,
    versionId,
  };
}

export function validateB2(b2: JsonObject): void {
  requireString(b2, "bucket_id", 24, B2_BUCKET_ID);
  requireString(b2, "bucket_name", 64, SAFE_NAME);
  requireLiteral(b2, "bucket_type", "allPrivate");
  requireLiteral(b2, "prefix", "receipts/v1/");
  requireLiteral(b2, "object_lock_mode", "COMPLIANCE");
  assert(requireBoolean(b2, "object_lock_enabled"), "ACTIVATION_B2_OBJECT_LOCK_REQUIRED");
  requireExactInteger(b2, "retention_days", 2557);
  requireLiteral(b2, "encryption", "SSE-B2");
  requireExactStringArray(b2, "writer_capabilities", ["writeFiles"]);
  requireExactStringArray(b2, "observer_capabilities", [
    "listBuckets",
    "listFiles",
    "readBucketEncryption",
    "readBucketReplications",
    "readBucketRetentions",
    "readFileRetentions",
    "readFiles",
  ]);
  for (const key of [
    "bucket_configuration_evidence_sha256",
    "observer_key_id_sha256",
    "observer_restriction_evidence_sha256",
    "writer_key_id_sha256",
    "writer_restriction_evidence_sha256",
  ]) {
    requireDigest(b2, key);
  }
  assert(
    b2.observer_key_id_sha256 !== b2.writer_key_id_sha256,
    "ACTIVATION_B2_CREDENTIAL_ALIAS_FORBIDDEN",
  );
}

export function validateAdminAccess(
  access: JsonObject,
  config: ActivationAdminSemanticTrust,
): void {
  requireLiteral(access, "access_application_id", config.adminAccessApplicationId);
  requireLiteral(access, "access_audience", config.adminAccessAudience);
  requireDigest(access, "access_group_sha256");
  requireDigest(access, "access_identity_sha256");
  requireLiteral(access, "access_issuer", config.adminAccessIssuer);
  requireLiteral(access, "access_policy_id", config.adminAccessPolicyId);
  requireExactInteger(access, "access_session_duration_seconds", 900);
  requireDigest(access, "access_subject_id_sha256");
  requireLiteral(access, "hostname", config.adminHostname);
  requireLiteral(access, "certificate_fingerprint_sha256", config.adminMtlsCertSha256);
  requireString(access, "mtls_ca_id", 128, SAFE_NAME);
  const notBefore = requireTimestamp(access, "certificate_not_before");
  const notAfter = requireTimestamp(access, "certificate_not_after");
  assert(
    Date.parse(notBefore) < Date.parse(notAfter),
    "ACTIVATION_ADMIN_CERTIFICATE_VALIDITY_INVALID",
  );
  requireLiteral(access, "provision_path", "/v1/admin/activation/provision");
  requireLiteral(access, "finalize_path", "/v1/admin/activation/finalize");
  for (const key of [
    "access_application_evidence_sha256",
    "access_policy_evidence_sha256",
    "certificate_evidence_sha256",
    "certificate_validity_evidence_sha256",
    "hostname_path_rule_evidence_sha256",
    "jwks_evidence_sha256",
    "mtls_ca_evidence_sha256",
    "mtls_provider_observation_sha256",
  ]) {
    requireDigest(access, key);
  }
}
