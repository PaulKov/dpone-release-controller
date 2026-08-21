import { canonicalJson, digestObject } from "./canonical";
import { assert } from "./errors";
import {
  parseExpectedCloudflareNetworkSurface,
  parseExpectedServiceDeployments,
  parseServiceAuthorityInventory,
  type ExpectedCloudflareNetworkSurface,
  type ExpectedServiceDeployment,
  type ServiceAuthorityInventoryRow,
} from "./service-authority";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireObject, requireString } from "./validation";

export const SERVICE_AUTHORITY_EXPECTATION_SCHEMA =
  "dpone.release-broker-service-authority-expectation.v1";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;
const ACCOUNT_ID = /^[0-9a-f]{32}$/u;

export const RECEIPT_ROLE_BINDINGS = Object.freeze([
  Object.freeze({
    service_authority_role: "attestation_mutator",
    service_role: "attestation_mutator",
  }),
  Object.freeze({
    service_authority_role: "governance_reader",
    service_role: "attestation_reader",
  }),
  Object.freeze({
    service_authority_role: "release_authority_ingress",
    service_role: "cancellation_observer",
  }),
  Object.freeze({
    service_authority_role: "closed_projector",
    service_role: "closed_check_mutator",
  }),
  Object.freeze({
    service_authority_role: "controller_run_reader",
    service_role: "controller_run_reader",
  }),
  Object.freeze({
    service_authority_role: "release_authority_ingress",
    service_role: "draft_ledger_orchestrator",
  }),
  Object.freeze({
    service_authority_role: "release_mutator",
    service_role: "github_draft_mutator",
  }),
  Object.freeze({
    service_authority_role: "governance_reader",
    service_role: "github_governance_reader",
  }),
  Object.freeze({
    service_authority_role: "release_mutator",
    service_role: "github_release_mutator",
  }),
  Object.freeze({
    service_authority_role: "release_authority_ingress",
    service_role: "lease_orchestrator",
  }),
  Object.freeze({
    service_authority_role: "release_authority_ingress",
    service_role: "ledger_orchestrator",
  }),
  Object.freeze({
    service_authority_role: "pypi_deployment_gate",
    service_role: "pypi_deployment_gate",
  }),
  Object.freeze({ service_authority_role: "pypi_reader", service_role: "pypi_reader" }),
  Object.freeze({
    service_authority_role: "release_authority_ingress",
    service_role: "recovery_observer",
  }),
  Object.freeze({ service_authority_role: "tenant_scanner", service_role: "tenant_scanner" }),
] as const);

export interface ServiceAuthorityExpectation {
  readonly a0PreDeployments: readonly ExpectedServiceDeployment[];
  readonly a1PrecommitDeployments: readonly ExpectedServiceDeployment[];
  readonly authorities: readonly ServiceAuthorityInventoryRow[];
  readonly document: JsonObject;
  readonly expectationSha256: string;
  readonly networkSurface: ExpectedCloudflareNetworkSurface;
}

/** Cross-bind the fourteen-row authority expectation before any provider effect. */
export function assertServiceAuthorityExpectationMatchesBroker(
  expectation: ServiceAuthorityExpectation,
  broker: JsonObject,
): void {
  const brokerHostname = requireString(broker, "worker_hostname", 253);
  const brokerEndpoint = requireString(broker, "endpoint", 512);
  const brokerService = requireString(broker, "worker_script", 128);
  assert(
    expectation.networkSurface.hostname === brokerHostname &&
      expectation.networkSurface.service === brokerService &&
      brokerEndpoint === `https://${brokerHostname}`,
    "SERVICE_AUTHORITY_BROKER_CROSS_BIND_MISMATCH",
    409,
  );
  const privateServices = requireObject(
    broker.private_services,
    "SERVICE_AUTHORITY_BROKER_SERVICES_REQUIRED",
  );
  for (const authority of expectation.authorities) {
    const source =
      authority.authority_role === "release_authority_ingress"
        ? ingressAuthorityProjection(broker)
        : privateAuthorityProjection(
            authority.authority_role,
            requireObject(
              privateServices[authority.authority_role],
              "SERVICE_AUTHORITY_BROKER_SERVICE_REQUIRED",
            ),
          );
    assert(
      canonicalJson(source) === canonicalJson(authority),
      "SERVICE_AUTHORITY_BROKER_CROSS_BIND_MISMATCH",
      409,
    );
  }
}

/** Parse and hash the sole immutable authority expectation carried by A0. */
export async function parseServiceAuthorityExpectation(
  value: unknown,
  suppliedDigest: unknown,
  cloudflareAccountId: string,
  brokerSourceCommitSha: string,
): Promise<ServiceAuthorityExpectation> {
  const document = exactObject(value, [
    "authorities",
    "broker_source_commit_sha",
    "cloudflare_account_id",
    "deployment_expectations",
    "network_surface",
    "receipt_role_bindings",
    "schema",
    "schema_version",
  ]);
  literal(document, "schema", SERVICE_AUTHORITY_EXPECTATION_SCHEMA);
  integer(document, "schema_version", 1);
  literal(document, "cloudflare_account_id", cloudflareAccountId);
  literal(document, "broker_source_commit_sha", brokerSourceCommitSha);
  requireString(document, "cloudflare_account_id", 32, ACCOUNT_ID);
  requireString(document, "broker_source_commit_sha", 40, GIT_SHA);
  parseReceiptRoleBindings(document.receipt_role_bindings);
  const authorities = parseServiceAuthorityInventory(document.authorities, cloudflareAccountId);
  assert(
    authorities.every((row) => row.source_commit_sha === brokerSourceCommitSha),
    "SERVICE_AUTHORITY_SOURCE_COMMIT_MISMATCH",
  );
  const expectations = exactObject(document.deployment_expectations, ["a0_pre", "a1_precommit"]);
  const a0PreDeployments = parseExpectedServiceDeployments(expectations.a0_pre, "A0_PRE");
  const a1PrecommitDeployments = parseExpectedServiceDeployments(
    expectations.a1_precommit,
    "A1_PRECOMMIT",
    true,
  );
  const networkSurface = parseExpectedCloudflareNetworkSurface(document.network_surface);
  crossBindExpectedDeployments(authorities, a0PreDeployments, a1PrecommitDeployments);
  const expectationSha256 = await digestObject(document);
  assert(
    typeof suppliedDigest === "string" &&
      DIGEST.test(suppliedDigest) &&
      suppliedDigest === expectationSha256,
    "SERVICE_AUTHORITY_EXPECTATION_DIGEST_MISMATCH",
    409,
  );
  return {
    a0PreDeployments,
    a1PrecommitDeployments,
    authorities,
    document,
    expectationSha256,
    networkSurface,
  };
}

/** Bind the future ingress deployment ID returned by the promotion report. */
export function materializeA1PrecommitDeployments(
  expected: readonly ExpectedServiceDeployment[],
  ingressDeploymentId: string,
): readonly ExpectedServiceDeployment[] {
  const value = expected.map((deployment) => ({
    authority_role: deployment.authority_role,
    deployment_id:
      deployment.authority_role === "release_authority_ingress"
        ? ingressDeploymentId
        : deployment.deployment_id,
    deployment_versions: deployment.deployment_versions.map((member) => ({ ...member })),
    service: deployment.service,
  }));
  return parseExpectedServiceDeployments(value, "A1_PRECOMMIT");
}

function parseReceiptRoleBindings(value: unknown): void {
  assert(
    canonicalJson({ value: value as JsonValue }) ===
      canonicalJson({ value: RECEIPT_ROLE_BINDINGS as unknown as JsonValue }),
    "SERVICE_AUTHORITY_RECEIPT_ROLE_BINDINGS_MISMATCH",
  );
}

function crossBindExpectedDeployments(
  authorities: readonly ServiceAuthorityInventoryRow[],
  a0: readonly ExpectedServiceDeployment[],
  a1: readonly ExpectedServiceDeployment[],
): void {
  authorities.forEach((authority, index) => {
    const a0Deployment = a0[index];
    const a1Deployment = a1[index];
    const finalA0 = a0Deployment?.deployment_versions.find(
      (member) => member.artifact_kind === "FINAL_AUTHORITY",
    );
    const finalA1 = a1Deployment?.deployment_versions[0];
    const immutable = (member: typeof finalA0): JsonObject | null =>
      member === undefined
        ? null
        : {
            artifact_kind: member.artifact_kind,
            configuration_sha256: member.configuration_sha256,
            provisioning_record_id: member.provisioning_record_id,
            provisioning_record_sha256: member.provisioning_record_sha256,
            script_etag: member.script_etag,
            source_sha256: member.source_sha256,
            version_resource_projection_sha256: member.version_resource_projection_sha256,
            worker_version_id: member.worker_version_id,
          };
    assert(
      a0Deployment !== undefined &&
        a1Deployment !== undefined &&
        finalA0 !== undefined &&
        finalA1 !== undefined &&
        canonicalJson(immutable(finalA0)) === canonicalJson(immutable(finalA1)) &&
        finalA1.percentage === 100 &&
        finalA0.percentage ===
          (authority.authority_role === "release_authority_ingress" ? 0 : 100) &&
        (authority.authority_role === "release_authority_ingress"
          ? a1Deployment.deployment_id === null
          : a0Deployment.deployment_id === a1Deployment.deployment_id) &&
        finalA1.worker_version_id === authority.worker_version_id &&
        finalA1.configuration_sha256 === authority.configuration_sha256 &&
        finalA1.source_sha256 === authority.source_sha256 &&
        finalA1.version_resource_projection_sha256 === authority.version_resource_projection_sha256,
      "SERVICE_AUTHORITY_EXPECTATION_VERSION_MISMATCH",
    );
  });
}

function ingressAuthorityProjection(broker: JsonObject): JsonObject {
  return {
    authority_role: "release_authority_ingress",
    binding: "INGRESS",
    configuration_sha256: broker.configuration_sha256 ?? null,
    service: broker.worker_script ?? null,
    service_identity: broker.service_identity ?? null,
    source_commit_sha: broker.source_commit_sha ?? null,
    source_sha256: broker.source_sha256 ?? null,
    version_resource_projection_sha256: broker.version_resource_projection_sha256 ?? null,
    worker_version_id: broker.worker_version_id ?? null,
  };
}

function privateAuthorityProjection(
  authorityRole: Exclude<
    ServiceAuthorityInventoryRow["authority_role"],
    "release_authority_ingress"
  >,
  service: JsonObject,
): JsonObject {
  return {
    authority_role: authorityRole,
    binding: service.binding ?? null,
    configuration_sha256: service.configuration_sha256 ?? null,
    service: service.service ?? null,
    service_identity: service.service_identity ?? null,
    source_commit_sha: service.source_commit_sha ?? null,
    source_sha256: service.source_sha256 ?? null,
    version_resource_projection_sha256: service.version_resource_projection_sha256 ?? null,
    worker_version_id: service.worker_version_id ?? null,
  };
}

function literal(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "SERVICE_AUTHORITY_LITERAL_MISMATCH",
  );
}

function integer(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "SERVICE_AUTHORITY_INTEGER_MISMATCH",
  );
}
