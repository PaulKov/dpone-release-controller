import { assert, BrokerError } from "./errors";
import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const SERVICE_AUTHORITY_DEFINITIONS = Object.freeze({
  attestation_mutator: Object.freeze({
    binding: "ATTESTATION_MUTATOR",
    service: "dpone-release-attestation-mutator",
  }),
  candidate_reader: Object.freeze({
    binding: "CANDIDATE_READER",
    service: "dpone-release-candidate-reader",
  }),
  closed_projector: Object.freeze({
    binding: "CLOSED_PROJECTOR",
    service: "dpone-release-closed-projector",
  }),
  cloudflare_deployment_observer: Object.freeze({
    binding: "CLOUDFLARE_DEPLOYMENT_OBSERVER",
    service: "dpone-release-cloudflare-deployment-observer",
  }),
  controller_run_reader: Object.freeze({
    binding: "CONTROLLER_RUN_READER",
    service: "dpone-release-controller-run-reader",
  }),
  governance_reader: Object.freeze({
    binding: "GOVERNANCE_READER",
    service: "dpone-release-governance-reader",
  }),
  pypi_deployment_gate: Object.freeze({
    binding: "PYPI_DEPLOYMENT_GATE",
    service: "dpone-release-pypi-deployment-gate",
  }),
  pypi_reader: Object.freeze({
    binding: "PYPI_READER",
    service: "dpone-release-pypi-reader",
  }),
  release_authority_ingress: Object.freeze({
    binding: "INGRESS",
    service: "dpone-release-authority-broker",
  }),
  release_mutator: Object.freeze({
    binding: "RELEASE_MUTATOR",
    service: "dpone-release-mutator",
  }),
  runtime_deployment_gate: Object.freeze({
    binding: "RUNTIME_DEPLOYMENT_GATE",
    service: "dpone-release-runtime-deployment-gate",
  }),
  tenant_scanner: Object.freeze({
    binding: "TENANT_SCANNER",
    service: "dpone-release-tenant-scanner",
  }),
  worm_mirror: Object.freeze({
    binding: "WORM_MIRROR",
    service: "dpone-release-worm-mirror",
  }),
  worm_version_observer: Object.freeze({
    binding: "WORM_VERSION_OBSERVER",
    service: "dpone-release-worm-version-observer",
  }),
});

export const SERVICE_AUTHORITY_ROLES = Object.freeze(
  Object.keys(SERVICE_AUTHORITY_DEFINITIONS),
) as readonly ServiceAuthorityRole[];

export type ServiceAuthorityRole = keyof typeof SERVICE_AUTHORITY_DEFINITIONS;
export type DeploymentObservationPhase = "A0_PRE" | "A1_PRECOMMIT";

export interface ExpectedDeploymentVersion {
  readonly artifact_kind: "BOOTSTRAP_DENY" | "FINAL_AUTHORITY";
  readonly configuration_sha256: string;
  readonly percentage: number;
  readonly provisioning_record_id: string;
  readonly provisioning_record_sha256: string;
  readonly script_etag: string;
  readonly source_sha256: string;
  readonly version_resource_projection_sha256: string;
  readonly worker_version_id: string;
}

export interface ExpectedServiceDeployment {
  readonly authority_role: ServiceAuthorityRole;
  readonly deployment_id: string | null;
  readonly deployment_versions: readonly ExpectedDeploymentVersion[];
  readonly service: string;
}

export interface ExpectedCloudflareNetworkSurface {
  readonly cert_id: string;
  readonly domain_id: string;
  readonly environment: null | "production";
  readonly hostname: string;
  readonly service: string;
  readonly zone_id: string;
  readonly zone_name: string;
}

export interface ServiceAuthorityInventoryRow {
  readonly authority_role: ServiceAuthorityRole;
  readonly binding: string;
  readonly configuration_sha256: string;
  readonly service: string;
  readonly service_identity: string;
  readonly source_commit_sha: string;
  readonly source_sha256: string;
  readonly version_resource_projection_sha256: string;
  readonly worker_version_id: string;
}

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const GIT_SHA = /^[0-9a-f]{40}$/u;
const VERSION = CLOUDFLARE_UUID;
const ACCOUNT_OBJECT_ID = /^[0-9a-f]{32}$/u;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;

/**
 * Parse the cross-language, ASCII-ordered fourteen-row executable authority
 * inventory. Credentials, provider tokens and credential fingerprints are
 * intentionally outside this sanitized document.
 */
export function parseServiceAuthorityInventory(
  value: unknown,
  cloudflareAccountId: string,
): readonly ServiceAuthorityInventoryRow[] {
  if (!Array.isArray(value) || value.length !== SERVICE_AUTHORITY_ROLES.length) {
    throw new BrokerError("SERVICE_AUTHORITY_INVENTORY_INVALID", 400, false);
  }
  const rows = value.map((item, index) => {
    const row = exactObject(item, [
      "authority_role",
      "binding",
      "configuration_sha256",
      "service",
      "service_identity",
      "source_commit_sha",
      "source_sha256",
      "version_resource_projection_sha256",
      "worker_version_id",
    ]);
    const authorityRole = requireAuthorityRole(row, index);
    const definition = SERVICE_AUTHORITY_DEFINITIONS[authorityRole];
    const service = requireString(row, "service", 128);
    const workerVersionId = requireString(row, "worker_version_id", 128, VERSION);
    assert(service === definition.service, "SERVICE_AUTHORITY_SERVICE_MISMATCH");
    assert(
      requireString(row, "binding", 64) === definition.binding,
      "SERVICE_AUTHORITY_BINDING_MISMATCH",
    );
    assert(
      requireString(row, "service_identity", 512) ===
        `cloudflare-worker:${cloudflareAccountId}/${service}@${workerVersionId}`,
      "SERVICE_AUTHORITY_IDENTITY_MISMATCH",
    );
    return Object.freeze({
      authority_role: authorityRole,
      binding: definition.binding,
      configuration_sha256: requireString(row, "configuration_sha256", 71, DIGEST),
      service,
      service_identity: requireString(row, "service_identity", 512),
      source_commit_sha: requireString(row, "source_commit_sha", 40, GIT_SHA),
      source_sha256: requireString(row, "source_sha256", 71, DIGEST),
      version_resource_projection_sha256: requireString(
        row,
        "version_resource_projection_sha256",
        71,
        DIGEST,
      ),
      worker_version_id: workerVersionId,
    });
  });
  assertUnique(
    rows.map((row) => row.service),
    "SERVICE_AUTHORITY_SERVICE_ALIAS_FORBIDDEN",
  );
  assertUnique(
    rows.map((row) => row.worker_version_id),
    "SERVICE_AUTHORITY_VERSION_ALIAS_FORBIDDEN",
  );
  return Object.freeze(rows);
}

/** Parse the exact pre-A1 or post-A1 provider deployment expectation. */
export function parseExpectedServiceDeployments(
  value: unknown,
  phase: DeploymentObservationPhase,
  allowUnresolvedIngress = false,
): readonly ExpectedServiceDeployment[] {
  if (!Array.isArray(value) || value.length !== SERVICE_AUTHORITY_ROLES.length) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EXPECTATION_INVALID", 400, false);
  }
  const rows = value.map((item, index) => {
    const row = exactObject(item, [
      "authority_role",
      "deployment_id",
      "deployment_versions",
      "service",
    ]);
    const authorityRole = requireAuthorityRole(row, index);
    const service = requireString(row, "service", 128);
    assert(
      service === SERVICE_AUTHORITY_DEFINITIONS[authorityRole].service,
      "CLOUDFLARE_DEPLOYMENT_SERVICE_MISMATCH",
    );
    if (!Array.isArray(row.deployment_versions)) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_MEMBERSHIP_INVALID", 400, false);
    }
    const deploymentVersions = row.deployment_versions.map((candidate) => {
      const member = exactObject(candidate, [
        "artifact_kind",
        "configuration_sha256",
        "percentage",
        "provisioning_record_id",
        "provisioning_record_sha256",
        "script_etag",
        "source_sha256",
        "version_resource_projection_sha256",
        "worker_version_id",
      ]);
      const artifactKind = requireString(member, "artifact_kind", 32);
      assert(
        artifactKind === "BOOTSTRAP_DENY" || artifactKind === "FINAL_AUTHORITY",
        "CLOUDFLARE_DEPLOYMENT_ARTIFACT_KIND_INVALID",
      );
      return Object.freeze({
        artifact_kind: artifactKind,
        configuration_sha256: requireString(member, "configuration_sha256", 71, DIGEST),
        percentage: requireInteger(member, "percentage", 0, 100),
        provisioning_record_id: requireString(member, "provisioning_record_id", 71, DIGEST),
        provisioning_record_sha256: requireString(member, "provisioning_record_sha256", 71, DIGEST),
        script_etag: requireString(member, "script_etag", 128, /^[A-Za-z0-9._:-]{1,128}$/u),
        source_sha256: requireString(member, "source_sha256", 71, DIGEST),
        version_resource_projection_sha256: requireString(
          member,
          "version_resource_projection_sha256",
          71,
          DIGEST,
        ),
        worker_version_id: requireString(member, "worker_version_id", 128, VERSION),
      });
    });
    assertUnique(
      deploymentVersions.map((member) => member.worker_version_id),
      "CLOUDFLARE_DEPLOYMENT_VERSION_ALIAS_FORBIDDEN",
    );
    assertAsciiSorted(
      deploymentVersions.map((member) => member.worker_version_id),
      "CLOUDFLARE_DEPLOYMENT_VERSION_ORDER_INVALID",
    );
    validatePhaseMembership(authorityRole, deploymentVersions, phase);
    const final = deploymentVersions.filter((member) => member.artifact_kind === "FINAL_AUTHORITY");
    assert(final.length === 1, "CLOUDFLARE_DEPLOYMENT_FINAL_ARTIFACT_INVALID");
    const deploymentId =
      row.deployment_id === null &&
      allowUnresolvedIngress &&
      phase === "A1_PRECOMMIT" &&
      authorityRole === "release_authority_ingress"
        ? null
        : requireString(row, "deployment_id", 36, VERSION);
    return Object.freeze({
      authority_role: authorityRole,
      deployment_id: deploymentId,
      deployment_versions: Object.freeze(deploymentVersions),
      service,
    });
  });
  return Object.freeze(rows);
}

export function isServiceAuthorityRole(value: string): value is ServiceAuthorityRole {
  return Object.hasOwn(SERVICE_AUTHORITY_DEFINITIONS, value);
}

/** Exact reviewed Custom Domain boundary for the ingress authority. */
export function parseExpectedCloudflareNetworkSurface(
  value: unknown,
): ExpectedCloudflareNetworkSurface {
  const surface = exactObject(value, [
    "cert_id",
    "domain_id",
    "environment",
    "hostname",
    "service",
    "zone_id",
    "zone_name",
  ]);
  assert(
    surface.environment === null || surface.environment === "production",
    "CLOUDFLARE_NETWORK_ENVIRONMENT_FORBIDDEN",
  );
  const service = requireString(surface, "service", 128);
  assert(
    service === SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service,
    "CLOUDFLARE_NETWORK_SERVICE_MISMATCH",
  );
  return Object.freeze({
    cert_id: requireString(surface, "cert_id", 36, UUID),
    domain_id: requireString(surface, "domain_id", 32, ACCOUNT_OBJECT_ID),
    environment: surface.environment,
    hostname: requireString(surface, "hostname", 253, HOSTNAME),
    service,
    zone_id: requireString(surface, "zone_id", 32, ACCOUNT_OBJECT_ID),
    zone_name: requireString(surface, "zone_name", 253, HOSTNAME),
  });
}

function requireAuthorityRole(row: JsonObject, index: number): ServiceAuthorityRole {
  const role = requireString(row, "authority_role", 64);
  const expected = SERVICE_AUTHORITY_ROLES[index];
  if (expected === undefined || role !== expected || !isServiceAuthorityRole(role)) {
    throw new BrokerError("SERVICE_AUTHORITY_ORDER_INVALID", 400, false);
  }
  return role;
}

function validatePhaseMembership(
  role: ServiceAuthorityRole,
  versions: readonly ExpectedDeploymentVersion[],
  phase: DeploymentObservationPhase,
): void {
  if (phase === "A0_PRE" && role === "release_authority_ingress") {
    const percentages = versions
      .map((member) => member.percentage)
      .sort((left, right) => left - right);
    assert(
      versions.length === 2 && JSON.stringify(percentages) === "[0,100]",
      "CLOUDFLARE_DEPLOYMENT_PRE_INGRESS_INVALID",
    );
    assert(
      versions.some(
        (member) => member.artifact_kind === "BOOTSTRAP_DENY" && member.percentage === 100,
      ) &&
        versions.some(
          (member) => member.artifact_kind === "FINAL_AUTHORITY" && member.percentage === 0,
        ),
      "CLOUDFLARE_DEPLOYMENT_PRE_INGRESS_ARTIFACT_INVALID",
    );
    return;
  }
  assert(
    versions.length === 1 &&
      versions[0]?.percentage === 100 &&
      versions[0].artifact_kind === "FINAL_AUTHORITY",
    phase === "A0_PRE"
      ? "CLOUDFLARE_DEPLOYMENT_PRE_PRIVATE_INVALID"
      : "CLOUDFLARE_DEPLOYMENT_POST_INVALID",
  );
}

function assertUnique(values: readonly string[], code: string): void {
  assert(new Set(values).size === values.length, code);
}

function assertAsciiSorted(values: readonly string[], code: string): void {
  const sorted = [...values].sort();
  assert(JSON.stringify(values) === JSON.stringify(sorted), code);
}
