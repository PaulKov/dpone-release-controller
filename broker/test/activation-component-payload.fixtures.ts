import {
  AUDIENCES,
  PROJECTS,
  PROVISION_REQUEST_SCHEMA,
  REQUIRED_OIDC_CLAIMS,
} from "../src/activation-contract";
import { activationJsonBudget, type ActivationJsonBudget } from "../src/activation-component-codec";
import type { ActivationComponentPayloadInput } from "../src/activation-component-contract";
import { buildActivationComponentPayloads } from "../src/activation-component-payload-builder";
import {
  parseProvisionRequest,
  verifyAdminAccessPrincipalDigests,
  verifyProvisionEvidenceDigests,
  type ProvisionRequest,
} from "../src/activation-schema";
import { adminPrincipalDigest } from "../src/admin-principal";
import { canonicalBytes } from "../src/canonical";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  parseServiceAuthorityExpectation,
  type ServiceAuthorityExpectation,
} from "../src/service-authority-activation";
import type { JsonObject, TrustedRuntimeConfig } from "../src/types";
import {
  VALID_A0_ACCOUNT_ID,
  VALID_A0_SOURCE_COMMIT,
  VALID_A0_WORKER_VERSION,
  validServiceAuthorityFixture,
} from "./activation-component-authority.fixtures";
import { validGovernanceFixture } from "./activation-component-governance.fixtures";
import { githubApps, tagged } from "./activation-schema-topology.fixtures";

const OWNER_ID = "74862786";
const CONTROLLER_REPOSITORY_ID = 1_305_993_853;
const TARGET_REPOSITORY_ID = 1_255_975_556;
const PRODUCTION_COMMIT_SHA = "c".repeat(40);

export const VALID_A0_CONFIG: TrustedRuntimeConfig = Object.freeze({
  adminAccessApplicationId: "11111111-1111-4111-8111-111111111111",
  adminAccessAudience: "access-audience-immutable-000001",
  adminAccessGroup: "release-activation-admins",
  adminAccessIdentity: "release-admin@example.invalid",
  adminAccessIssuer: "https://review-template.cloudflareaccess.com",
  adminAccessPolicyId: "22222222-2222-4222-8222-222222222222",
  adminAccessSubjectId: "33333333-3333-4333-8333-333333333333",
  adminHostname: "release-broker.example.invalid",
  adminMtlsCertSha256: "e".repeat(64),
  cloudflareAccountId: VALID_A0_ACCOUNT_ID,
  cloudflareObserverRpcAuthKey: "A".repeat(43),
  workerServiceIdentity: `cloudflare-worker:${VALID_A0_ACCOUNT_ID}/dpone-release-authority-broker@${VALID_A0_WORKER_VERSION}`,
  workerVersionId: VALID_A0_WORKER_VERSION,
  wormRpcAuthKey: "B".repeat(43),
});

export interface ProductionValidA0Fixture {
  readonly authorityExpectation: ServiceAuthorityExpectation;
  readonly body: JsonObject;
  readonly canonicalBodyBytes: Uint8Array;
  readonly componentPayloads: readonly ActivationComponentPayloadInput[];
  readonly config: TrustedRuntimeConfig;
  readonly expectationDocument: JsonObject;
  readonly expectationSha256: string;
  readonly measurement: ActivationJsonBudget;
  readonly request: ProvisionRequest;
}

/**
 * Build and production-validate a complete coherent A0 input.
 *
 * Every call returns fresh mutable JSON so negative tests can safely introduce
 * drift without contaminating another test. Provider evidence digests are
 * deterministic placeholders; every content-derived digest is recomputed by
 * the same production helper that verifies it.
 */
export async function productionValidA0Fixture(): Promise<ProductionValidA0Fixture> {
  const authority = await validServiceAuthorityFixture();
  const services = requireObject(authority.broker.private_services, "private services missing");
  const apps = githubApps(services);
  const governance = await validGovernanceFixture(apps);
  const body: JsonObject = {
    evidence: {
      admin_access: await adminAccessEvidence(VALID_A0_CONFIG),
      b2: b2Evidence(),
      broker: authority.broker,
      controller: governance.controller,
      controller_governance: governance.controllerGovernance,
      github_apps: apps,
      oidc: oidcEvidence(),
      service_authorities: {
        expectation: authority.expectationDocument,
        expectation_sha256: authority.expectationSha256,
      },
      target_governance: governance.targetGovernance,
      trusted_publishers: trustedPublishers(),
    },
    observed_at: "2026-08-19T12:00:00.000Z",
    request_id: "activation-request-a0-valid-0001",
    schema: PROVISION_REQUEST_SCHEMA,
    schema_version: 1,
  };
  const request = parseProvisionRequest(body, VALID_A0_CONFIG);
  await verifyProvisionEvidenceDigests(request);
  await verifyAdminAccessPrincipalDigests(request, VALID_A0_CONFIG);
  const authorityExpectation = await parseServiceAuthorityExpectation(
    authority.expectationDocument,
    authority.expectationSha256,
    VALID_A0_ACCOUNT_ID,
    VALID_A0_SOURCE_COMMIT,
  );
  assertServiceAuthorityExpectationMatchesBroker(authorityExpectation, request.broker);
  const componentPayloads = buildActivationComponentPayloads(request, authorityExpectation);
  return {
    authorityExpectation,
    body,
    canonicalBodyBytes: canonicalBytes(body),
    componentPayloads,
    config: VALID_A0_CONFIG,
    expectationDocument: authority.expectationDocument,
    expectationSha256: authority.expectationSha256,
    measurement: measureCanonicalActivationObject(body),
    request,
  };
}

/** Measure the exact canonical bytes and the iterative candidate JSON budget. */
export function measureCanonicalActivationObject(value: JsonObject): ActivationJsonBudget {
  const bytes = canonicalBytes(value);
  const measurement = activationJsonBudget(value);
  if (measurement.bytes !== bytes.byteLength) {
    throw new Error("activation fixture canonical measurement mismatch");
  }
  return measurement;
}

async function adminAccessEvidence(config: TrustedRuntimeConfig): Promise<JsonObject> {
  return {
    access_application_evidence_sha256: tagged(500),
    access_application_id: config.adminAccessApplicationId,
    access_audience: config.adminAccessAudience,
    access_group_sha256: await adminPrincipalDigest("access_group", config.adminAccessGroup),
    access_identity_sha256: await adminPrincipalDigest(
      "access_identity",
      config.adminAccessIdentity,
    ),
    access_issuer: config.adminAccessIssuer,
    access_policy_evidence_sha256: tagged(501),
    access_policy_id: config.adminAccessPolicyId,
    access_session_duration_seconds: 900,
    access_subject_id_sha256: await adminPrincipalDigest(
      "access_subject_id",
      config.adminAccessSubjectId,
    ),
    certificate_evidence_sha256: tagged(502),
    certificate_fingerprint_sha256: config.adminMtlsCertSha256,
    certificate_not_after: "2027-08-19T12:00:00.000Z",
    certificate_not_before: "2026-08-18T12:00:00.000Z",
    certificate_validity_evidence_sha256: tagged(503),
    finalize_path: "/v1/admin/activation/finalize",
    hostname: config.adminHostname,
    hostname_path_rule_evidence_sha256: tagged(504),
    jwks_evidence_sha256: tagged(505),
    mtls_ca_evidence_sha256: tagged(506),
    mtls_ca_id: "mtls-ca-0001",
    mtls_provider_observation_sha256: tagged(507),
    provision_path: "/v1/admin/activation/provision",
  };
}

function b2Evidence(): JsonObject {
  return {
    bucket_configuration_evidence_sha256: tagged(520),
    bucket_id: "f".repeat(24),
    bucket_name: "dpone-release-receipts",
    bucket_type: "allPrivate",
    encryption: "SSE-B2",
    object_lock_enabled: true,
    object_lock_mode: "COMPLIANCE",
    observer_capabilities: [
      "listBuckets",
      "listFiles",
      "readBucketEncryption",
      "readBucketReplications",
      "readBucketRetentions",
      "readFileRetentions",
      "readFiles",
    ],
    observer_key_id_sha256: tagged(521),
    observer_restriction_evidence_sha256: tagged(522),
    prefix: "receipts/v1/",
    retention_days: 2557,
    writer_capabilities: ["writeFiles"],
    writer_key_id_sha256: tagged(523),
    writer_restriction_evidence_sha256: tagged(524),
  };
}

function oidcEvidence(): JsonObject {
  const releaseAttest = controllerSubject("release-attest");
  const controllerSubjects = {
    github_release: controllerSubject("github-release"),
    pypi: controllerSubject("pypi"),
    release_attest: releaseAttest,
  };
  const runtimeSubject = `repo:PaulKov@${OWNER_ID}/dpone@${TARGET_REPOSITORY_ID}:environment:ghcr`;
  const rehearsals: JsonObject = {};
  for (const [index, [role, audience]] of Object.entries(AUDIENCES).entries()) {
    const isRuntime = role === "runtime_closure_read";
    const environment =
      role === "github_release"
        ? "github-release"
        : role === "pypi"
          ? "pypi"
          : isRuntime
            ? "ghcr"
            : "release-attest";
    const subject =
      role === "github_release"
        ? controllerSubjects.github_release
        : role === "pypi"
          ? controllerSubjects.pypi
          : isRuntime
            ? runtimeSubject
            : releaseAttest;
    rehearsals[role] = {
      audience,
      check_run_id: String(6_000 + index),
      environment,
      evidence_sha256: tagged(540 + index),
      jti_sha256: tagged(560 + index),
      repository_id: isRuntime ? TARGET_REPOSITORY_ID : CONTROLLER_REPOSITORY_ID,
      repository_owner_id: OWNER_ID,
      run_attempt: 1,
      run_id: String(7_000 + index),
      subject,
      workflow_sha: isRuntime ? "9".repeat(40) : PRODUCTION_COMMIT_SHA,
    };
  }
  return {
    claim_template_evidence_sha256: tagged(580),
    claim_template_receipt_id: tagged(581),
    controller_actor_ids: [OWNER_ID],
    controller_subjects: controllerSubjects,
    issuer: "https://token.actions.githubusercontent.com",
    rehearsals,
    repository_owner_id: OWNER_ID,
    required_claims: [...REQUIRED_OIDC_CLAIMS],
    runtime_actor_ids: [OWNER_ID],
    runtime_subject: runtimeSubject,
    subject_format:
      "repo:{owner}@{owner_id}/{repository}@{repository_id}:environment:{environment}",
  };
}

function controllerSubject(environment: string): string {
  return (
    `repo:PaulKov@${OWNER_ID}/dpone-release-controller@${CONTROLLER_REPOSITORY_ID}:` +
    `environment:${environment}`
  );
}

function trustedPublishers(): JsonObject[] {
  return PROJECTS.map((project, index) => ({
    environment: "pypi",
    evidence_receipt_id: tagged(600 + index),
    evidence_sha256: tagged(610 + index),
    project,
    repository: "PaulKov/dpone-release-controller",
    workflow_path: ".github/workflows/release-controller.yml",
  }));
}

function requireObject(value: unknown, message: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as JsonObject;
}
