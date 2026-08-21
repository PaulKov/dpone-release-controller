import {
  ACTIVATED_RECORD_SCHEMA,
  POSITIVE_ID,
  PROVISIONED_RECORD_SCHEMA,
  SHA1,
  WORKER_VERSION,
} from "./activation-contract";
import { requireDigest, requireExactInteger, requireLiteral } from "./activation-fields";
import { verifyActionsPolicyDigest } from "./activation-governance";
import { assertAdminPrincipalDigests } from "./admin-principal";
import { controllerActionFromProvisioned } from "./activation-controller-action";
import { parseProvisionedEnvelope } from "./activation-records";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import {
  controllerActionBundleSha256,
  parseControllerActionBundle,
} from "./controller-action-bundle";
import type { ControllerActionBundleObservation } from "./controller-action-bundle-client";
import { TRUST } from "./config";
import { assert } from "./errors";
import {
  githubRulesetProjectionDigest,
  validateGitHubRulesetProjection,
} from "./github-ruleset-projection";
import type {
  FinalizeRequest,
  MirroredProviderEvidence,
  ProvisionRequest,
} from "./activation-schema-types";
import type { TargetRulesetObservation } from "./target-ruleset-client";
import type { ActivationAdminSemanticTrust, JsonObject } from "./types";
import { requireObject, requireString } from "./validation";

export async function buildProvisionedRecord(
  request: ProvisionRequest,
  committedAt: string,
  actionObservation: ControllerActionBundleObservation,
  oidcEvidence: {
    readonly controller: MirroredProviderEvidence;
    readonly target: MirroredProviderEvidence;
  },
  targetRulesetObservation: TargetRulesetObservation,
  targetRulesetEvidence: MirroredProviderEvidence,
  serviceAuthorityObservation: JsonObject,
): Promise<JsonObject> {
  requireLiteral(serviceAuthorityObservation, "phase", "A0_PRE");
  assert(
    canonicalJson(actionObservation.bundle) ===
      canonicalJson(
        parseControllerActionBundle(
          request.controller.controller_action_bundle,
          requireString(request.controller, "controller_action_commit_sha", 40, SHA1),
        ),
      ) &&
      actionObservation.bundleSha256 ===
        requireDigest(request.controller, "controller_action_bundle_sha256"),
    "ACTIVATION_CONTROLLER_ACTION_PROVIDER_MISMATCH",
    503,
  );
  const ingressWorkerVersion = requireString(
    request.broker,
    "worker_version_id",
    128,
    WORKER_VERSION,
  );
  const controllerOidcPointer = await providerEvidencePointer(oidcEvidence.controller, {
    evidenceKind: "github_oidc_subject_customization",
    ingressWorkerVersion,
    repository: TRUST.controllerRepository,
    repositoryId: TRUST.controllerRepositoryId,
  });
  const targetOidcPointer = await providerEvidencePointer(oidcEvidence.target, {
    evidenceKind: "github_oidc_subject_customization",
    ingressWorkerVersion,
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
  });
  const targetRulesetPointer = await providerEvidencePointer(targetRulesetEvidence, {
    evidenceKind: "github_branch_ruleset",
    ingressWorkerVersion,
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
  });
  const evidence: JsonObject = {
    ...request.evidence,
    controller: {
      ...request.controller,
      controller_action_bundle_provider_observation: actionObservation.observation,
      controller_action_bundle_provider_observation_sha256: actionObservation.observationSha256,
    },
    oidc: {
      ...request.oidc,
      provider_evidence: {
        controller: controllerOidcPointer,
        target: targetOidcPointer,
      },
    },
    target_governance: {
      ...requireObject(request.evidence.target_governance, "ACTIVATION_TARGET_GOVERNANCE_REQUIRED"),
      branch_ruleset_provider_evidence: targetRulesetPointer,
      branch_ruleset_provider_observation: targetRulesetObservation.summary,
      branch_ruleset_provider_observation_sha256: targetRulesetObservation.summarySha256,
    },
    service_authorities: {
      a0_pre_observation: serviceAuthorityObservation,
      expectation: request.serviceAuthorities.expectation ?? null,
      expectation_sha256: request.serviceAuthorities.expectation_sha256 ?? null,
    },
  };
  assert(
    targetRulesetEvidence.canonicalSha256 === targetRulesetObservation.evidenceCanonicalSha256 &&
      canonicalJson(targetRulesetEvidence.evidence) ===
        canonicalJson(targetRulesetObservation.evidence),
    "ACTIVATION_TARGET_RULESET_WORM_DIGEST_MISMATCH",
    503,
  );
  const withoutId: JsonObject = {
    committed_at: committedAt,
    evidence,
    fencing_token: 1,
    observed_at: committedAt,
    previous: "GENESIS",
    request_id: request.requestId,
    schema: PROVISIONED_RECORD_SCHEMA,
    schema_version: 1,
    sequence: 0,
  };
  return {
    ...withoutId,
    record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
  };
}

interface ProviderEvidencePointerExpectation {
  readonly evidenceKind: "github_branch_ruleset" | "github_oidc_subject_customization";
  readonly ingressWorkerVersion: string;
  readonly repository: string;
  readonly repositoryId: number;
}

async function providerEvidencePointer(
  input: MirroredProviderEvidence,
  expected: ProviderEvidencePointerExpectation,
): Promise<JsonObject> {
  requireLiteral(input.evidence, "schema", "dpone.release-broker-provider-evidence-entry.v1");
  requireExactInteger(input.evidence, "schema_version", 1);
  requireLiteral(input.evidence, "evidence_kind", expected.evidenceKind);
  requireLiteral(input.evidence, "repository", expected.repository);
  requireExactInteger(input.evidence, "repository_id", expected.repositoryId);
  const canonicalSha256 = `sha256:${await sha256Hex(canonicalBytes(input.evidence))}`;
  assert(
    input.canonicalSha256 === canonicalSha256,
    "ACTIVATION_PROVIDER_EVIDENCE_CANONICAL_DIGEST_MISMATCH",
    503,
  );
  const evidenceKind = expected.evidenceKind;
  const observationSha256 = requireDigest(input.evidence, "observation_sha256");
  const observedAt = requireString(
    input.evidence,
    "observed_at",
    32,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u,
  );
  const projectionSha256 = requireDigest(input.evidence, "projection_sha256");
  const rawResponseSha256 = requireDigest(input.evidence, "raw_response_sha256");
  const expectedWormKey = [
    "receipts",
    "v1",
    "activation-evidence",
    expected.ingressWorkerVersion,
    evidenceKind,
    `${canonicalSha256.slice("sha256:".length)}.json`,
  ].join("/");
  assert(
    input.worm.digest === canonicalSha256 && input.worm.key === expectedWormKey,
    "ACTIVATION_PROVIDER_EVIDENCE_WORM_POINTER_MISMATCH",
    503,
  );
  return {
    canonical_sha256: canonicalSha256,
    evidence_kind: evidenceKind,
    observation_sha256: observationSha256,
    observed_at: observedAt,
    observer_service_identity: requireString(input.evidence, "observer_service_identity", 512),
    observer_worker_version_id: requireString(input.evidence, "observer_worker_version_id", 128),
    projection_sha256: projectionSha256,
    raw_response_sha256: rawResponseSha256,
    repository: expected.repository,
    repository_id: expected.repositoryId,
    worm: {
      digest: input.worm.digest,
      key: input.worm.key,
      retention_until: input.worm.retentionUntil,
      version_id: input.worm.versionId,
    },
  };
}

export async function verifyProvisionEvidenceDigests(request: ProvisionRequest): Promise<void> {
  const controllerGovernance = requireObject(
    request.evidence.controller_governance,
    "ACTIVATION_CONTROLLER_GOVERNANCE_REQUIRED",
  );
  const targetGovernance = requireObject(
    request.evidence.target_governance,
    "ACTIVATION_TARGET_GOVERNANCE_REQUIRED",
  );
  await verifyActionsPolicyDigest(controllerGovernance);
  await verifyActionsPolicyDigest(targetGovernance);
  const branchRulesetId = requireString(targetGovernance, "branch_ruleset_id", 32, POSITIVE_ID);
  const branchProjection = validateGitHubRulesetProjection(
    targetGovernance.branch_ruleset_projection,
    {
      repository: TRUST.targetRepository,
      repositoryId: TRUST.targetRepositoryId,
      rulesetId: Number(branchRulesetId),
    },
  );
  assert(
    (await githubRulesetProjectionDigest(branchProjection)) ===
      requireDigest(targetGovernance, "branch_ruleset_projection_sha256"),
    "ACTIVATION_TARGET_RULESET_PROJECTION_DIGEST_MISMATCH",
  );
  const actionCommitSha = requireString(
    request.controller,
    "controller_action_commit_sha",
    40,
    SHA1,
  );
  const actionBundle = parseControllerActionBundle(
    request.controller.controller_action_bundle,
    actionCommitSha,
  );
  assert(
    (await controllerActionBundleSha256(actionBundle)) ===
      requireDigest(request.controller, "controller_action_bundle_sha256"),
    "ACTIVATION_CONTROLLER_ACTION_BUNDLE_DIGEST_MISMATCH",
  );
}

/** Verify the three Access-principal commitments against runtime secrets. */
export async function verifyAdminAccessPrincipalDigests(
  request: ProvisionRequest,
  config: ActivationAdminSemanticTrust,
): Promise<void> {
  await assertAdminPrincipalDigests(
    requireObject(request.evidence.admin_access, "ACTIVATION_ADMIN_ACCESS_REQUIRED"),
    config,
  );
}

export async function buildActivatedRecord(
  request: FinalizeRequest,
  committedAt: string,
  previous: string,
  provisionedEnvelope: JsonObject,
  serviceAuthorityObservation: JsonObject,
): Promise<JsonObject> {
  requireLiteral(serviceAuthorityObservation, "phase", "A1_PRECOMMIT");
  const action = controllerActionFromProvisioned(
    parseProvisionedEnvelope(provisionedEnvelope).controller,
  );
  const withoutId: JsonObject = {
    approvals: request.approvals,
    committed_at: committedAt,
    controller_action_bundle_sha256: action.controllerActionBundleSha256,
    controller_action_commit_sha: action.controllerActionCommitSha,
    controller_action_metadata_blob_sha: action.controllerActionMetadataBlobSha,
    fencing_token: 2,
    observed_at: committedAt,
    previous,
    promotion: request.promotion,
    provisioned: request.provisioned,
    request_id: request.requestId,
    schema: ACTIVATED_RECORD_SCHEMA,
    schema_version: 1,
    sequence: 1,
    service_authorities: {
      a1_precommit_observation: serviceAuthorityObservation,
      expectation_sha256:
        requireObject(
          requireObject(provisionedEnvelope.evidence, "ACTIVATION_EVIDENCE_INVALID")
            .service_authorities,
          "SERVICE_AUTHORITY_EXPECTATION_REQUIRED",
        ).expectation_sha256 ?? null,
    },
    target: request.target,
  };
  return {
    ...withoutId,
    record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
  };
}
