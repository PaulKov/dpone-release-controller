import {
  ACTIVATED_RECORD_SCHEMA,
  PROVISIONED_RECORD_SCHEMA,
  type FinalizeRequest,
  type ProvisionRequest,
} from "../src/activation-schema";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { ActivationRecordView, JsonObject } from "../src/types";
import { requireObject } from "../src/validation";
import rulesetProjectionFixture from "./fixtures/github-ruleset-projection-v1-golden.json";
import {
  WORKER_VERSION,
  privateServices,
  tagged,
  uuid,
} from "./activation-schema-topology.fixtures";

export function provisionRequest(): ProvisionRequest {
  const services = privateServices();
  const controller: JsonObject = {
    controller_action_bundle: actionBundle(),
    controller_action_bundle_sha256: tagged(89),
    controller_action_commit_sha: "d".repeat(40),
    controller_action_metadata_blob_sha: "e".repeat(40),
    default_branch_ref: "refs/heads/master",
    default_branch_workflow_blob_sha: "1".repeat(40),
    default_branch_workflow_observation_sha256: tagged(91),
    peeled_commit_sha: "c".repeat(40),
    production_commit_sha: "c".repeat(40),
    ref: "refs/tags/v1.0.0",
    ref_type: "tag",
    tag_no_bypass_evidence_sha256: tagged(92),
    tag_object_sha: "2".repeat(40),
    tag_protection_evidence_sha256: tagged(93),
    workflow_blob_sha: "d".repeat(40),
    workflow_id: 987_654_321,
  };
  const broker: JsonObject = {
    cloudflare_account_id: "a".repeat(32),
    private_services: services,
    worker_version_id: WORKER_VERSION,
  };
  const oidc: JsonObject = {
    controller_actor_ids: ["74862786"],
    repository_owner_id: "74862786",
    runtime_actor_ids: ["74862786"],
  };
  const githubApps: JsonObject = {
    controller_run_reader: {
      app_id: "101",
      app_slug: "controller-reader",
      installation_id: "202",
    },
  };
  const targetGovernance: JsonObject = {
    branch_ruleset_evidence_sha256: tagged(94),
    branch_ruleset_id: "18806829",
    branch_ruleset_projection: rulesetProjectionFixture,
    branch_ruleset_projection_sha256:
      "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39",
  };
  const evidence: JsonObject = {
    broker,
    controller,
    github_apps: githubApps,
    oidc,
    service_authorities: {
      expectation: { schema: "dpone.release-broker-service-authority-expectation.v1" },
      expectation_sha256: tagged(99),
    },
    target_governance: targetGovernance,
  };
  const body: JsonObject = {
    evidence,
    observed_at: "2026-08-15T12:00:00.000Z",
    request_id: "activation-request-a0-0001",
    schema: "dpone.release-broker-provision-request.v1",
    schema_version: 1,
  };
  return {
    body,
    broker,
    controller,
    evidence,
    observedAt: "2026-08-15T12:00:00.000Z",
    oidc,
    requestId: "activation-request-a0-0001",
    serviceAuthorities: requireObject(
      evidence.service_authorities,
      "missing service authority fixture",
    ),
  };
}

function actionBundle(): JsonObject {
  const paths = [
    "actions/broker-call/action.yml",
    "actions/broker-call/dist/index.js",
    "actions/lease-sentinel/action.yml",
    "actions/lease-sentinel/dist/index.js",
    "actions/runtime-closure/action.yml",
    "actions/runtime-closure/dist/index.js",
  ];
  return {
    commit_sha: "d".repeat(40),
    members: paths.map((path, index) => ({
      git_blob_sha: (index + 1).toString(16).repeat(40),
      mode: "100644",
      path,
      sha256: tagged(index + 1),
      size_bytes: index + 1,
    })),
    repository: "PaulKov/dpone-release-controller",
    repository_id: 1_305_993_853,
    schema: "dpone.release-controller-action-bundle.v1",
    schema_version: 1,
  };
}

export function actionBundleObservation(controller: JsonObject) {
  const bundle = requireObject(
    controller.controller_action_bundle,
    "missing controller action bundle",
  );
  const observation: JsonObject = {
    controller_action_bundle: bundle,
    controller_action_bundle_sha256: tagged(89),
    provider_observation_sha256: tagged(88),
    schema: "dpone.release-controller-action-bundle-observation.v1",
    schema_version: 1,
  };
  return {
    bundle,
    bundleSha256: tagged(89),
    observation,
    observationSha256: tagged(88),
  };
}

export function targetRulesetObservation(
  evidence: Awaited<ReturnType<typeof mirroredProviderEvidence>>,
) {
  const projection = rulesetProjectionFixture as JsonObject;
  const summary: JsonObject = { schema: "dpone.target-ruleset-observation-summary.v1" };
  return {
    evidence: evidence.evidence,
    evidenceCanonicalSha256: evidence.canonicalSha256,
    projection,
    projectionSha256: "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39",
    summary,
    summarySha256: tagged(96),
  };
}

export async function mirroredProviderEvidence(
  evidenceKind: "github_branch_ruleset" | "github_oidc_subject_customization",
  repository: string,
  repositoryId: number,
  digestSeed: number,
) {
  const evidence: JsonObject = {
    evidence_kind: evidenceKind,
    observation_sha256: tagged(digestSeed + 10),
    observed_at: "2026-08-15T12:00:00Z",
    observer_service_identity:
      "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/provider-reader@" + uuid(501),
    observer_worker_version_id: uuid(501),
    projection_sha256: tagged(digestSeed + 20),
    raw_response_sha256: tagged(digestSeed + 30),
    repository,
    repository_id: repositoryId,
    schema: "dpone.release-broker-provider-evidence-entry.v1",
    schema_version: 1,
  };
  const digestValue = `sha256:${await sha256Hex(canonicalBytes(evidence))}`;
  return {
    canonicalSha256: digestValue,
    evidence,
    worm: {
      digest: digestValue,
      key: `receipts/v1/activation-evidence/${WORKER_VERSION}/${evidenceKind}/${digestValue.slice(7)}.json`,
      retentionUntil: "2033-08-16T12:00:00Z",
      versionId: `provider-evidence-version-${digestSeed}`,
    },
  };
}

export function finalizeRequest(provisioned: ActivationRecordView): FinalizeRequest {
  const pointer: JsonObject = {
    digest: provisioned.digest,
    record_id: provisioned.recordId,
    worker_version_id: WORKER_VERSION,
    worm_key: provisioned.worm.key,
    worm_version_id: provisioned.worm.versionId,
  };
  const target: JsonObject = {
    commit_sha: "e".repeat(40),
    policy_blob_sha: "f".repeat(40),
    policy_sha256: tagged(90),
    runtime_workflow_blob_sha: "a".repeat(40),
    runtime_workflow_sha256: tagged(91),
  };
  const body: JsonObject = {
    approvals: {},
    observed_at: "2026-08-15T12:00:01.000Z",
    promotion: {
      completed_at: "2026-08-15T12:00:01.000Z",
      deployment_id: uuid(700),
      promotion_report_record_id: tagged(101),
      promotion_report_record_sha256: tagged(102),
      promotion_report_worm: {
        digest: tagged(102),
        key: "receipts/v1/deployment-observations/promotion.json",
        retention_until: "2033-08-15T12:00:00.000Z",
        version_id: "promotion-report-version-0001",
      },
      provider_observation_sha256: tagged(103),
      started_at: "2026-08-15T12:00:00.500Z",
      worker_version_id: WORKER_VERSION,
    },
    provisioned: pointer,
    request_id: "activation-request-a1-0001",
    schema: "dpone.release-broker-finalize-request.v1",
    schema_version: 1,
    target,
  };
  return {
    approvals: {},
    body,
    observedAt: "2026-08-15T12:00:01.000Z",
    promotion: requireObject(body.promotion, "missing promotion fixture"),
    provisioned: pointer,
    requestId: "activation-request-a1-0001",
    target,
  };
}

export function serviceAuthorityObservation(phase: "A0_PRE" | "A1_PRECOMMIT"): JsonObject {
  return {
    expectation_sha256: tagged(99),
    phase,
    provider_observation_sha256: phase === "A0_PRE" ? tagged(104) : tagged(105),
    schema: "dpone.release-broker-service-authority-observation.v1",
    schema_version: 1,
  };
}

export async function recordView(
  envelope: JsonObject,
  sequence: 0 | 1,
  wormVersionId: string,
): Promise<ActivationRecordView> {
  const expectedSchema = sequence === 0 ? PROVISIONED_RECORD_SCHEMA : ACTIVATED_RECORD_SCHEMA;
  if (envelope.schema !== expectedSchema) {
    throw new Error("unexpected activation record schema");
  }
  const digestValue = `sha256:${await sha256Hex(canonicalBytes(envelope))}`;
  return {
    digest: digestValue,
    envelope,
    recordId: digest(envelope, "record_id"),
    sequence,
    worm: {
      digest: digestValue,
      key: `receipts/v1/activation/${String(sequence)}.json`,
      retentionUntil: "2033-08-15T12:00:00.000Z",
      versionId: wormVersionId,
    },
  };
}

export function digest(object: JsonObject, key: string): string {
  const value = object[key];
  if (typeof value !== "string") throw new Error(`missing ${key}`);
  return value;
}
