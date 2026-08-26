import { FINALIZE_REQUEST_SCHEMA, PROVISION_REQUEST_SCHEMA } from "./activation-contract";
import type { JsonObject } from "./types";
import { exactObject } from "./validation";

export function exactProvisionedEnvelope(value: JsonObject): JsonObject {
  return exactObject(value, [
    "committed_at",
    "evidence",
    "fencing_token",
    "observed_at",
    "previous",
    "record_id",
    "request_id",
    "schema",
    "schema_version",
    "sequence",
  ]);
}

export function exactActivatedEnvelope(value: JsonObject): JsonObject {
  return exactObject(value, [
    "approvals",
    "committed_at",
    "controller_action_bundle_sha256",
    "controller_action_commit_sha",
    "controller_action_metadata_blob_sha",
    "fencing_token",
    "observed_at",
    "previous",
    "promotion",
    "provisioned",
    "record_id",
    "request_id",
    "schema",
    "schema_version",
    "sequence",
    "service_authorities",
    "target",
  ]);
}

export function reconstructedProvisionRequest(envelope: JsonObject): JsonObject {
  const evidence = exactObject(envelope.evidence, [
    "admin_access",
    "b2",
    "broker",
    "controller",
    "controller_governance",
    "github_apps",
    "oidc",
    "service_authorities",
    "target_governance",
    "trusted_publishers",
  ]);
  const controller = without(
    exactObject(evidence.controller, [
      "controller_action_bundle",
      "controller_action_bundle_provider_observation",
      "controller_action_bundle_provider_observation_sha256",
      "controller_action_bundle_sha256",
      "controller_action_commit_sha",
      "controller_action_metadata_blob_sha",
      "default_branch_ref",
      "default_branch_workflow_blob_sha",
      "default_branch_workflow_observation_sha256",
      "peeled_commit_sha",
      "production_commit_sha",
      "production_tree_sha",
      "ref",
      "ref_type",
      "repository",
      "repository_id",
      "reusable_actions",
      "reusable_actions_commit_sha",
      "reusable_actions_tree_sha",
      "tag_no_bypass_evidence_sha256",
      "tag_object_sha",
      "tag_protection_evidence_sha256",
      "workflow_blob_sha",
      "workflow_id",
      "workflow_identity_evidence_sha256",
      "workflow_path",
      "workflow_sha256",
    ]),
    [
      "controller_action_bundle_provider_observation",
      "controller_action_bundle_provider_observation_sha256",
    ],
  );
  const oidc = without(
    exactObject(evidence.oidc, [
      "claim_template_evidence_sha256",
      "claim_template_receipt_id",
      "controller_actor_ids",
      "controller_subjects",
      "issuer",
      "provider_evidence",
      "repository_owner_id",
      "required_claims",
      "rehearsals",
      "runtime_actor_ids",
      "runtime_subject",
      "subject_format",
    ]),
    ["provider_evidence"],
  );
  const target = without(
    exactObject(evidence.target_governance, [
      "actions_policy",
      "branch_ruleset_evidence_sha256",
      "branch_ruleset_id",
      "branch_ruleset_projection",
      "branch_ruleset_projection_sha256",
      "branch_ruleset_provider_evidence",
      "branch_ruleset_provider_observation",
      "branch_ruleset_provider_observation_sha256",
      "ghcr_environment_evidence_sha256",
      "immutable_releases_evidence_sha256",
      "repository",
      "repository_id",
      "tag_ruleset_evidence_sha256",
      "tag_ruleset_id",
    ]),
    [
      "branch_ruleset_provider_evidence",
      "branch_ruleset_provider_observation",
      "branch_ruleset_provider_observation_sha256",
    ],
  );
  const authorities = exactObject(evidence.service_authorities, [
    "a0_pre_observation",
    "expectation",
    "expectation_sha256",
  ]);
  return {
    evidence: {
      ...evidence,
      controller,
      oidc,
      service_authorities: {
        expectation: authorities.expectation ?? null,
        expectation_sha256: authorities.expectation_sha256 ?? null,
      },
      target_governance: target,
    },
    observed_at: envelope.observed_at ?? null,
    request_id: envelope.request_id ?? null,
    schema: PROVISION_REQUEST_SCHEMA,
    schema_version: 1,
  };
}

export function reconstructedFinalizeRequest(envelope: JsonObject): JsonObject {
  return {
    approvals: envelope.approvals ?? null,
    observed_at: envelope.observed_at ?? null,
    provisioned: envelope.provisioned ?? null,
    promotion: envelope.promotion ?? null,
    request_id: envelope.request_id ?? null,
    schema: FINALIZE_REQUEST_SCHEMA,
    schema_version: 1,
    target: envelope.target ?? null,
  };
}

function without(value: JsonObject, keys: readonly string[]): JsonObject {
  const result = { ...value };
  for (const key of keys) Reflect.deleteProperty(result, key);
  return result;
}
