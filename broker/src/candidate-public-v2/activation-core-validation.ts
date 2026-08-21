import { canonicalPublicV2Bytes } from "./canonical";
import { candidateAssert } from "./error";
import type { CandidateJsonObject } from "./types";
import {
  TAG_REF,
  digestField,
  exactObject,
  gitShaField,
  literalField,
  objectField,
  stringField,
} from "./validation";

export const PROVISIONED_PUBLIC_CORE_SCHEMA = "dpone.release-broker-provisioned-public-core.v2";
export const ACTIVATED_PUBLIC_CORE_SCHEMA = "dpone.release-broker-activated-public-core.v2";

export const A0_BASE_KEYS = [
  "broker_source",
  "controller_source",
  "previous",
  "schema",
  "schema_version",
  "sequence",
] as const;
export const A0_KEYS = [...A0_BASE_KEYS, "private_sidecar_commitment", "record_id"] as const;
export const A1_BASE_KEYS = [
  "baseline_source",
  "previous",
  "provisioned_record_sha256",
  "schema",
  "schema_version",
  "sequence",
] as const;
export const A1_KEYS = [...A1_BASE_KEYS, "private_sidecar_commitment", "record_id"] as const;

export function validateProvisionedBase(value: unknown): CandidateJsonObject {
  const base = exactObject(value, A0_BASE_KEYS, "PUBLIC_V2_A0_BASE_INVALID");
  const broker = exactObject(
    objectField(base, "broker_source", "PUBLIC_V2_A0_BROKER_SOURCE_INVALID"),
    ["commit_sha", "source_sha256", "tree_sha"],
    "PUBLIC_V2_A0_BROKER_SOURCE_INVALID",
  );
  gitShaField(broker, "commit_sha", "PUBLIC_V2_A0_BROKER_SOURCE_INVALID");
  digestField(broker, "source_sha256", "PUBLIC_V2_A0_BROKER_SOURCE_INVALID");
  gitShaField(broker, "tree_sha", "PUBLIC_V2_A0_BROKER_SOURCE_INVALID");
  validateControllerSource(
    objectField(base, "controller_source", "PUBLIC_V2_A0_CONTROLLER_INVALID"),
  );
  literalField(base, "previous", "GENESIS", "PUBLIC_V2_A0_BASE_INVALID");
  literalField(base, "schema", PROVISIONED_PUBLIC_CORE_SCHEMA, "PUBLIC_V2_A0_BASE_INVALID");
  literalField(base, "schema_version", 2, "PUBLIC_V2_A0_BASE_INVALID");
  literalField(base, "sequence", 0, "PUBLIC_V2_A0_BASE_INVALID");
  canonicalPublicV2Bytes(base);
  return base;
}

export function validateActivatedBase(value: unknown): CandidateJsonObject {
  const base = exactObject(value, A1_BASE_KEYS, "PUBLIC_V2_A1_BASE_INVALID");
  const baseline = exactObject(
    objectField(base, "baseline_source", "PUBLIC_V2_A1_BASELINE_INVALID"),
    [
      "baseline_commit_sha",
      "baseline_tree_sha",
      "policy_blob_sha",
      "policy_sha256",
      "runtime_workflow_blob_sha",
      "runtime_workflow_sha256",
    ],
    "PUBLIC_V2_A1_BASELINE_INVALID",
  );
  for (const key of [
    "baseline_commit_sha",
    "baseline_tree_sha",
    "policy_blob_sha",
    "runtime_workflow_blob_sha",
  ]) {
    gitShaField(baseline, key, "PUBLIC_V2_A1_BASELINE_INVALID");
  }
  digestField(baseline, "policy_sha256", "PUBLIC_V2_A1_BASELINE_INVALID");
  digestField(baseline, "runtime_workflow_sha256", "PUBLIC_V2_A1_BASELINE_INVALID");
  digestField(base, "previous", "PUBLIC_V2_A1_BASE_INVALID");
  digestField(base, "provisioned_record_sha256", "PUBLIC_V2_A1_BASE_INVALID");
  literalField(base, "schema", ACTIVATED_PUBLIC_CORE_SCHEMA, "PUBLIC_V2_A1_BASE_INVALID");
  literalField(base, "schema_version", 2, "PUBLIC_V2_A1_BASE_INVALID");
  literalField(base, "sequence", 1, "PUBLIC_V2_A1_BASE_INVALID");
  canonicalPublicV2Bytes(base);
  return base;
}

export function withoutRecordId(record: CandidateJsonObject): CandidateJsonObject {
  return Object.fromEntries(Object.entries(record).filter(([key]) => key !== "record_id"));
}

function validateControllerSource(value: CandidateJsonObject): void {
  const source = exactObject(
    value,
    [
      "action_bundle",
      "commit_sha",
      "default_branch_workflow_blob_sha",
      "tag_object_sha",
      "tag_ref",
      "tree_sha",
      "workflow_blob_sha",
      "workflow_sha256",
    ],
    "PUBLIC_V2_A0_CONTROLLER_INVALID",
  );
  const action = exactObject(
    objectField(source, "action_bundle", "PUBLIC_V2_A0_ACTION_INVALID"),
    ["bundle_sha256", "commit_sha", "metadata_blob_sha"],
    "PUBLIC_V2_A0_ACTION_INVALID",
  );
  digestField(action, "bundle_sha256", "PUBLIC_V2_A0_ACTION_INVALID");
  const actionCommit = gitShaField(action, "commit_sha", "PUBLIC_V2_A0_ACTION_INVALID");
  gitShaField(action, "metadata_blob_sha", "PUBLIC_V2_A0_ACTION_INVALID");
  const workflowCommit = gitShaField(source, "commit_sha", "PUBLIC_V2_A0_CONTROLLER_INVALID");
  candidateAssert(actionCommit !== workflowCommit, "PUBLIC_V2_A0_ACTION_WORKFLOW_COLLISION");
  gitShaField(source, "default_branch_workflow_blob_sha", "PUBLIC_V2_A0_CONTROLLER_INVALID");
  const tagObject = gitShaField(source, "tag_object_sha", "PUBLIC_V2_A0_CONTROLLER_INVALID");
  candidateAssert(tagObject !== workflowCommit, "PUBLIC_V2_A0_TAG_NOT_ANNOTATED");
  stringField(source, "tag_ref", "PUBLIC_V2_A0_CONTROLLER_INVALID", TAG_REF);
  gitShaField(source, "tree_sha", "PUBLIC_V2_A0_CONTROLLER_INVALID");
  gitShaField(source, "workflow_blob_sha", "PUBLIC_V2_A0_CONTROLLER_INVALID");
  digestField(source, "workflow_sha256", "PUBLIC_V2_A0_CONTROLLER_INVALID");
}
