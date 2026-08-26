import { POSITIVE_ID, SAFE_NAME, SHA1 } from "./activation-contract";
import {
  activationJsonBudget,
  activationLiteral,
  activationString,
  activationTimestamp,
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
  componentError,
  decodeBoundedActivationObject,
  exactActivationObject,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  type PreparedActivationComponentManifest,
} from "./activation-component-contract";
import type { ValidatedActivationComponentSet } from "./activation-component-payload-contract";
import { activationComponentWormJson } from "./activation-component-manifest-worm";
import { controllerActionFromProvisioned } from "./activation-controller-action";
import { requireDigest, stringArray } from "./activation-fields";
import { canonicalBytes } from "./canonical";
import { TRUST } from "./config";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { ActivationWorm, JsonObject, JsonValue } from "./types";
import { requireInteger, requireObject, requireString } from "./validation";

export const ACTIVATION_COMPONENT_RESOLVED_PROJECTION_SCHEMA =
  "dpone.resolved-activation-component-semantics.v2";

const PROJECTION_INVALID = "ACTIVATION_COMPONENT_RESOLVER_PROJECTION_INVALID";
const ROOT_FIELDS = ["component_set", "runtime", "schema", "schema_version"] as const;
const SET_FIELDS = [
  "component_set_committed_at",
  "component_set_descriptor_id",
  "component_set_descriptor_sha256",
  "component_set_id",
  "manifest_id",
  "manifest_sha256",
  "manifest_worm",
  "worker_version_id",
] as const;
const RUNTIME_FIELDS = [
  "cloudflare_account_id",
  "controller_action_bundle_sha256",
  "controller_action_commit_sha",
  "controller_action_metadata_blob_sha",
  "controller_actor_ids",
  "controller_default_branch_workflow_blob_sha",
  "controller_ref",
  "controller_ref_type",
  "controller_run_reader_app",
  "controller_tag_object_sha",
  "controller_workflow_blob_sha",
  "controller_workflow_id",
  "controller_workflow_ref",
  "controller_workflow_sha",
  "private_services",
  "repository_owner_id",
  "runtime_actor_ids",
  "service_authority_expectation_sha256",
  "target_branch_ruleset_evidence_sha256",
  "target_branch_ruleset_id",
  "target_branch_ruleset_projection_sha256",
  "target_default_branch_ref",
] as const;

export interface PreparedActivationComponentResolverProjection {
  readonly canonicalBytes: Uint8Array;
  readonly document: JsonObject;
}

/** Build a compact runtime projection only from closed reconstructed semantics. */
export function buildActivationComponentResolverProjection(
  validated: ValidatedActivationComponentSet,
  manifest: PreparedActivationComponentManifest,
  manifestWorm: ActivationWorm,
): PreparedActivationComponentResolverProjection {
  const controller = validated.payloads.controller;
  const oidc = validated.payloads.oidc;
  const target = validated.payloads.target_governance;
  const action = controllerActionFromProvisioned(controller);
  const controllerRef = requireString(controller, "ref", 80);
  const controllerRunReader = requireObject(
    validated.githubApps.controller_run_reader,
    PROJECTION_INVALID,
  );
  const document: JsonObject = {
    component_set: {
      component_set_committed_at: manifest.committedAt,
      component_set_descriptor_id: manifest.descriptorId,
      component_set_descriptor_sha256: manifest.descriptorSha256,
      component_set_id: manifest.setId,
      manifest_id: manifest.manifestId,
      manifest_sha256: manifest.manifestSha256,
      manifest_worm: activationComponentWormJson(manifestWorm),
      worker_version_id: manifest.workerVersionId,
    },
    runtime: {
      cloudflare_account_id: validated.broker.cloudflare_account_id ?? null,
      controller_action_bundle_sha256: action.controllerActionBundleSha256,
      controller_action_commit_sha: action.controllerActionCommitSha,
      controller_action_metadata_blob_sha: action.controllerActionMetadataBlobSha,
      controller_actor_ids: [...stringArray(oidc, "controller_actor_ids")],
      controller_default_branch_workflow_blob_sha: requireString(
        controller,
        "default_branch_workflow_blob_sha",
        40,
        SHA1,
      ),
      controller_ref: controllerRef,
      controller_ref_type: "tag",
      controller_run_reader_app: {
        app_id: requireString(controllerRunReader, "app_id", 32, POSITIVE_ID),
        app_slug: requireString(controllerRunReader, "app_slug", 128, SAFE_NAME),
        installation_id: requireString(controllerRunReader, "installation_id", 32, POSITIVE_ID),
      },
      controller_tag_object_sha: requireString(controller, "tag_object_sha", 40, SHA1),
      controller_workflow_blob_sha: requireString(controller, "workflow_blob_sha", 40, SHA1),
      controller_workflow_id: requireInteger(controller, "workflow_id", 1),
      controller_workflow_ref: `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@${controllerRef}`,
      controller_workflow_sha: requireString(controller, "production_commit_sha", 40, SHA1),
      private_services: privateServiceProjection(validated),
      repository_owner_id: requireString(oidc, "repository_owner_id", 32, POSITIVE_ID),
      runtime_actor_ids: [...stringArray(oidc, "runtime_actor_ids")],
      service_authority_expectation_sha256: validated.serviceAuthorityExpectation.expectationSha256,
      target_branch_ruleset_evidence_sha256: requireDigest(
        target,
        "branch_ruleset_evidence_sha256",
      ),
      target_branch_ruleset_id: requireString(target, "branch_ruleset_id", 32, POSITIVE_ID),
      target_branch_ruleset_projection_sha256: requireDigest(
        target,
        "branch_ruleset_projection_sha256",
      ),
      target_default_branch_ref: TRUST.targetDefaultBranchRef,
    },
    schema: ACTIVATION_COMPONENT_RESOLVED_PROJECTION_SCHEMA,
    schema_version: 2,
  };
  activationJsonBudget(
    document,
    {
      bytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
    },
    PROJECTION_INVALID,
  );
  return parseActivationComponentResolverProjection(canonicalBytes(document));
}

/** Structural parser only. It does not mint the private resolver brand. */
export function parseActivationComponentResolverProjection(
  input: Uint8Array,
): PreparedActivationComponentResolverProjection {
  const decoded = decodeBoundedActivationObject(
    input,
    {
      bytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_MANIFEST_MAX_NODES,
    },
    PROJECTION_INVALID,
  );
  const document = exactActivationObject(decoded.value, ROOT_FIELDS, PROJECTION_INVALID);
  activationLiteral(
    document,
    "schema",
    ACTIVATION_COMPONENT_RESOLVED_PROJECTION_SCHEMA,
    PROJECTION_INVALID,
  );
  activationLiteral(document, "schema_version", 2, PROJECTION_INVALID);
  parseSet(document.component_set);
  parseRuntime(document.runtime);
  return Object.freeze({
    canonicalBytes: Uint8Array.from(decoded.bytes),
    document: freezeJson(document),
  });
}

function privateServiceProjection(validated: ValidatedActivationComponentSet): JsonObject {
  const result: JsonObject = {};
  for (const row of validated.serviceAuthorityExpectation.authorities) {
    if (row.authority_role === "release_authority_ingress") continue;
    result[row.authority_role] = {
      service_identity: row.service_identity,
      service_name: row.service,
      version_id: row.worker_version_id,
    };
  }
  return result;
}

function parseSet(value: JsonValue | undefined): void {
  const set = exactActivationObject(value, SET_FIELDS, PROJECTION_INVALID);
  for (const key of [
    "component_set_descriptor_id",
    "component_set_descriptor_sha256",
    "component_set_id",
    "manifest_id",
    "manifest_sha256",
  ]) {
    activationString(set, key, ACTIVATION_COMPONENT_DIGEST, PROJECTION_INVALID);
  }
  activationTimestamp(
    activationString(
      set,
      "component_set_committed_at",
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
      PROJECTION_INVALID,
    ),
    PROJECTION_INVALID,
  );
  activationString(
    set,
    "worker_version_id",
    ACTIVATION_COMPONENT_WORKER_VERSION,
    PROJECTION_INVALID,
  );
  parseWorm(set.manifest_worm);
}

function parseRuntime(value: JsonValue | undefined): void {
  const runtime = exactActivationObject(value, RUNTIME_FIELDS, PROJECTION_INVALID);
  const digestFields = [
    "controller_action_bundle_sha256",
    "service_authority_expectation_sha256",
    "target_branch_ruleset_evidence_sha256",
    "target_branch_ruleset_projection_sha256",
  ];
  digestFields.forEach((key) =>
    activationString(runtime, key, ACTIVATION_COMPONENT_DIGEST, PROJECTION_INVALID),
  );
  for (const key of [
    "controller_action_commit_sha",
    "controller_action_metadata_blob_sha",
    "controller_default_branch_workflow_blob_sha",
    "controller_tag_object_sha",
    "controller_workflow_blob_sha",
    "controller_workflow_sha",
  ]) {
    activationString(runtime, key, SHA1, PROJECTION_INVALID);
  }
  activationString(runtime, "cloudflare_account_id", /^[0-9a-f]{32}$/u, PROJECTION_INVALID);
  activationString(
    runtime,
    "controller_ref",
    /^refs\/tags\/[A-Za-z0-9._-]{1,64}$/u,
    PROJECTION_INVALID,
  );
  activationLiteral(runtime, "controller_ref_type", "tag", PROJECTION_INVALID);
  activationString(
    runtime,
    "controller_workflow_ref",
    /^[A-Za-z0-9./@_-]{1,512}$/u,
    PROJECTION_INVALID,
  );
  activationString(runtime, "repository_owner_id", POSITIVE_ID, PROJECTION_INVALID);
  activationString(runtime, "target_branch_ruleset_id", POSITIVE_ID, PROJECTION_INVALID);
  activationLiteral(
    runtime,
    "target_default_branch_ref",
    TRUST.targetDefaultBranchRef,
    PROJECTION_INVALID,
  );
  if (
    !Number.isSafeInteger(runtime.controller_workflow_id) ||
    Number(runtime.controller_workflow_id) < 1
  ) {
    throw componentError(PROJECTION_INVALID);
  }
  parseStringArray(runtime.controller_actor_ids);
  parseStringArray(runtime.runtime_actor_ids);
  const app = exactActivationObject(
    runtime.controller_run_reader_app,
    ["app_id", "app_slug", "installation_id"],
    PROJECTION_INVALID,
  );
  activationString(app, "app_id", POSITIVE_ID, PROJECTION_INVALID);
  activationString(app, "app_slug", SAFE_NAME, PROJECTION_INVALID);
  activationString(app, "installation_id", POSITIVE_ID, PROJECTION_INVALID);
  const serviceRoles = SERVICE_AUTHORITY_ROLES.filter(
    (role) => role !== "release_authority_ingress",
  );
  const services = exactActivationObject(
    runtime.private_services,
    serviceRoles,
    PROJECTION_INVALID,
  );
  serviceRoles.forEach((role) => {
    const service = exactActivationObject(
      services[role],
      ["service_identity", "service_name", "version_id"],
      PROJECTION_INVALID,
    );
    activationString(
      service,
      "service_identity",
      /^cloudflare-worker:[A-Za-z0-9:@._/-]{1,500}$/u,
      PROJECTION_INVALID,
    );
    activationString(service, "service_name", SAFE_NAME, PROJECTION_INVALID);
    activationString(
      service,
      "version_id",
      ACTIVATION_COMPONENT_WORKER_VERSION,
      PROJECTION_INVALID,
    );
  });
}

function parseWorm(value: JsonValue | undefined): void {
  const worm = exactActivationObject(
    value,
    ["digest", "key", "retention_until", "version_id"],
    PROJECTION_INVALID,
  );
  activationString(worm, "digest", ACTIVATION_COMPONENT_DIGEST, PROJECTION_INVALID);
  activationString(
    worm,
    "key",
    /^receipts\/v2\/[A-Za-z0-9._/-]{1,500}\.json$/u,
    PROJECTION_INVALID,
  );
  activationTimestamp(
    activationString(
      worm,
      "retention_until",
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
      PROJECTION_INVALID,
    ),
    PROJECTION_INVALID,
  );
  activationString(worm, "version_id", /^[A-Za-z0-9._=-]{1,512}$/u, PROJECTION_INVALID);
}

function parseStringArray(value: JsonValue | undefined): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    throw componentError(PROJECTION_INVALID);
  }
  const seen = new Set<string>();
  for (const candidate of value) {
    if (typeof candidate !== "string" || !POSITIVE_ID.test(candidate) || seen.has(candidate)) {
      throw componentError(PROJECTION_INVALID);
    }
    seen.add(candidate);
  }
}

function freezeJson<T extends JsonValue>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Array.isArray(value) ? value : Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}
