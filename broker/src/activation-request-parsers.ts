import {
  FINALIZE_REQUEST_SCHEMA,
  PROVISION_REQUEST_SCHEMA,
  REQUEST_ID,
  SAFE_NAME,
  SHA1,
  WORKER_VERSION,
} from "./activation-contract";
import {
  nested,
  requireDigest,
  requireExactInteger,
  requireLiteral,
  requireTimestamp,
} from "./activation-fields";
import {
  validateController,
  validateControllerGovernance,
  validateOidc,
  validateTargetGovernance,
  validateTrustedPublishers,
} from "./activation-governance";
import {
  validateAdminAccess,
  validateApps,
  validateB2,
  validateBroker,
} from "./activation-infrastructure";
import { validateActivationTarget } from "./activation-records";
import type { FinalizeRequest, ProvisionRequest } from "./activation-schema-types";
import { assert } from "./errors";
import type { TrustedRuntimeConfig } from "./types";
import { exactObject, requireObject, requireString } from "./validation";

export function parseProvisionRequest(
  value: unknown,
  config: TrustedRuntimeConfig,
): ProvisionRequest {
  const body = exactObject(value, [
    "evidence",
    "observed_at",
    "request_id",
    "schema",
    "schema_version",
  ]);
  requireLiteral(body, "schema", PROVISION_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  const observedAt = requireTimestamp(body, "observed_at");
  const requestId = requireString(body, "request_id", 128, REQUEST_ID);
  const evidence = nested(body, "evidence", [
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
  const controller = validateController(
    nested(evidence, "controller", [
      "controller_action_bundle",
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
  );
  const broker = validateBroker(
    nested(evidence, "broker", [
      "api_version",
      "audiences",
      "cloudflare_account_id",
      "configuration_sha256",
      "durable_object_migration_tag",
      "durable_object_namespaces",
      "endpoint",
      "lockfile_sha256",
      "openapi_sha256",
      "private_services",
      "route_schema_sha256",
      "service_identity",
      "source_commit_sha",
      "source_path",
      "source_repository",
      "source_repository_id",
      "source_sha256",
      "source_tree_sha",
      "version_resource_projection_sha256",
      "worker_hostname",
      "worker_script",
      "worker_version_id",
      "worker_version_tag",
    ]),
  );
  assert(
    requireString(broker, "worker_version_id", 128, WORKER_VERSION) === config.workerVersionId,
    "ACTIVATION_WORKER_VERSION_MISMATCH",
    409,
  );
  validateAdminAccess(
    nested(evidence, "admin_access", [
      "access_application_evidence_sha256",
      "access_application_id",
      "access_audience",
      "access_group_sha256",
      "access_identity_sha256",
      "access_issuer",
      "access_policy_evidence_sha256",
      "access_policy_id",
      "access_session_duration_seconds",
      "access_subject_id_sha256",
      "certificate_evidence_sha256",
      "certificate_fingerprint_sha256",
      "certificate_not_after",
      "certificate_not_before",
      "certificate_validity_evidence_sha256",
      "finalize_path",
      "hostname",
      "hostname_path_rule_evidence_sha256",
      "jwks_evidence_sha256",
      "mtls_ca_evidence_sha256",
      "mtls_ca_id",
      "mtls_provider_observation_sha256",
      "provision_path",
    ]),
    config,
  );
  validateB2(
    nested(evidence, "b2", [
      "bucket_configuration_evidence_sha256",
      "bucket_id",
      "bucket_name",
      "bucket_type",
      "encryption",
      "object_lock_enabled",
      "object_lock_mode",
      "observer_capabilities",
      "observer_key_id_sha256",
      "observer_restriction_evidence_sha256",
      "prefix",
      "retention_days",
      "writer_capabilities",
      "writer_key_id_sha256",
      "writer_restriction_evidence_sha256",
    ]),
  );
  validateApps(
    requireObject(evidence.github_apps, "ACTIVATION_APPS_REQUIRED"),
    requireObject(broker.private_services, "ACTIVATION_SERVICES_REQUIRED"),
  );
  const oidc = validateOidc(
    nested(evidence, "oidc", [
      "claim_template_evidence_sha256",
      "claim_template_receipt_id",
      "controller_actor_ids",
      "controller_subjects",
      "issuer",
      "repository_owner_id",
      "required_claims",
      "rehearsals",
      "runtime_actor_ids",
      "runtime_subject",
      "subject_format",
    ]),
    controller,
  );
  validateTrustedPublishers(evidence.trusted_publishers);
  const serviceAuthorities = nested(evidence, "service_authorities", [
    "expectation",
    "expectation_sha256",
  ]);
  requireDigest(serviceAuthorities, "expectation_sha256");
  validateControllerGovernance(
    nested(evidence, "controller_governance", [
      "actions_policy",
      "environments",
      "no_admin_bypass_evidence_sha256",
      "protected_ref",
      "repository",
      "repository_id",
      "ruleset_evidence_sha256",
      "ruleset_id",
      "workflow_enabled_evidence_sha256",
    ]),
    requireObject(evidence.github_apps, "ACTIVATION_APPS_REQUIRED"),
    controller,
  );
  validateTargetGovernance(
    nested(evidence, "target_governance", [
      "actions_policy",
      "branch_ruleset_evidence_sha256",
      "branch_ruleset_id",
      "branch_ruleset_projection",
      "branch_ruleset_projection_sha256",
      "ghcr_environment_evidence_sha256",
      "immutable_releases_evidence_sha256",
      "repository",
      "repository_id",
      "tag_ruleset_evidence_sha256",
      "tag_ruleset_id",
    ]),
    requireString(controller, "controller_action_commit_sha", 40, SHA1),
  );
  return {
    body,
    broker,
    controller,
    evidence,
    observedAt,
    oidc,
    requestId,
    serviceAuthorities,
  };
}

export function parseFinalizeRequest(value: unknown): FinalizeRequest {
  const body = exactObject(value, [
    "approvals",
    "observed_at",
    "provisioned",
    "promotion",
    "request_id",
    "schema",
    "schema_version",
    "target",
  ]);
  requireLiteral(body, "schema", FINALIZE_REQUEST_SCHEMA);
  requireExactInteger(body, "schema_version", 1);
  const observedAt = requireTimestamp(body, "observed_at");
  const requestId = requireString(body, "request_id", 128, REQUEST_ID);
  const provisioned = nested(body, "provisioned", [
    "digest",
    "record_id",
    "worker_version_id",
    "worm_key",
    "worm_version_id",
  ]);
  requireDigest(provisioned, "digest");
  requireDigest(provisioned, "record_id");
  requireString(provisioned, "worker_version_id", 128, WORKER_VERSION);
  requireString(provisioned, "worm_key", 512, /^receipts\/v1\/activation\/.+\.json$/u);
  requireString(provisioned, "worm_version_id", 512, SAFE_NAME);
  const promotion = nested(body, "promotion", [
    "completed_at",
    "deployment_id",
    "promotion_report_record_id",
    "promotion_report_record_sha256",
    "promotion_report_worm",
    "provider_observation_sha256",
    "started_at",
    "worker_version_id",
  ]);
  requireTimestamp(promotion, "started_at");
  requireTimestamp(promotion, "completed_at");
  requireString(promotion, "deployment_id", 36, WORKER_VERSION);
  requireString(promotion, "worker_version_id", 36, WORKER_VERSION);
  requireDigest(promotion, "provider_observation_sha256");
  requireDigest(promotion, "promotion_report_record_id");
  requireDigest(promotion, "promotion_report_record_sha256");
  const promotionWorm = nested(promotion, "promotion_report_worm", [
    "digest",
    "key",
    "retention_until",
    "version_id",
  ]);
  requireDigest(promotionWorm, "digest");
  requireString(promotionWorm, "key", 512, /^receipts\/v1\/deployment-observations\/.+\.json$/u);
  requireTimestamp(promotionWorm, "retention_until");
  requireString(promotionWorm, "version_id", 512, SAFE_NAME);
  assert(
    promotionWorm.digest === promotion.promotion_report_record_sha256 &&
      Date.parse(requireString(promotion, "started_at", 32)) <=
        Date.parse(requireString(promotion, "completed_at", 32)),
    "ACTIVATION_PROMOTION_EVIDENCE_INVALID",
  );
  const target = validateActivationTarget(
    nested(body, "target", [
      "commit_sha",
      "policy_blob_sha",
      "policy_path",
      "policy_sha256",
      "repository",
      "repository_id",
      "runtime_oidc_rehearsal",
      "runtime_workflow_blob_sha",
      "runtime_workflow_path",
      "runtime_workflow_sha256",
      "tree_sha",
    ]),
  );
  const approvals = nested(body, "approvals", [
    "adr_sha256",
    "feature_design_sha256",
    "final_diff_sha256",
    "independent_review_receipt_id",
    "owner_approval_receipt_id",
  ]);
  for (const key of Object.keys(approvals)) {
    requireDigest(approvals, key);
  }
  return { approvals, body, observedAt, promotion, provisioned, requestId, target };
}
