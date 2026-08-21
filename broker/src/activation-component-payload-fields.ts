export const ADMIN_ACCESS_FIELDS = [
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
] as const;

export const B2_FIELDS = [
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
] as const;

export const BROKER_FIELDS = [
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
] as const;

export const BROKER_CORE_FIELDS = [
  "api_version",
  "audiences",
  "authority_role",
  "durable_object_migration_tag",
  "durable_object_namespaces",
  "endpoint",
  "lockfile_sha256",
  "openapi_sha256",
  "route_schema_sha256",
  "source_path",
  "source_repository",
  "source_repository_id",
  "source_tree_sha",
  "worker_hostname",
  "worker_version_tag",
] as const;

export const CONTROLLER_FIELDS = [
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
] as const;

export const CONTROLLER_GOVERNANCE_FIELDS = [
  "actions_policy",
  "environments",
  "no_admin_bypass_evidence_sha256",
  "protected_ref",
  "repository",
  "repository_id",
  "ruleset_evidence_sha256",
  "ruleset_id",
  "workflow_enabled_evidence_sha256",
] as const;

export const GITHUB_APP_FIELDS = [
  "app_id",
  "app_slug",
  "credential_fingerprint_sha256",
  "installation_id",
  "oauth_callback_configured",
  "permissions",
  "provider_observation_sha256",
  "repository",
  "repository_id",
  "repository_selection",
  "repository_selection_evidence_sha256",
  "request_on_install_enabled",
  "service_binding",
  "subscriptions",
  "user_authorization_enabled",
  "webhook_active",
  "worker_version_id",
] as const;

export const NORMALIZED_GITHUB_APP_FIELDS = GITHUB_APP_FIELDS.filter(
  (field) => field !== "service_binding" && field !== "worker_version_id",
);

export const OIDC_FIELDS = [
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
] as const;

export const TARGET_GOVERNANCE_FIELDS = [
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
] as const;

export const AUTHORITY_HEADER_FIELDS = [
  "broker_source_commit_sha",
  "cloudflare_account_id",
  "expectation_sha256",
  "schema",
  "schema_version",
] as const;

export const AUTHORITY_INVENTORY_ROW_FIELDS = [
  "authority_role",
  "binding",
  "configuration_sha256",
  "service",
  "service_identity",
  "source_commit_sha",
  "source_sha256",
  "version_resource_projection_sha256",
  "worker_version_id",
] as const;

export const NORMALIZED_DEPLOYMENT_ROW_FIELDS = [
  "authority_role",
  "deployment_id",
  "deployment_versions",
] as const;

export const FINAL_DEPLOYMENT_MEMBER_FIELDS = [
  "artifact_kind",
  "percentage",
  "provisioning_record_id",
  "provisioning_record_sha256",
  "script_etag",
] as const;

export const BOOTSTRAP_DEPLOYMENT_MEMBER_FIELDS = [
  "artifact_kind",
  "configuration_sha256",
  "percentage",
  "provisioning_record_id",
  "provisioning_record_sha256",
  "script_etag",
  "source_sha256",
  "version_resource_projection_sha256",
  "worker_version_id",
] as const;

export const AUTHORITY_NETWORK_FIELDS = [
  "authority_role",
  "cert_id",
  "domain_id",
  "environment",
  "hostname",
  "zone_id",
  "zone_name",
] as const;
