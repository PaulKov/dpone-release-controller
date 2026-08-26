const DIGEST = "^sha256:[0-9a-f]{64}$";
const SHA1 = "^[0-9a-f]{40}$";
const TAG = "^v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$";
const TIMESTAMP = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?Z$";
const VERSION = "^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$";
const SERVICE_IDENTITY =
  "^cloudflare-worker:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._-]{1,127}@[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$";
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;

const request = object({
  release_identity_id: string(DIGEST),
  schema: constant("dpone.release-runtime-closure-request.v1"),
  schema_version: constant(1),
});

const observation = object({
  activation: object({
    activated_record_id: string(DIGEST),
    activated_record_sha256: string(DIGEST),
    closed_projector_app_id: integer(1),
    closed_projector_app_slug: string("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$"),
    closed_projector_installation_id: integer(1),
    controller_action_bundle_sha256: string(DIGEST),
    controller_action_commit_sha: string(SHA1),
    controller_action_metadata_blob_sha: string(SHA1),
    provisioned_record_id: string(DIGEST),
    provisioned_record_sha256: string(DIGEST),
    target_branch_ruleset_evidence_sha256: string(DIGEST),
    target_branch_ruleset_id: string("^[1-9][0-9]{0,31}$"),
    target_branch_ruleset_projection_sha256: string(DIGEST),
    target_default_branch_ref: constant("refs/heads/master"),
    target_policy_blob_sha: string(SHA1),
    target_policy_commit_sha: string(SHA1),
    target_policy_sha256: string(DIGEST),
    target_runtime_workflow_blob_sha: string(SHA1),
    target_runtime_workflow_sha256: string(DIGEST),
    worker_version_id: string(VERSION),
  }),
  archive_source: object({
    expires_at: string(TIMESTAMP),
    raw_url_retained: constant(false),
    url_sha256: string(DIGEST),
  }),
  broker_accepted_at: string(TIMESTAMP),
  broker_request_id: string("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$"),
  closed_check: object({
    app_id: integer(1),
    app_slug: string("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$"),
    check_run_id: integer(1),
    completed_at: string(TIMESTAMP),
    conclusion: constant("success"),
    external_id: string(
      "^dpone-release-controller\\.closed\\.v1\\|sha256:[0-9a-f]{64}\\|[1-9][0-9]{0,15}\\|[1-9][0-9]{0,3}$",
    ),
    head_sha: string(SHA1),
    name: constant("Release controller CLOSED"),
    output_marker_sha256: string(DIGEST),
    output_summary: string("^DPONE_RELEASE_CONTROLLER_CLOSED_V1 [A-Za-z0-9_-]{1,10923}$"),
    output_title: constant("dpone release controller CLOSED / PASS / GO"),
    provider_response_sha256: string(DIGEST),
    started_at: string(TIMESTAMP),
    status: constant("completed"),
  }),
  closure_artifact: object({
    created_at: string(TIMESTAMP),
    digest: string(DIGEST),
    expired: constant(false),
    expires_at: string(TIMESTAMP),
    id: integer(1),
    name: string("^release-controller-closure-[1-9][0-9]{0,15}-[1-9][0-9]{0,3}$"),
    provider_response_sha256: string(DIGEST),
    size_bytes: integer(1, 67_108_864),
    workflow_run_head_sha: string(SHA1),
    workflow_run_id: integer(1),
  }),
  controller_run: object({
    conclusion: constant("success"),
    event: constant("workflow_dispatch"),
    head_branch: string("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$"),
    head_sha: string(SHA1),
    provider_response_sha256: string(DIGEST),
    repository: constant("PaulKov/dpone-release-controller"),
    repository_id: constant(1_305_993_853),
    run_attempt: integer(1, 1000),
    run_id: integer(1),
    status: constant("completed"),
    workflow_id: integer(1),
    workflow_path: constant(".github/workflows/release-controller.yml"),
    workflow_sha: string(SHA1),
  }),
  ledger: object({
    closed_check_verified_receipt_id: string(DIGEST),
    closed_check_verified_receipt_sha256: string(DIGEST),
    closed_check_verified_sequence: integer(0, MAX_SAFE_INTEGER - 1),
    head_receipt_id: string(DIGEST),
    head_receipt_sha256: string(DIGEST),
    head_receipt_type: constant("LEASE_RELEASED"),
    head_sequence: integer(1),
    phase: constant("TERMINAL"),
    release_identity_id: string(DIGEST),
  }),
  provider_api_version: constant("2026-03-10"),
  provider_response_sha256: string(DIGEST),
  runtime: object({
    actor_id: string("^[1-9][0-9]{0,31}$"),
    check_app_id: constant(15_368),
    check_app_slug: constant("github-actions"),
    check_name: constant("Promote certified runtime image aliases"),
    check_run_id: integer(1),
    check_status: constant("in_progress"),
    environment: constant("ghcr"),
    event: constant("push"),
    head_branch: string(TAG),
    peeled_commit_sha: string(SHA1),
    policy_blob_sha: string(SHA1),
    policy_sha256: string(DIGEST),
    policy_source_commit_sha: string(SHA1),
    provider_response_sha256: string(DIGEST),
    repository: constant("PaulKov/dpone"),
    repository_id: constant(1_255_975_556),
    run_attempt: integer(1, 1000),
    run_id: integer(1),
    run_status: constant("in_progress"),
    tag: string(TAG),
    tag_object_sha: string(SHA1),
    tag_ref: string("^refs/tags/v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$"),
    workflow_path: constant(".github/workflows/runtime-image.yml"),
    workflow_ref: string(
      "^PaulKov/dpone/\\.github/workflows/runtime-image\\.yml@refs/tags/v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$",
    ),
    workflow_blob_sha: string(SHA1),
    workflow_sha: string(SHA1),
    workflow_sha256: string(DIGEST),
    workflow_source_commit_sha: string(SHA1),
  }),
  schema: constant("dpone.release-runtime-closure-provider-observation.v1"),
  schema_version: constant(1),
  services: object({
    controller_run_reader: service(),
    governance_reader: service(),
  }),
  target_lineage: object({
    baseline_ahead_by: integer(0),
    baseline_behind_by: constant(0),
    baseline_commit_sha: string(SHA1),
    baseline_compare_path: string(
      "^/repos/PaulKov/dpone/compare/[0-9a-f]{40}\\.\\.\\.[0-9a-f]{40}$",
    ),
    baseline_compare_provider_response_sha256: string(DIGEST),
    baseline_merge_base_commit_sha: string(SHA1),
    baseline_status: string("^(?:ahead|identical)$"),
    baseline_total_commits: integer(0),
    branch_ruleset_evidence_sha256: string(DIGEST),
    branch_ruleset_id: string("^[1-9][0-9]{0,31}$"),
    branch_ruleset_projection_sha256: string(DIGEST),
    branch_ruleset_provider_response_sha256: string(DIGEST),
    default_branch_head_sha: string(SHA1),
    default_branch_provider_response_sha256: string(DIGEST),
    default_branch_ref: constant("refs/heads/master"),
    observed_at: string(TIMESTAMP),
    release_ahead_by: integer(0),
    release_behind_by: constant(0),
    release_commit_sha: string(SHA1),
    release_compare_path: string(
      "^/repos/PaulKov/dpone/compare/[0-9a-f]{40}\\.\\.\\.[0-9a-f]{40}$",
    ),
    release_compare_provider_response_sha256: string(DIGEST),
    release_merge_base_commit_sha: string(SHA1),
    release_status: string("^(?:ahead|identical)$"),
    release_total_commits: integer(0),
  }),
});

const response = object({
  cache_control: constant("private, no-store, max-age=0"),
  content_length: string("^[1-9][0-9]{0,7}$"),
  content_type: constant("application/vnd.dpone.release-controller-closure.v1+zip"),
  controller_run_reader_service_identity: string(SERVICE_IDENTITY),
  controller_run_reader_service_version_id: string(VERSION),
  governance_reader_service_identity: string(SERVICE_IDENTITY),
  governance_reader_service_version_id: string(VERSION),
  provider_observation: string("^[A-Za-z0-9_-]{1,16384}$"),
  provider_observation_sha256: string(DIGEST),
  request_id: string("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$"),
  response_schema: constant("dpone.release-runtime-closure-stream-response.v1"),
  x_content_type_options: constant("nosniff"),
});

const selected =
  process.argv[2] === "request"
    ? {
        $id: "https://schemas.dp-one.ru/release/release-runtime-closure-request-v1.schema.json",
        ...request,
      }
    : process.argv[2] === "observation"
      ? {
          $comment:
            "The verifier additionally enforces canonical JSON, head_sequence=closed_check_verified_sequence+1, marker decoding/digest/cross-bindings, projection aggregate digest, and exact service pins.",
          $id: "https://schemas.dp-one.ru/release/release-runtime-closure-provider-observation-v1.schema.json",
          ...observation,
        }
      : process.argv[2] === "response"
        ? {
            $comment:
              "The verifier constructs this normalized object from required response headers, rejects redirects and forbidden capability/cookie/range/encoding headers, parses content_length <= 67108864, verifies the observation and service pins, and hashes the exact raw ZIP bytes to closure_artifact.digest.",
            $id: "https://schemas.dp-one.ru/release/release-runtime-closure-stream-response-v1.schema.json",
            ...response,
          }
        : null;
if (selected === null || process.argv.length !== 3) {
  throw new Error(
    "usage: node scripts/generate-runtime-closure-schema.mjs (request|observation|response)",
  );
}
process.stdout.write(
  canonical({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    ...selected,
  }) + "\n",
);

function object(properties) {
  return {
    additionalProperties: false,
    properties,
    required: Object.keys(properties).sort(),
    type: "object",
  };
}

function service() {
  return object({
    service_identity: string(SERVICE_IDENTITY),
    service_version_id: string(VERSION),
  });
}

function string(pattern) {
  return { pattern, type: "string" };
}

function integer(minimum, maximum = MAX_SAFE_INTEGER) {
  return { maximum, minimum, type: "integer" };
}

function constant(value) {
  return { const: value };
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
