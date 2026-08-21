import { CLOUDFLARE_UUID } from "./cloudflare-ids";

export const PROVISION_REQUEST_SCHEMA = "dpone.release-broker-provision-request.v1";
export const PROVISIONED_RECORD_SCHEMA = "dpone.release-broker-provisioned.v1";
export const FINALIZE_REQUEST_SCHEMA = "dpone.release-broker-finalize-request.v1";
export const ACTIVATED_RECORD_SCHEMA = "dpone.release-broker-activated.v1";

export const CONTROLLER_ACTION_BUNDLE_SCHEMA = "dpone.release-controller-action-bundle.v1";
export const CONTROLLER_ACTION_BUNDLE_SCHEMA_SHA256 =
  "481fd94602156d9674be387780a2aebd51b6f653555aa4e5b5c950aee7127869";
export const CONTROLLER_ACTION_BUNDLE_MAX_MEMBER_BYTES = 16 * 1024 * 1024;
export const CONTROLLER_ACTION_BUNDLE_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const CONTROLLER_ACTION_EXECUTABLE_PATHS = [
  "actions/broker-call/action.yml",
  "actions/broker-call/dist/index.js",
  "actions/lease-sentinel/action.yml",
  "actions/lease-sentinel/dist/index.js",
  "actions/runtime-closure/action.yml",
  "actions/runtime-closure/dist/index.js",
] as const;
export const RUNTIME_CLOSURE_ACTION_METADATA_PATH = "actions/runtime-closure/action.yml";

export const AUDIENCES = Object.freeze({
  attest: "dpone-release-controller-attest",
  candidate_read: "dpone-release-controller-candidate-read",
  github_release: "dpone-release-controller-github-release",
  governance_read: "dpone-release-controller-governance-read",
  ledger_write: "dpone-release-controller-ledger-write",
  pypi: "dpone-release-controller-pypi",
  runtime_closure_read: "dpone-runtime-controller-closure-read",
});

export const PROJECTS = [
  "apache-airflow-providers-dpone",
  "dpone",
  "dpone-airflow-pack",
  "dpone-native-accel",
] as const;

const CONTROLLER_EXTERNAL_ACTIONS = [
  "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
] as const;

const TARGET_EXTERNAL_ACTIONS = [
  "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
  "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
  "azure/setup-helm@1a275c3b69536ee54be43f2070a358922e12c8d4",
  "docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",
  "ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a",
  "trufflesecurity/trufflehog@27b0417c16317ca9a472a9a8092acce143b49c55",
] as const;

/** Exact provider-normalized selected-actions array for Commit A. */
export function controllerSelectedActions(controllerActionCommitSha: string): readonly string[] {
  return Object.freeze([
    `paulkov/dpone-release-controller@${controllerActionCommitSha}`,
    ...CONTROLLER_EXTERNAL_ACTIONS,
  ]);
}

/** Exact provider-normalized target selected-actions array for Commit A. */
export function targetSelectedActions(controllerActionCommitSha: string): readonly string[] {
  return Object.freeze([
    ...TARGET_EXTERNAL_ACTIONS.slice(0, 5),
    `paulkov/dpone-release-controller@${controllerActionCommitSha}`,
    TARGET_EXTERNAL_ACTIONS[5],
  ]);
}

export const REQUIRED_OIDC_CLAIMS = [
  "actor_id",
  "aud",
  "check_run_id",
  "environment",
  "event_name",
  "exp",
  "iat",
  "iss",
  "jti",
  "nbf",
  "ref",
  "ref_type",
  "repository",
  "repository_id",
  "repository_owner_id",
  "repository_visibility",
  "run_attempt",
  "run_id",
  "runner_environment",
  "sha",
  "sub",
  "workflow_ref",
  "workflow_sha",
] as const;

export const SERVICE_BINDINGS = Object.freeze({
  attestation_mutator: "ATTESTATION_MUTATOR",
  candidate_reader: "CANDIDATE_READER",
  closed_projector: "CLOSED_PROJECTOR",
  cloudflare_deployment_observer: "CLOUDFLARE_DEPLOYMENT_OBSERVER",
  controller_run_reader: "CONTROLLER_RUN_READER",
  governance_reader: "GOVERNANCE_READER",
  pypi_deployment_gate: "PYPI_DEPLOYMENT_GATE",
  pypi_reader: "PYPI_READER",
  release_mutator: "RELEASE_MUTATOR",
  runtime_deployment_gate: "RUNTIME_DEPLOYMENT_GATE",
  tenant_scanner: "TENANT_SCANNER",
  worm_mirror: "WORM_MIRROR",
  worm_version_observer: "WORM_VERSION_OBSERVER",
});

/**
 * Exact read-only controller App grant. This role is isolated from all
 * provider mutations and is the sole authority for controller run and A0
 * governance observations.
 */
export const CONTROLLER_RUN_READER_PERMISSIONS = Object.freeze({
  actions: "read",
  administration: "read",
  attestations: "read",
  checks: "read",
  contents: "read",
  environments: "read",
  metadata: "read",
} as const);

/** Exact read-only target grant used only by the candidate artifact adapter. */
export const CANDIDATE_READER_PERMISSIONS = Object.freeze({
  actions: "read",
  contents: "read",
  metadata: "read",
} as const);

/** Exact read-only target governance grant; no provider mutation is possible. */
export const GOVERNANCE_READER_PERMISSIONS = Object.freeze({
  actions: "read",
  administration: "read",
  attestations: "read",
  checks: "read",
  contents: "read",
  metadata: "read",
  statuses: "read",
} as const);

export const APP_PERMISSIONS = Object.freeze({
  attestation_mutator: ["attestations:write", "metadata:read"],
  candidate_reader: Object.freeze(
    Object.entries(CANDIDATE_READER_PERMISSIONS).map(
      ([permission, access]) => `${permission}:${access}`,
    ),
  ),
  closed_projector: ["checks:write", "metadata:read"],
  controller_run_reader: Object.freeze(
    Object.entries(CONTROLLER_RUN_READER_PERMISSIONS).map(
      ([permission, access]) => `${permission}:${access}`,
    ),
  ),
  governance_reader: Object.freeze(
    Object.entries(GOVERNANCE_READER_PERMISSIONS).map(
      ([permission, access]) => `${permission}:${access}`,
    ),
  ),
  pypi_deployment_gate: ["actions:read", "deployments:write", "metadata:read"],
  release_mutator: ["contents:write", "metadata:read"],
  runtime_deployment_gate: ["actions:read", "deployments:write", "metadata:read"],
});

export const SHA1 = /^[0-9a-f]{40}$/u;
export const SHA256_HEX = /^[0-9a-f]{64}$/u;
export const POSITIVE_ID = /^[1-9][0-9]{0,31}$/u;
export const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
export const REPOSITORY_OWNER_ID = "74862786";
export const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
export const WORKER_VERSION = CLOUDFLARE_UUID;
export const CF_ID = /^[0-9a-f]{32}$/u;
export const B2_BUCKET_ID = /^[0-9a-f]{24}$/u;
export const PATH = /^(?!\/)(?!.*\.\.)(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/u;
export const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
