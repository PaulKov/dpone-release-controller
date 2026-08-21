import type { JsonObject } from "./types";

/** Candidate-only compact activation record protocol. It is not wired to runtime routes or storage. */
export const ACTIVATION_PROVISIONED_RECORD_V2_SCHEMA =
  "dpone.release-broker-provisioned.v2" as const;
export const ACTIVATION_ACTIVATED_RECORD_V2_SCHEMA = "dpone.release-broker-activated.v2" as const;
export const ACTIVATION_PROVISION_INTENT_V2_SCHEMA =
  "dpone.release-broker-provision-intent.v2" as const;
export const ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA =
  "dpone.release-broker-finalize-request.v2" as const;
export const ACTIVATION_ATTEMPT_V2_SCHEMA = "dpone.activation-evidence-attempt.v2" as const;
export const ACTIVATION_ISSUANCE_V2_SCHEMA = "dpone.activation-evidence-issuance.v2" as const;
export const ACTIVATION_ANCHOR_VECTOR_V2_SCHEMA =
  "dpone.activation-service-authority-anchor-vector.v2" as const;
export const CLOUDFLARE_BATCH_INTENT_V2_SCHEMA =
  "dpone.cloudflare-evidence-worm-batch-intent.v2" as const;

export const ACTIVATION_RECORD_V2_LIMITS = Object.freeze({
  bytes: 65_536,
  depth: 16,
  keyBytes: 512,
  nodes: 512,
  stringBytes: 512,
});

export const ACTIVATION_RECORD_V2_RETENTION_DAYS = 2_557;
export const ACTIVATION_RECORD_V2_MAX_ISSUANCE_ORDINAL = 1_000_000;

/** This tuple is protocol data. Never derive its order with Object.keys(). */
export const ACTIVATION_RECORD_V2_SERVICE_ROLES = Object.freeze([
  "attestation_mutator",
  "candidate_reader",
  "closed_projector",
  "cloudflare_deployment_observer",
  "controller_run_reader",
  "governance_reader",
  "pypi_deployment_gate",
  "pypi_reader",
  "release_authority_ingress",
  "release_mutator",
  "runtime_deployment_gate",
  "tenant_scanner",
  "worm_mirror",
  "worm_version_observer",
] as const);

export const ACTIVATION_RECORD_V2_DIRECT_SLOTS = Object.freeze([
  "CONTROLLER_ACTION",
  "CONTROLLER_OIDC",
  "TARGET_OIDC",
  "TARGET_RULESET",
] as const);

export const ACTIVATION_RECORD_V2_DIRECT_KINDS = Object.freeze([
  "controller_action_bundle_observation",
  "github_oidc_subject_customization",
  "github_oidc_subject_customization",
  "github_branch_ruleset",
] as const);

export type ActivationRecordV2Sequence = 0 | 1;
export type ActivationRecordV2DirectSlot = (typeof ACTIVATION_RECORD_V2_DIRECT_SLOTS)[number];

export interface ActivationRecordV2Budget {
  readonly bytes: number;
  readonly depth: number;
  readonly maxKeyBytes: number;
  readonly maxStringBytes: number;
  readonly nodes: number;
}

/** A structurally valid value only. No journal, resolver, provider, or WORM authority is implied. */
export interface UntrustedActivationRecordV2 {
  readonly canonicalBytes: Uint8Array;
  readonly document: JsonObject;
  readonly recordId: string;
  readonly recordSha256: string;
  readonly sequence: ActivationRecordV2Sequence;
  readonly trust: "UNTRUSTED";
}

export interface UntrustedActivationRecordV2Chain {
  readonly activated: UntrustedActivationRecordV2;
  readonly provisioned: UntrustedActivationRecordV2;
  readonly trust: "UNTRUSTED";
}

export const ACTIVATION_RECORD_V2_ROOT_FIELDS = Object.freeze({
  0: Object.freeze([
    "committed_at",
    "component_authority",
    "fencing_token",
    "observed_at",
    "operation",
    "previous",
    "provider_evidence",
    "record_id",
    "schema",
    "schema_version",
    "sequence",
    "service_authority",
    "worker_version_id",
  ]),
  1: Object.freeze([
    "approvals",
    "committed_at",
    "fencing_token",
    "observed_at",
    "operation",
    "previous",
    "promotion",
    "provisioned",
    "record_id",
    "schema",
    "schema_version",
    "sequence",
    "service_authority",
    "target",
    "worker_version_id",
  ]),
} as const);

export const ACTIVATION_RECORD_V2_BODY_FIELDS = Object.freeze({
  0: Object.freeze(ACTIVATION_RECORD_V2_ROOT_FIELDS[0].filter((field) => field !== "record_id")),
  1: Object.freeze(ACTIVATION_RECORD_V2_ROOT_FIELDS[1].filter((field) => field !== "record_id")),
} as const);
