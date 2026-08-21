import {
  AUDIENCES,
  POSITIVE_ID,
  PROJECTS,
  REPOSITORY_OWNER_ID,
  REQUIRED_OIDC_CLAIMS,
  SHA1,
} from "./activation-contract";
import {
  nested,
  requireDigest,
  requireExactInteger,
  requireExactStringArray,
  requireLiteral,
  stringArray,
  validateActorIds,
} from "./activation-fields";
import { TRUST } from "./config";
import { assert } from "./errors";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

/** Validate exact controller/runtime OIDC claims and rehearsal evidence. */
export function validateOidc(oidc: JsonObject, controller: JsonObject): JsonObject {
  requireLiteral(oidc, "issuer", TRUST.issuer);
  requireLiteral(
    oidc,
    "subject_format",
    "repo:{owner}@{owner_id}/{repository}@{repository_id}:environment:{environment}",
  );
  const ownerId = requireString(oidc, "repository_owner_id", 32, POSITIVE_ID);
  assert(ownerId === REPOSITORY_OWNER_ID, "ACTIVATION_REPOSITORY_OWNER_MISMATCH");
  requireExactStringArray(oidc, "required_claims", REQUIRED_OIDC_CLAIMS);
  const controllerActors = stringArray(oidc, "controller_actor_ids");
  const runtimeActors = stringArray(oidc, "runtime_actor_ids");
  validateActorIds(controllerActors);
  validateActorIds(runtimeActors);
  const subjects = nested(oidc, "controller_subjects", [
    "github_release",
    "pypi",
    "release_attest",
  ]);
  const prefix =
    `repo:PaulKov@${ownerId}/dpone-release-controller@` +
    `${TRUST.controllerRepositoryId}:environment:`;
  requireLiteral(subjects, "release_attest", `${prefix}release-attest`);
  requireLiteral(subjects, "pypi", `${prefix}pypi`);
  requireLiteral(subjects, "github_release", `${prefix}github-release`);
  requireLiteral(
    oidc,
    "runtime_subject",
    `repo:PaulKov@${ownerId}/dpone@${TRUST.targetRepositoryId}:environment:ghcr`,
  );
  requireDigest(oidc, "claim_template_evidence_sha256");
  requireDigest(oidc, "claim_template_receipt_id");
  const rehearsals = exactObject(oidc.rehearsals, Object.keys(AUDIENCES));
  const releaseAttestSubject = requireString(subjects, "release_attest", 512);
  const controllerWorkflowSha = requireString(controller, "production_commit_sha", 40, SHA1);
  const definitions = {
    attest: controllerDefinition(releaseAttestSubject, controllerWorkflowSha, "release-attest"),
    candidate_read: controllerDefinition(
      releaseAttestSubject,
      controllerWorkflowSha,
      "release-attest",
    ),
    github_release: controllerDefinition(
      requireString(subjects, "github_release", 512),
      controllerWorkflowSha,
      "github-release",
    ),
    governance_read: controllerDefinition(
      releaseAttestSubject,
      controllerWorkflowSha,
      "release-attest",
    ),
    ledger_write: controllerDefinition(
      releaseAttestSubject,
      controllerWorkflowSha,
      "release-attest",
    ),
    pypi: controllerDefinition(requireString(subjects, "pypi", 512), controllerWorkflowSha, "pypi"),
    runtime_closure_read: {
      environment: "ghcr",
      repositoryId: TRUST.targetRepositoryId,
      subject: requireString(oidc, "runtime_subject", 512),
      workflowSha: null,
    },
  } as const;
  for (const [role, audience] of Object.entries(AUDIENCES)) {
    const definition = definitions[role as keyof typeof definitions];
    validateOidcRehearsal(
      nested(rehearsals, role, [
        "audience",
        "check_run_id",
        "environment",
        "evidence_sha256",
        "jti_sha256",
        "repository_id",
        "repository_owner_id",
        "run_attempt",
        "run_id",
        "subject",
        "workflow_sha",
      ]),
      {
        audience,
        environment: definition.environment,
        ownerId,
        repositoryId: definition.repositoryId,
        subject: definition.subject,
        workflowSha: definition.workflowSha,
      },
    );
  }
  return oidc;
}

export function validateTrustedPublishers(value: JsonValue | undefined): void {
  assert(Array.isArray(value), "ACTIVATION_TRUSTED_PUBLISHERS_REQUIRED");
  assert(value.length === PROJECTS.length, "ACTIVATION_TRUSTED_PUBLISHERS_INVALID");
  for (let index = 0; index < PROJECTS.length; index += 1) {
    const publisher = exactObject(value[index], [
      "environment",
      "evidence_receipt_id",
      "evidence_sha256",
      "project",
      "repository",
      "workflow_path",
    ]);
    requireLiteral(publisher, "project", PROJECTS[index] ?? "");
    requireLiteral(publisher, "repository", TRUST.controllerRepository);
    requireLiteral(publisher, "workflow_path", TRUST.controllerWorkflowPath);
    requireLiteral(publisher, "environment", "pypi");
    requireDigest(publisher, "evidence_receipt_id");
    requireDigest(publisher, "evidence_sha256");
  }
}

function controllerDefinition(subject: string, workflowSha: string, environment: string) {
  return {
    environment,
    repositoryId: TRUST.controllerRepositoryId,
    subject,
    workflowSha,
  } as const;
}

function validateOidcRehearsal(
  rehearsal: JsonObject,
  expected: {
    readonly audience: string;
    readonly environment: string;
    readonly ownerId: string;
    readonly repositoryId: number;
    readonly subject: string;
    readonly workflowSha: JsonValue | null;
  },
): void {
  requireLiteral(rehearsal, "audience", expected.audience);
  requireLiteral(rehearsal, "environment", expected.environment);
  requireLiteral(rehearsal, "subject", expected.subject);
  requireString(rehearsal, "check_run_id", 32, POSITIVE_ID);
  requireString(rehearsal, "run_id", 32, POSITIVE_ID);
  requireInteger(rehearsal, "run_attempt", 1, 1000);
  requireDigest(rehearsal, "evidence_sha256");
  requireDigest(rehearsal, "jti_sha256");
  requireExactInteger(rehearsal, "repository_id", expected.repositoryId);
  requireLiteral(rehearsal, "repository_owner_id", expected.ownerId);
  const workflowSha = requireString(rehearsal, "workflow_sha", 40, SHA1);
  if (expected.workflowSha !== null) {
    assert(workflowSha === expected.workflowSha, "ACTIVATION_OIDC_WORKFLOW_MISMATCH");
  }
}
