import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTPayload,
} from "jose";

import { LIMITS, TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import type { AuthenticatedWorkflow, OidcRouteTrust } from "./types";

const remoteJwks = createRemoteJWKSet(new URL(TRUST.jwks), {
  cacheMaxAge: 10 * 60 * 1000,
  cooldownDuration: 30 * 1000,
  timeoutDuration: 5 * 1000,
});

const REQUIRED_CLAIMS = [
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

export async function authenticateGitHubOidc(
  request: Request,
  trust: OidcRouteTrust,
  keySet: JWTVerifyGetKey = remoteJwks,
): Promise<AuthenticatedWorkflow> {
  const authorization = request.headers.get("authorization");
  assert(authorization !== null, "OIDC_BEARER_REQUIRED", 401);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/u.exec(authorization);
  assert(match !== null, "OIDC_BEARER_INVALID", 401);
  const token = match[1];
  assert(token !== undefined && token.length <= 16_384, "OIDC_BEARER_INVALID", 401);
  return verifyGitHubOidcToken(token, trust, keySet);
}

export async function verifyGitHubOidcToken(
  token: string,
  trust: OidcRouteTrust,
  keySet: JWTVerifyGetKey,
): Promise<AuthenticatedWorkflow> {
  try {
    const verified = await jwtVerify(token, keySet, {
      algorithms: ["RS256"],
      audience: trust.audience,
      clockTolerance: LIMITS.oidcClockToleranceSeconds,
      issuer: TRUST.issuer,
      maxTokenAge: `${LIMITS.oidcMaxAgeSeconds}s`,
      requiredClaims: [...REQUIRED_CLAIMS],
    });
    assert(verified.protectedHeader.alg === "RS256", "OIDC_ALGORITHM_INVALID", 401);
    assert(
      verified.protectedHeader.typ === undefined || verified.protectedHeader.typ === "JWT",
      "OIDC_TYPE_INVALID",
      401,
    );
    return validateClaims(verified.payload, trust);
  } catch (error) {
    if (error instanceof BrokerError) {
      throw error;
    }
    if (error instanceof joseErrors.JOSEError) {
      throw new BrokerError("OIDC_VERIFICATION_FAILED", 401, false);
    }
    throw new BrokerError("OIDC_VERIFICATION_UNAVAILABLE", 503, true);
  }
}

function validateClaims(payload: JWTPayload, trust: OidcRouteTrust): AuthenticatedWorkflow {
  const audience = claimString(payload.aud, "OIDC_AUDIENCE_INVALID");
  const actorId = claimPositiveIntegerText(payload.actor_id, "OIDC_ACTOR_ID_INVALID");
  const checkRunId = claimPositiveIntegerText(payload.check_run_id, "OIDC_CHECK_RUN_ID_INVALID");
  const environment = claimString(payload.environment, "OIDC_ENVIRONMENT_INVALID");
  const jti = claimString(payload.jti, "OIDC_JTI_INVALID");
  const ref = claimString(payload.ref, "OIDC_REF_INVALID");
  const repository = claimString(payload.repository, "OIDC_REPOSITORY_INVALID");
  const repositoryOwnerId = claimPositiveIntegerText(
    payload.repository_owner_id,
    "OIDC_REPOSITORY_OWNER_ID_INVALID",
  );
  const repositoryId = claimPositiveInteger(payload.repository_id, "OIDC_REPOSITORY_ID_INVALID");
  const repositoryVisibility = claimString(
    payload.repository_visibility,
    "OIDC_REPOSITORY_VISIBILITY_INVALID",
  );
  const runAttempt = claimPositiveInteger(payload.run_attempt, "OIDC_RUN_ATTEMPT_INVALID");
  const runId = claimPositiveIntegerText(payload.run_id, "OIDC_RUN_ID_INVALID");
  const sha = claimString(payload.sha, "OIDC_SHA_INVALID");
  const subject = claimString(payload.sub, "OIDC_SUBJECT_INVALID");
  const workflowRef = claimString(payload.workflow_ref, "OIDC_WORKFLOW_REF_INVALID");
  const workflowSha = claimString(payload.workflow_sha, "OIDC_WORKFLOW_SHA_INVALID");
  const issuedAt = claimNumber(payload.iat, "OIDC_IAT_INVALID");
  const notBefore = claimNumber(payload.nbf, "OIDC_NBF_INVALID");
  const expiresAt = claimNumber(payload.exp, "OIDC_EXP_INVALID");

  assert(audience === trust.audience, "OIDC_AUDIENCE_MISMATCH", 403);
  assert(repository === trust.repository, "OIDC_REPOSITORY_MISMATCH", 403);
  assert(repositoryId === trust.repositoryId, "OIDC_REPOSITORY_ID_MISMATCH", 403);
  assert(
    canonicalPositiveIntegerText(trust.repositoryOwnerId, "OIDC_TRUST_CONFIGURATION_INVALID", 503),
    "OIDC_TRUST_CONFIGURATION_INVALID",
    503,
  );
  assert(repositoryOwnerId === trust.repositoryOwnerId, "OIDC_REPOSITORY_OWNER_ID_MISMATCH", 403);
  assert(
    repositoryVisibility === trust.repositoryVisibility,
    "OIDC_REPOSITORY_VISIBILITY_MISMATCH",
    403,
  );
  const expectedWorkflowRef = `${trust.repository}/${trust.workflowPath}@${trust.ref}`;
  assert(workflowRef === expectedWorkflowRef, "OIDC_WORKFLOW_REF_MISMATCH", 403);
  assert(workflowSha === trust.workflowSha, "OIDC_WORKFLOW_SHA_MISMATCH", 403);
  assert(sha === trust.workflowSha, "OIDC_SHA_MISMATCH", 403);
  assert(ref === trust.ref, "OIDC_REF_MISMATCH", 403);
  assert(payload.ref_type === trust.refType, "OIDC_REF_TYPE_MISMATCH", 403);
  assert(environment === trust.environment, "OIDC_ENVIRONMENT_MISMATCH", 403);
  const repositoryName = trust.repository.split("/", 2)[1];
  assert(repositoryName !== undefined, "OIDC_TRUST_CONFIGURATION_INVALID", 503);
  const expectedSubject =
    `repo:PaulKov@${trust.repositoryOwnerId}/` +
    `${repositoryName}@${trust.repositoryId}:environment:${trust.environment}`;
  assert(subject === expectedSubject, "OIDC_SUBJECT_MISMATCH", 403);
  assert(payload.event_name === trust.eventName, "OIDC_EVENT_MISMATCH", 403);
  assert(payload.runner_environment === "github-hosted", "OIDC_RUNNER_MISMATCH", 403);
  assert(trust.allowedActorIds.has(actorId), "OIDC_ACTOR_FORBIDDEN", 403);
  assert(runAttempt >= 1 && runAttempt <= 1000, "OIDC_RUN_ATTEMPT_INVALID", 401);
  assert(jti.length >= 16 && jti.length <= 256, "OIDC_JTI_INVALID", 401);
  assert(
    expiresAt > issuedAt && issuedAt >= notBefore - LIMITS.oidcClockToleranceSeconds,
    "OIDC_TIME_INVALID",
    401,
  );
  assert(expiresAt - issuedAt <= LIMITS.oidcMaxAgeSeconds, "OIDC_LIFETIME_INVALID", 401);
  assert(payload.job_workflow_ref === undefined, "OIDC_REUSABLE_WORKFLOW_FORBIDDEN", 403);
  assert(payload.job_workflow_sha === undefined, "OIDC_REUSABLE_WORKFLOW_FORBIDDEN", 403);

  return {
    actorId,
    audience,
    checkRunId,
    environment,
    expiresAt,
    issuedAt,
    jti,
    notBefore,
    ref,
    repository,
    repositoryId,
    repositoryOwnerId,
    runAttempt,
    runId,
    sha,
    subject,
    workflowRef,
    workflowSha,
  };
}

function claimString(value: unknown, code: string): string {
  assert(typeof value === "string" && value.length > 0 && value.length <= 512, code, 401);
  return value;
}

function claimPositiveInteger(value: unknown, code: string): number {
  return Number(claimPositiveIntegerText(value, code));
}

function claimPositiveIntegerText(value: unknown, code: string): string {
  const text = claimString(value, code);
  assert(canonicalPositiveIntegerText(text, code, 401), code, 401);
  return text;
}

function canonicalPositiveIntegerText(value: string, code: string, status: number): boolean {
  assert(/^[1-9][0-9]{0,15}$/u.test(value), code, status);
  return Number.isSafeInteger(Number(value));
}

function claimNumber(value: unknown, code: string): number {
  assert(typeof value === "number" && Number.isSafeInteger(value) && value >= 0, code, 401);
  return value;
}
