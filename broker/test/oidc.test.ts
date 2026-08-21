import { generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { controllerRouteTrust, TRUST } from "../src/config";
import { verifyGitHubOidcToken } from "../src/oidc";
import type { ActivationTrust } from "../src/types";

const WORKFLOW_SHA = "c".repeat(40);
const CONTROLLER_REF = "refs/tags/v1.0.0";
const CONTROLLER_WORKFLOW_REF = `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@${CONTROLLER_REF}`;
const OWNER_ID = "123456789";
let privateKey: CryptoKey;
let publicKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("RS256", { extractable: false }));
});

describe("GitHub OIDC admission", () => {
  it("accepts only the immutable repository identity and exact route claims", async () => {
    const token = await issueToken();
    const verified = await verifyGitHubOidcToken(
      token,
      controllerRouteTrust(activation(), "ledger"),
      async () => publicKey,
    );
    expect(verified.checkRunId).toBe("9001");
    expect(verified.workflowSha).toBe(WORKFLOW_SHA);
  });

  it("rejects an actor outside the route allowlist", async () => {
    const token = await issueToken({ actor_id: "444444444" });
    await expect(
      verifyGitHubOidcToken(
        token,
        controllerRouteTrust(activation(), "ledger"),
        async () => publicKey,
      ),
    ).rejects.toThrowError("OIDC_ACTOR_FORBIDDEN");
  });

  it("rejects the wrong check-run shape and workflow SHA", async () => {
    const invalidCheckRun = await issueToken({ check_run_id: "0" });
    await expect(
      verifyGitHubOidcToken(
        invalidCheckRun,
        controllerRouteTrust(activation(), "ledger"),
        async () => publicKey,
      ),
    ).rejects.toThrowError("OIDC_CHECK_RUN_ID_INVALID");

    const wrongSha = await issueToken({ workflow_sha: "d".repeat(40) });
    await expect(
      verifyGitHubOidcToken(
        wrongSha,
        controllerRouteTrust(activation(), "ledger"),
        async () => publicKey,
      ),
    ).rejects.toThrowError("OIDC_WORKFLOW_SHA_MISMATCH");
  });

  it("requires workflow_dispatch on the exact protected tag ref", async () => {
    await expect(
      verifyGitHubOidcToken(
        await issueToken({ ref_type: "branch" }),
        controllerRouteTrust(activation(), "ledger"),
        async () => publicKey,
      ),
    ).rejects.toThrowError("OIDC_REF_TYPE_MISMATCH");
    await expect(
      verifyGitHubOidcToken(
        await issueToken({ event_name: "push" }),
        controllerRouteTrust(activation(), "ledger"),
        async () => publicKey,
      ),
    ).rejects.toThrowError("OIDC_EVENT_MISMATCH");
  });
});

async function issueToken(overrides: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    actor_id: "123456789",
    check_run_id: "9001",
    environment: "release-attest",
    event_name: "workflow_dispatch",
    ref: CONTROLLER_REF,
    ref_type: "tag",
    repository: TRUST.controllerRepository,
    repository_id: String(TRUST.controllerRepositoryId),
    repository_owner_id: OWNER_ID,
    repository_visibility: "public",
    run_attempt: "1",
    run_id: "123",
    runner_environment: "github-hosted",
    sha: WORKFLOW_SHA,
    workflow_ref: CONTROLLER_WORKFLOW_REF,
    workflow_sha: WORKFLOW_SHA,
    ...overrides,
  };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: "JWT" })
    .setIssuer(TRUST.issuer)
    .setAudience(TRUST.routes.ledger.audience)
    .setSubject(
      `repo:PaulKov@${OWNER_ID}/dpone-release-controller@${TRUST.controllerRepositoryId}:environment:release-attest`,
    )
    .setJti(crypto.randomUUID())
    .setIssuedAt(now)
    .setNotBefore(now - 1)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

function activation(): ActivationTrust {
  return {
    activatedDigest: `sha256:${"a".repeat(64)}`,
    activatedRecordId: `sha256:${"b".repeat(64)}`,
    controllerActionBundleSha256: `sha256:${"f".repeat(64)}`,
    controllerActionCommitSha: "f".repeat(40),
    controllerActionMetadataBlobSha: "e".repeat(40),
    controllerActorIds: new Set(["123456789"]),
    controllerDefaultBranchWorkflowBlobSha: "d".repeat(40),
    controllerWorkflowBlobSha: "d".repeat(40),
    controllerWorkflowId: 987_654_321,
    controllerRef: CONTROLLER_REF,
    controllerRefType: "tag",
    controllerTagObjectSha: "a".repeat(40),
    controllerWorkflowRef: CONTROLLER_WORKFLOW_REF,
    controllerWorkflowSha: WORKFLOW_SHA,
    controllerRunReaderApp: {
      appId: "101",
      appSlug: "controller-reader",
      installationId: "202",
    },
    provisionedDigest: `sha256:${"c".repeat(64)}`,
    provisionedRecordId: `sha256:${"d".repeat(64)}`,
    privateServices: {
      attestationMutator: servicePin("attestation"),
      candidateReader: servicePin("candidate"),
      closedProjector: servicePin("closed"),
      cloudflareDeploymentObserver: servicePin("cloudflare-observer"),
      controllerRunReader: servicePin("controller"),
      governanceReader: servicePin("governance"),
      pypiDeploymentGate: servicePin("pypi-gate"),
      pypiReader: servicePin("pypi-reader"),
      releaseMutator: servicePin("release"),
      runtimeDeploymentGate: servicePin("runtime-gate"),
      tenantScanner: servicePin("tenant-scanner"),
      wormMirror: servicePin("worm"),
      wormVersionObserver: servicePin("observer"),
    },
    repositoryOwnerId: OWNER_ID,
    runtimeActorIds: new Set(["123456789"]),
    targetBranchRulesetEvidenceSha256: `sha256:${"f".repeat(64)}`,
    targetBranchRulesetId: "987654321",
    targetBranchRulesetProjectionSha256: `sha256:${"a".repeat(64)}`,
    targetDefaultBranchRef: "refs/heads/master",
    targetPolicyBlobSha: "e".repeat(40),
    targetPolicyCommitSha: "b".repeat(40),
    targetPolicySha256: `sha256:${"e".repeat(64)}`,
    targetRuntimeWorkflowBlobSha: "c".repeat(40),
    targetRuntimeWorkflowSha256: `sha256:${"d".repeat(64)}`,
    workerVersionId: "worker-version-test-0001",
  };
}

function servicePin(name: string) {
  const serviceName = `test-${name}-worker`;
  const versionId = `test-${name}-version-0001`;
  return {
    serviceIdentity: `cloudflare-worker:test-account/${serviceName}@${versionId}`,
    serviceName,
    versionId,
  };
}
