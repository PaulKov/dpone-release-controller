import { describe, expect, it } from "vitest";

import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
} from "../src/activated-authority-head";
import { buildCurrentHeadProof } from "../src/activated-authority-head-proof";
import { activationProofIntentDigest, buildActivationProof } from "../src/activation-proof";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type {
  ActivationSnapshot,
  ActivationTrust,
  AuthenticatedWorkflow,
  JsonObject,
} from "../src/types";

describe("activation admission proof", () => {
  it("emits canonical whole-second UTC bounds and the immutable controller tag authority", async () => {
    const activationSnapshot = snapshot();
    const proof = await buildActivationProof({
      activation: activation(),
      activatedAuthorityHead: await currentHead(activationSnapshot),
      auth: authentication(),
      nowMs: Date.parse("2026-08-15T12:00:00Z") + 987,
      observation: {
        defaultBranchRef: "refs/heads/master",
        defaultBranchWorkflowBlobSha: "f".repeat(40),
        defaultBranchWorkflowObservationSha256: tagged("9"),
        digest: tagged("8"),
        jobName: "admit",
      },
      requestId: "activation-proof-request-0001",
      snapshot: activationSnapshot,
    });

    expect(proof.admitted_at).toBe("2026-08-15T12:00:00Z");
    expect(proof.expires_at).toBe("2026-08-15T12:01:00Z");
    expect(proof.controller).toEqual({
      default_branch_ref: "refs/heads/master",
      default_branch_workflow_blob_sha: "f".repeat(40),
      default_branch_workflow_observation_sha256: tagged("9"),
      ref: "refs/tags/v1.0.0",
      ref_type: "tag",
      repository_id: 1_305_993_853,
      run_attempt: 2,
      run_id: 123,
      tag_object_sha: "a".repeat(40),
      workflow_id: 987_654_321,
      workflow_ref:
        "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
      workflow_sha: "c".repeat(40),
    });
    expect((proof.provisioned as JsonObject).controller_workflow_id).toBe(987_654_321);
    expect(proof.activated).toMatchObject({
      controller_action_bundle_sha256: tagged("a"),
      controller_action_commit_sha: "d".repeat(40),
      controller_action_metadata_blob_sha: "e".repeat(40),
    });
    expect(proof.provisioned).toMatchObject({
      controller_action_bundle_sha256: tagged("a"),
      controller_action_commit_sha: "d".repeat(40),
      controller_action_metadata_blob_sha: "e".repeat(40),
    });
    expect((proof.activated_authority_head as JsonObject).request_id).toBe(
      "activation-proof-request-0001",
    );
    const unsigned = { ...proof };
    delete unsigned.proof_sha256;
    expect(proof.proof_sha256).toBe(`sha256:${await sha256Hex(canonicalBytes(unsigned))}`);
  });

  it("rejects a fresh but differently addressed global-head proof", async () => {
    const activationSnapshot = snapshot();
    await expect(
      buildActivationProof({
        activation: activation(),
        activatedAuthorityHead: await currentHead(
          activationSnapshot,
          "different-head-request-0001",
        ),
        auth: authentication(),
        nowMs: Date.parse("2026-08-15T12:00:00Z"),
        observation: {
          defaultBranchRef: "refs/heads/master",
          defaultBranchWorkflowBlobSha: "f".repeat(40),
          defaultBranchWorkflowObservationSha256: tagged("9"),
          digest: tagged("8"),
          jobName: "admit",
        },
        requestId: "activation-proof-request-0001",
        snapshot: activationSnapshot,
      }),
    ).rejects.toThrow("ACTIVATION_PROOF_HEAD_MISMATCH");
  });

  it("rejects a replayed head read that became stale during admission", async () => {
    const activationSnapshot = snapshot();
    const staleHead = await currentHead(activationSnapshot, "activation-proof-request-0001", true);

    await expect(
      buildActivationProof({
        activation: activation(),
        activatedAuthorityHead: staleHead,
        auth: authentication(),
        nowMs: Date.parse("2026-08-15T12:00:00Z"),
        observation: {
          defaultBranchRef: "refs/heads/master",
          defaultBranchWorkflowBlobSha: "f".repeat(40),
          defaultBranchWorkflowObservationSha256: tagged("9"),
          digest: tagged("8"),
          jobName: "admit",
        },
        requestId: "activation-proof-request-0001",
        snapshot: activationSnapshot,
      }),
    ).rejects.toThrow("ACTIVATION_PROOF_HEAD_MISMATCH");
  });

  it("keeps the recovery intent stable across fresh transport tokens", async () => {
    const first = authentication();
    const refreshed = {
      ...first,
      expiresAt: first.expiresAt + 60,
      issuedAt: first.issuedAt + 60,
      jti: "oidc-jti-0000000000000002",
      notBefore: first.notBefore + 60,
    };
    const observation = {
      defaultBranchRef: "refs/heads/master",
      defaultBranchWorkflowBlobSha: "f".repeat(40),
      defaultBranchWorkflowObservationSha256: tagged("9"),
      digest: tagged("8"),
      jobName: "admit" as const,
    } as const;
    await expect(activationProofIntentDigest(first, observation, snapshot())).resolves.toBe(
      await activationProofIntentDigest(refreshed, observation, snapshot()),
    );
    await expect(
      activationProofIntentDigest({ ...refreshed, runAttempt: 3 }, observation, snapshot()),
    ).resolves.not.toBe(await activationProofIntentDigest(first, observation, snapshot()));
  });
});

const INGRESS_VERSION = "123e4567-e89b-42d3-a456-426614174000";

function activation(): ActivationTrust {
  return {
    activatedDigest: tagged("1"),
    activatedRecordId: tagged("2"),
    controllerActionBundleSha256: tagged("a"),
    controllerActionCommitSha: "d".repeat(40),
    controllerActionMetadataBlobSha: "e".repeat(40),
    controllerActorIds: new Set(["74862786"]),
    controllerDefaultBranchWorkflowBlobSha: "b".repeat(40),
    controllerRef: "refs/tags/v1.0.0",
    controllerRefType: "tag",
    controllerTagObjectSha: "a".repeat(40),
    controllerWorkflowBlobSha: "b".repeat(40),
    controllerWorkflowId: 987_654_321,
    controllerRunReaderApp: {
      appId: "101",
      appSlug: "controller-reader",
      installationId: "202",
    },
    controllerWorkflowRef:
      "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
    controllerWorkflowSha: "c".repeat(40),
    privateServices: {
      attestationMutator: pin("attestation"),
      candidateReader: pin("candidate"),
      closedProjector: pin("closed"),
      cloudflareDeploymentObserver: pin("cloudflare-observer"),
      controllerRunReader: pin("controller-run"),
      governanceReader: pin("governance"),
      pypiDeploymentGate: pin("pypi-gate"),
      pypiReader: pin("pypi-reader"),
      releaseMutator: pin("release"),
      runtimeDeploymentGate: pin("runtime-gate"),
      tenantScanner: pin("tenant-scanner"),
      wormMirror: pin("worm"),
      wormVersionObserver: pin("observer"),
    },
    provisionedDigest: tagged("3"),
    provisionedRecordId: tagged("4"),
    repositoryOwnerId: "74862786",
    runtimeActorIds: new Set(["74862786"]),
    targetBranchRulesetEvidenceSha256: tagged("7"),
    targetBranchRulesetId: "987654321",
    targetBranchRulesetProjectionSha256: tagged("8"),
    targetDefaultBranchRef: "refs/heads/master",
    targetPolicyBlobSha: "d".repeat(40),
    targetPolicyCommitSha: "e".repeat(40),
    targetPolicySha256: tagged("5"),
    targetRuntimeWorkflowBlobSha: "f".repeat(40),
    targetRuntimeWorkflowSha256: tagged("6"),
    workerVersionId: INGRESS_VERSION,
  };
}

function authentication(): AuthenticatedWorkflow {
  return {
    actorId: "74862786",
    audience: "dpone-release-controller-ledger-write",
    checkRunId: "456",
    environment: "release-attest",
    expiresAt: 2_000_000_300,
    issuedAt: 2_000_000_000,
    jti: "oidc-jti-0000000000000001",
    notBefore: 1_999_999_999,
    ref: "refs/tags/v1.0.0",
    repository: "PaulKov/dpone-release-controller",
    repositoryId: 1_305_993_853,
    repositoryOwnerId: "74862786",
    runAttempt: 2,
    runId: "123",
    sha: "c".repeat(40),
    subject: "test-subject",
    workflowRef:
      "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
    workflowSha: "c".repeat(40),
  };
}

function snapshot(): ActivationSnapshot {
  const provisionedWorm = {
    digest: tagged("6"),
    key: "receipts/v1/activation/test.json",
    retentionUntil: "2033-08-15T12:00:00Z",
    versionId: "worm-version-0000000001",
  };
  const activatedDigest = tagged("1");
  return {
    activated: {
      digest: activatedDigest,
      envelope: {
        committed_at: "2026-08-15T11:57:55.000Z",
        previous: tagged("4"),
        service_authorities: {
          a1_precommit_observation: authorityObservation(),
          expectation_sha256: tagged("7"),
        },
      },
      recordId: tagged("2"),
      sequence: 1,
      worm: {
        digest: activatedDigest,
        key: `receipts/v1/activation/${INGRESS_VERSION}/1-${activatedDigest.slice(7)}.json`,
        retentionUntil: "2033-08-15T12:00:00.000Z",
        versionId: "worm-version-0000000002",
      },
    },
    provisioned: {
      digest: tagged("3"),
      envelope: {},
      recordId: tagged("4"),
      sequence: 0,
      worm: provisionedWorm,
    },
  };
}

async function currentHead(
  activationSnapshot: ActivationSnapshot,
  requestId = "activation-proof-request-0001",
  stale = false,
): Promise<JsonObject> {
  const activated = activationSnapshot.activated;
  if (activated === null) throw new Error("activated fixture required");
  const head = await buildActivatedAuthorityHead({
    activatedRecordId: activated.recordId,
    activatedRecordSha256: activated.digest,
    activatedServiceAuthoritiesSha256: tagged("7"),
    activatedWorm: activated.worm,
    committedAt: stale ? "2026-08-15T11:57:58.000Z" : "2026-08-15T11:59:58.000Z",
    generation: 1,
    ingressWorkerVersionId: INGRESS_VERSION,
    previous: "GENESIS",
  });
  return buildCurrentHeadProof({
    brokerAcceptedAt: stale ? "2026-08-15T11:58:00.500Z" : "2026-08-15T11:59:59.500Z",
    head,
    observedAt: stale ? "2026-08-15T11:58:00.250Z" : "2026-08-15T11:59:59.250Z",
    requestId,
    requestedAt: stale ? "2026-08-15T11:58:00.000Z" : "2026-08-15T11:59:59.000Z",
    worm: {
      digest: await activatedAuthorityHeadRecordSha256(head),
      key: await activatedAuthorityHeadKey(head),
      retentionUntil: "2034-08-15T12:00:00.000Z",
      versionId: "head-worm-version-0001",
    },
  });
}

function authorityObservation(): JsonObject {
  return {
    broker_accepted_at: "2026-08-15T11:59:57.000Z",
    cloudflare_provider_observation_sha256: tagged("5"),
    expectation_sha256: tagged("7"),
    network_surface: {},
    observed_at: "2026-08-15T11:59:56.000Z",
    observer_service_identity: "cloudflare-worker:test/observer@version",
    observer_worker_version_id: "00000000-0000-0000-0000-000000000099",
    phase: "A1_PRECOMMIT",
    provider_observation_sha256: tagged("7"),
    schema: "dpone.service-authority-observation.v1",
    schema_version: 1,
    services: [],
  };
}

function pin(name: string) {
  const serviceName = `test-${name}-worker`;
  const versionId = `test-${name}-version-0001`;
  return {
    serviceIdentity: `cloudflare-worker:test-account/${serviceName}@${versionId}`,
    serviceName,
    versionId,
  };
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
