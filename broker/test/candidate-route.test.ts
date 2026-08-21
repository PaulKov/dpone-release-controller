import { describe, expect, it } from "vitest";

import { CandidateStreamRoute } from "../src/candidate-route";
import { CANDIDATE_STREAM_REQUEST_SCHEMA } from "../src/candidate-stream";
import { canonicalJson } from "../src/canonical";
import { BrokerError } from "../src/errors";
import type { AuthenticatedWorkflow, JsonObject } from "../src/types";
import { CANDIDATE_ZIP } from "./support/candidate-provider-fixture";
import {
  CANDIDATE_READER_PIN,
  asCandidateReaderStream,
  candidateServiceFixture,
} from "./support/candidate-reader-service-fixture";

describe("candidate public admission orchestration", () => {
  it("cross-checks the active job and consumes the global JTI before provider access", async () => {
    const fixture = await candidateServiceFixture();
    const calls: string[] = [];
    let consumedDigest = "";
    const route = new CandidateStreamRoute(
      {
        async authenticate() {
          calls.push("authenticate");
          return authentication();
        },
        async consumeReplay(_auth, requestId, claimsDigest) {
          calls.push("consume-replay");
          expect(requestId).toBe(fixture.input.requestId);
          consumedDigest = claimsDigest;
        },
        async observeController() {
          calls.push("observe-controller");
          return controllerObservation();
        },
        async openCandidate(input, authority) {
          calls.push("open-candidate");
          expect(input).toEqual(fixture.input);
          expect(authority).toEqual(fixture.authority);
          return asCandidateReaderStream(fixture);
        },
      },
      CANDIDATE_READER_PIN,
      fixture.authority,
    );

    const response = await route.handle(candidateRequest(fixture), fixture.input.requestId);
    expect(calls).toEqual([
      "authenticate",
      "observe-controller",
      "consume-replay",
      "open-candidate",
    ]);
    expect(consumedDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(CANDIDATE_ZIP);
    expect(response.headers.has("authorization")).toBe(false);
    expect(response.headers.has("location")).toBe(false);
  });

  it("does not call the candidate provider after a replay failure", async () => {
    const fixture = await candidateServiceFixture();
    let opened = false;
    const route = new CandidateStreamRoute(
      {
        async authenticate() {
          return authentication();
        },
        async consumeReplay() {
          throw new BrokerError("OIDC_REPLAY", 409, false);
        },
        async observeController() {
          return controllerObservation();
        },
        async openCandidate() {
          opened = true;
          return asCandidateReaderStream(fixture);
        },
      },
      CANDIDATE_READER_PIN,
      fixture.authority,
    );
    await expect(route.handle(candidateRequest(fixture), fixture.input.requestId)).rejects.toThrow(
      "OIDC_REPLAY",
    );
    expect(opened).toBe(false);
  });

  it("rejects route and transport drift before OIDC or provider calls", async () => {
    const fixture = await candidateServiceFixture();
    let authenticated = false;
    const route = new CandidateStreamRoute(
      {
        async authenticate() {
          authenticated = true;
          return authentication();
        },
        async consumeReplay() {
          await Promise.resolve();
        },
        async observeController() {
          return controllerObservation();
        },
        async openCandidate() {
          return asCandidateReaderStream(fixture);
        },
      },
      CANDIDATE_READER_PIN,
      fixture.authority,
    );
    for (const request of [
      candidateRequest(fixture, { path: "/v1/providers/github/other" }),
      candidateRequest(fixture, { query: "?all=true" }),
      candidateRequest(fixture, { method: "GET" }),
      candidateRequest(fixture, { accept: "application/zip" }),
    ]) {
      await expect(route.handle(request, fixture.input.requestId)).rejects.toThrow();
    }
    expect(authenticated).toBe(false);
  });
});

function candidateRequest(
  fixture: Awaited<ReturnType<typeof candidateServiceFixture>>,
  overrides: {
    readonly accept?: string;
    readonly method?: string;
    readonly path?: string;
    readonly query?: string;
  } = {},
): Request {
  const body: JsonObject = {
    candidate_artifact_digest: fixture.input.artifactDigest,
    candidate_artifact_id: fixture.input.artifactId,
    candidate_run_attempt: fixture.input.runAttempt,
    candidate_run_id: fixture.input.runId,
    expected_peeled_commit_sha: fixture.input.peeledCommitSha,
    schema: CANDIDATE_STREAM_REQUEST_SCHEMA,
    schema_version: 1,
    tag: fixture.input.release,
  };
  const method = overrides.method ?? "POST";
  const init: RequestInit = {
    headers: {
      accept: overrides.accept ?? "application/vnd.dpone.release-candidate-artifact.v1+zip",
      authorization: "Bearer synthetic-fresh-oidc",
      "content-type": "application/json",
      "x-request-id": fixture.input.requestId,
    },
    method,
  };
  if (method !== "GET") init.body = canonicalJson(body);
  return new Request(
    `https://broker.invalid${overrides.path ?? "/v1/providers/github/candidate"}${overrides.query ?? ""}`,
    init,
  );
}

function authentication(): AuthenticatedWorkflow {
  return {
    actorId: "74862786",
    audience: "dpone-release-controller-candidate-read",
    checkRunId: "456",
    environment: "release-attest",
    expiresAt: 2_000_000_060,
    issuedAt: 2_000_000_000,
    jti: "candidate-oidc-jti-00000001",
    notBefore: 1_999_999_999,
    ref: "refs/tags/v1.0.0",
    repository: "PaulKov/dpone-release-controller",
    repositoryId: 1_305_993_853,
    repositoryOwnerId: "74862786",
    runAttempt: 2,
    runId: "123",
    sha: "c".repeat(40),
    subject: "immutable-controller-subject",
    workflowRef:
      "PaulKov/dpone-release-controller/.github/workflows/release-controller.yml@refs/tags/v1.0.0",
    workflowSha: "c".repeat(40),
  };
}

function controllerObservation() {
  return {
    defaultBranchRef: "refs/heads/master" as const,
    defaultBranchWorkflowBlobSha: "f".repeat(40),
    defaultBranchWorkflowObservationSha256: tagged("8"),
    digest: tagged("9"),
    jobName: "candidate-import",
  };
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
