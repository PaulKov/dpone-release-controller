import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import { readBoundedBytes } from "../src/bounded";
import { TRUST } from "../src/config";
import { digestDomain } from "../src/identity";
import type { AuthenticatedWorkflow, JsonObject } from "../src/types";
import identityFixture from "./fixtures/release-identity-v2-golden.json";
import {
  exactObject,
  parseJsonObject,
  parseReleaseBinding,
  requireString,
  verifyReleaseBinding,
} from "../src/validation";

const WORKFLOW_SHA = "c".repeat(40);
const CONTROLLER_REF = "refs/tags/v1.0.0";
const CONTROLLER_WORKFLOW_REF = `${TRUST.controllerRepository}/${TRUST.controllerWorkflowPath}@${CONTROLLER_REF}`;
const WORKFLOW_ID = identityFixture.attempt.payload.controller_workflow_id;

describe("strict request validation", () => {
  it("accepts only exact canonical request bytes", async () => {
    const value = { alpha: 1, beta: "ok" };
    const request = jsonRequest(canonicalJson(value));
    await expect(parseJsonObject(request)).resolves.toEqual(value);
  });

  it("rejects duplicate keys and formatting aliases", async () => {
    await expect(parseJsonObject(jsonRequest('{"alpha":1,"alpha":1}'))).rejects.toThrowError(
      "BODY_NOT_CANONICAL",
    );
    await expect(parseJsonObject(jsonRequest('{"alpha": 1}'))).rejects.toThrowError(
      "BODY_NOT_CANONICAL",
    );
  });

  it("cancels a body that exceeds the streaming limit", async () => {
    const body = new Uint8Array(65_537).fill(0x20);
    const request = new Request("https://broker.invalid/v1/test", {
      body,
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    await expect(parseJsonObject(request)).rejects.toThrowError("BODY_TOO_LARGE");
  });

  it("rejects non-decimal Content-Length spellings", async () => {
    for (const length of ["1e3", " 2", "+2", "02", "2 "]) {
      // Fetch Request normalizes this forbidden transport header, so use the
      // exact Request surface Workers passes to the validator.
      const request = {
        body: new Response("{}").body,
        headers: {
          get(name: string): string | null {
            if (name.toLowerCase() === "content-length") return length;
            if (name.toLowerCase() === "content-type") return "application/json";
            return null;
          },
        } as Headers,
      } as Request;
      await expect(parseJsonObject(request), length).rejects.toThrowError("CONTENT_LENGTH_INVALID");
    }
  });

  it("requires the declared Content-Length to match the exact stream EOF", async () => {
    for (const [declared, body] of [
      ["2", new Uint8Array([1])],
      ["1", new Uint8Array([1, 2])],
    ] as const) {
      await expect(
        readBoundedBytes(
          { body: new Response(body).body, headers: new Headers({ "content-length": declared }) },
          8,
          "TEST_BODY",
        ),
      ).rejects.toThrow("TEST_BODY_CONTENT_LENGTH_MISMATCH");
    }
    await expect(
      readBoundedBytes(
        { body: null, headers: new Headers({ "content-length": "1" }) },
        8,
        "TEST_BODY",
      ),
    ).rejects.toThrow("TEST_BODY_CONTENT_LENGTH_MISMATCH");
  });

  it("does not let JavaScript dollar anchors accept a trailing newline", () => {
    const object: JsonObject = { id: "123\n" };
    expect(() => requireString(object, "id", 32, /^[1-9][0-9]*$/u)).toThrowError("FIELD_INVALID");
  });

  it("rejects duplicate fields in every closed schema declaration", () => {
    expect(() => exactObject({ alpha: 1 }, ["alpha", "alpha"])).toThrowError(
      "SCHEMA_FIELD_DECLARATION_DUPLICATE",
    );
  });

  it("recomputes every derived release identity", async () => {
    const raw = await validBinding();
    const binding = parseReleaseBinding(raw);
    expect(binding).toMatchObject({
      candidateArtifactId: 456,
      candidateRunId: 789,
      runId: 123,
    });
    await expect(
      verifyReleaseBinding(binding, auth(), {
        id: WORKFLOW_ID,
        sha: WORKFLOW_SHA,
      }),
    ).resolves.toBeUndefined();

    raw.release_identity_id = `sha256:${"9".repeat(64)}`;
    const tampered = parseReleaseBinding(raw);
    await expect(
      verifyReleaseBinding(tampered, auth(), {
        id: WORKFLOW_ID,
        sha: WORKFLOW_SHA,
      }),
    ).rejects.toThrowError("RELEASE_IDENTITY_ID_MISMATCH");
  });

  it("matches the Python-produced identity-domain vector exactly", async () => {
    for (const vector of [
      identityFixture.release,
      identityFixture.authority,
      identityFixture.attempt,
      identityFixture.candidate,
    ]) {
      await expect(digestDomain(vector.domain, vector.payload)).resolves.toBe(vector.id);
    }
  });

  it("rejects legacy field aliases and project reordering by identity", async () => {
    const exact = identityFixture.release;
    await expect(
      digestDomain(exact.domain, { ...exact.payload, release: undefined } as unknown as JsonObject),
    ).rejects.toThrowError();
    await expect(
      digestDomain(exact.domain, {
        ...exact.payload,
        projects: [...exact.payload.projects].reverse(),
      }),
    ).resolves.not.toBe(exact.id);
    await expect(
      digestDomain(exact.domain, {
        projects: exact.payload.projects,
        repository_id: exact.payload.repository_id,
        tag: exact.payload.release,
      }),
    ).resolves.not.toBe(exact.id);
  });

  it("rejects prerelease tags, bare digests, uppercase digests, zero IDs and lightweight tags", async () => {
    const cases: [string, string | number][] = [
      ["tag", "v1.2.3-rc.1"],
      ["policy_sha256", "d".repeat(64)],
      ["policy_sha256", `sha256:${"D".repeat(64)}`],
      ["candidate_artifact_id", "0"],
      ["tag_object_sha", "b".repeat(40)],
    ];
    for (const [field, value] of cases) {
      const raw = await validBinding();
      raw[field] = value;
      expect(() => parseReleaseBinding(raw), field).toThrowError();
    }
  });

  it("rejects unsafe, boolean and noncanonical GitHub numeric IDs", async () => {
    for (const field of ["candidate_artifact_id", "candidate_run_id", "run_id"] as const) {
      for (const value of [String(Number.MAX_SAFE_INTEGER + 1), "01", "0", true]) {
        const raw = await validBinding();
        raw[field] = value;
        expect(() => parseReleaseBinding(raw), `${field}=${String(value)}`).toThrowError();
      }
    }
  });
});

async function validBinding(): Promise<JsonObject> {
  const tag = "v0.74.0";
  const policy = `sha256:${"d".repeat(64)}`;
  const releaseIdentity = await digestDomain("dpone.release.identity.v2", {
    projects: [
      "apache-airflow-providers-dpone",
      "dpone",
      "dpone-airflow-pack",
      "dpone-native-accel",
    ],
    release: tag,
    repository_id: TRUST.targetRepositoryId,
  });
  const releaseAuthority = await digestDomain("dpone.release.authority.v2", {
    peeled_commit_sha: "b".repeat(40),
    policy_sha256: policy,
    protected_base_ref: "refs/heads/master",
    release_identity_id: releaseIdentity,
    tag_object_sha: "a".repeat(40),
  });
  const attempt = await digestDomain("dpone.release.attempt.v2", {
    controller_repository_id: TRUST.controllerRepositoryId,
    controller_run_attempt: 1,
    controller_run_id: 123,
    controller_workflow_id: WORKFLOW_ID,
    release_authority_id: releaseAuthority,
  });
  const inventory = `sha256:${"1".repeat(64)}`;
  const candidate = await digestDomain("dpone.release.candidate.v2", {
    candidate_inventory_sha256: inventory,
    release_authority_id: releaseAuthority,
  });
  return {
    attempt_id: attempt,
    candidate_artifact_digest: `sha256:${"f".repeat(64)}`,
    candidate_artifact_id: "456",
    candidate_id: candidate,
    candidate_inventory_sha256: inventory,
    candidate_manifest_digest: `sha256:${"e".repeat(64)}`,
    candidate_run_attempt: 1,
    candidate_run_id: "789",
    controller_repo_id: TRUST.controllerRepositoryId,
    controller_workflow_id: WORKFLOW_ID,
    controller_workflow_sha: WORKFLOW_SHA,
    peeled_commit_sha: "b".repeat(40),
    policy_sha256: policy,
    release_authority_id: releaseAuthority,
    release_identity_id: releaseIdentity,
    run_attempt: 1,
    run_id: "123",
    tag,
    tag_object_sha: "a".repeat(40),
    tag_ref: `refs/tags/${tag}`,
    target_repo_id: TRUST.targetRepositoryId,
  };
}

function auth(): AuthenticatedWorkflow {
  return {
    actorId: "123456789",
    audience: TRUST.routes.ledger.audience,
    checkRunId: "9001",
    environment: TRUST.routes.ledger.environment,
    expiresAt: 2_000_000_000,
    issuedAt: 1_999_999_700,
    jti: "12345678-1234-1234-1234-123456789012",
    notBefore: 1_999_999_690,
    ref: CONTROLLER_REF,
    repository: TRUST.controllerRepository,
    repositoryId: TRUST.controllerRepositoryId,
    repositoryOwnerId: "123456789",
    runAttempt: 1,
    runId: "123",
    sha: WORKFLOW_SHA,
    subject: "unused-in-derived-binding-test",
    workflowRef: CONTROLLER_WORKFLOW_REF,
    workflowSha: WORKFLOW_SHA,
  };
}

function jsonRequest(body: BodyInit): Request {
  return new Request("https://broker.invalid/v1/test", {
    body,
    headers: { "content-type": "application/json" },
    method: "POST",
  });
}
