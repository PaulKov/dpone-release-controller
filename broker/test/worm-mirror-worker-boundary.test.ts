import { describe, expect, it } from "vitest";

import { canonicalBytes, digestObject, sha256Hex } from "../src/canonical";
import {
  CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES,
} from "../src/cloudflare-evidence-batch-resume-v2";
import type { JsonObject } from "../src/types";
import wormMirrorWorker from "../src/private/worm-mirror-worker";
import { assertExpectedCallee } from "../src/private/worm-mirror-worker-helpers";
import { signWormRpcRequest, type WormRpcCallerAuth } from "../src/worm-rpc-auth";
import {
  CALLER,
  OBSERVER,
  PIN,
  WORM_VERSION,
  calleeHeaders,
  decodeBase64url,
  encodeBase64url,
  fetchEvidenceWorker,
  objectAt,
  retainableEvidence,
  retainableRulesetEvidence,
  uuid,
  workerEnv,
} from "./worm-mirror-boundary.fixtures";

describe("WORM pre-side-effect version boundary", () => {
  it("rejects an unsigned provider-evidence caller before reading the body or B2 config", async () => {
    const response = await wormMirrorWorker.fetch(
      new Request("https://worm-mirror.internal/rpc/v1/activation-evidence", {
        body: "{}",
        headers: {
          ...Object.fromEntries(calleeHeaders()),
          "content-length": "2",
          "content-type": "application/json",
          "x-dpone-ingress-worker-version": CALLER.versionId,
          "x-request-id": "request-worm-evidence-0001",
        },
        method: "POST",
      }),
      workerEnv(PIN.versionId),
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: {
        code: "WORM_RPC_AUTH_INVALID",
        request_id: "request-worm-evidence-0001",
        retryable: false,
      },
    });
  });

  it("rejects a signed raw capability before reading B2 configuration", async () => {
    const response = await fetchEvidenceWorker(
      await retainableEvidence({ authorizationToken: "provider-secret" }),
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "UNKNOWN_FIELD", retryable: false },
    });
  });

  it("admits only exact signed evidence through validation before requiring B2 secrets", async () => {
    const response = await fetchEvidenceWorker(await retainableEvidence());
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "B2_SECRET_UNAVAILABLE", retryable: false },
    });
  });

  it("independently reprojects bounded branch-ruleset bytes before any B2 effect", async () => {
    const response = await fetchEvidenceWorker(
      await retainableRulesetEvidence(),
      "github_branch_ruleset",
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "B2_SECRET_UNAVAILABLE", retryable: false },
    });

    const drift = await retainableRulesetEvidence();
    const encodedRaw = drift.raw_response_base64url;
    if (typeof encodedRaw !== "string") throw new Error("missing ruleset raw evidence");
    const raw = JSON.parse(new TextDecoder().decode(decodeBase64url(encodedRaw))) as JsonObject;
    const status = objectAt(raw.rules, 3);
    (status.parameters as JsonObject).strict_required_status_checks_policy = false;
    const driftRaw = canonicalBytes(raw);
    drift.raw_response_base64url = encodeBase64url(driftRaw);
    drift.raw_response_sha256 = `sha256:${await sha256Hex(driftRaw)}`;
    const unsigned = { ...drift };
    delete unsigned.observation_sha256;
    drift.observation_sha256 = await digestObject(unsigned);
    const rejected = await fetchEvidenceWorker(drift, "github_branch_ruleset");
    expect(rejected.status).toBe(500);
    await expect(rejected.json()).resolves.toMatchObject({
      error: { code: "RAW_EVIDENCE_PROJECTION_MISMATCH", retryable: false },
    });
  });

  it("accepts only the exact callee identity and current immutable version", () => {
    const headers = calleeHeaders();
    expect(() => assertExpectedCallee(headers, workerEnv(PIN.versionId))).not.toThrow();

    for (const changed of [
      { header: "x-dpone-callee-version", value: uuid(9999) },
      { header: "x-dpone-callee-service", value: "attacker-service" },
      {
        header: "x-dpone-callee-service-identity",
        value: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/attacker-service@${WORM_VERSION}`,
      },
    ]) {
      const forged = calleeHeaders();
      forged.set(changed.header, changed.value);
      expect(() => assertExpectedCallee(forged, workerEnv(PIN.versionId))).toThrow();
    }
    expect(() => assertExpectedCallee(headers, workerEnv(uuid(9999)))).toThrow(
      "PRIVATE_SERVICE_VERSION_FALLBACK",
    );
  });

  it("rejects an unauthenticated activation caller before reading config or touching B2", async () => {
    const response = await wormMirrorWorker.fetch(
      new Request("https://worm-mirror.internal/rpc/v1/activation", {
        body: "{}",
        headers: {
          ...Object.fromEntries(calleeHeaders()),
          "content-length": "2",
          "content-type": "application/json",
          "x-dpone-ingress-worker-version": CALLER.versionId,
        },
        method: "POST",
      }),
      workerEnv(PIN.versionId),
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "WORM_RPC_AUTH_INVALID", retryable: false },
    });
  });

  it("enforces the dedicated v2 resume request cap before decoding or DO lookup", async () => {
    const exact = await fetchResumeSized(MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES);
    expect(exact.status).not.toBe(413);
    await expect(exact.json()).resolves.not.toMatchObject({
      error: { code: "MIRROR_BODY_SIZE_INVALID" },
    });

    const oversized = await fetchResumeSized(MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES + 1);
    expect(oversized.status).toBe(413);
    await expect(oversized.json()).resolves.toMatchObject({
      error: { code: "MIRROR_BODY_SIZE_INVALID", retryable: false },
    });
  });
});

async function fetchResumeSized(size: number): Promise<Response> {
  const caller: WormRpcCallerAuth = {
    key: "A".repeat(43),
    serviceIdentity:
      "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/" +
      `dpone-release-cloudflare-deployment-observer@${CALLER.versionId}`,
    versionId: CALLER.versionId,
  };
  const empty = canonicalBytes({ padding: "" });
  const bytes = canonicalBytes({ padding: "x".repeat(size - empty.byteLength) });
  expect(bytes).toHaveLength(size);
  const headers = new Headers({
    ...Object.fromEntries(calleeHeaders()),
    "content-length": String(bytes.byteLength),
    "content-type": "application/json",
    "x-dpone-batch-id": `sha256:${"1".repeat(64)}`,
    "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
    "x-dpone-cloudflare-observer-worker-version": caller.versionId,
    "x-dpone-observer-service": OBSERVER.serviceName,
    "x-dpone-observer-service-identity": OBSERVER.serviceIdentity,
    "x-dpone-observer-version": OBSERVER.versionId,
    "x-request-id": "request-worm-resume-v2-0001",
  });
  await signWormRpcRequest(headers, CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2, caller);
  return wormMirrorWorker.fetch(
    new Request(`https://worm-mirror.internal${CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2}`, {
      body: Uint8Array.from(bytes).buffer,
      headers,
      method: "POST",
    }),
    {
      ...workerEnv(PIN.versionId),
      CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: caller.key,
      WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY: caller.serviceIdentity,
    },
  );
}
