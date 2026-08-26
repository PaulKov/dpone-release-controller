import { describe, expect, it } from "vitest";

import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
  parseActivatedAuthorityHead,
} from "../src/activated-authority-head";
import {
  ACTIVATED_AUTHORITY_HEAD_CURRENT_SCHEMA,
  ACTIVATED_AUTHORITY_HEAD_READ_REQUEST_SCHEMA,
  assertCurrentHeadMatchesRequest,
  buildCurrentHeadProof,
  parseCurrentHeadProof,
  parseHeadReadRequest,
} from "../src/activated-authority-head-proof";
import type { ActivationWorm, JsonObject } from "../src/types";

describe("global activated service-authority head", () => {
  it("derives generation-one self id, full digest and generation-specific key", async () => {
    const head = await headOne();
    const fullDigest = await activatedAuthorityHeadRecordSha256(head);

    await expect(parseActivatedAuthorityHead(head)).resolves.toEqual(head);
    expect(await activatedAuthorityHeadKey(head)).toBe(
      `receipts/v1/activation-head/generations/00000000000000000001-${fullDigest.slice(7)}.json`,
    );
    expect((head.activated as JsonObject).worm).toEqual(activationWormJson());
  });

  it("requires generation two to link the exact prior self id and full digest", async () => {
    const prior = await headOne();
    const priorDigest = await activatedAuthorityHeadRecordSha256(prior);
    const next = await buildActivatedAuthorityHead({
      ...input(2),
      previous: {
        generation: 1,
        record_id: prior.record_id ?? null,
        record_sha256: priorDigest,
      },
    });

    await expect(parseActivatedAuthorityHead(next)).resolves.toEqual(next);
    await expect(
      buildActivatedAuthorityHead({
        ...input(2),
        previous: {
          generation: 2,
          record_id: prior.record_id ?? null,
          record_sha256: priorDigest,
        },
      }),
    ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_PREVIOUS_INVALID");
  });

  it("rejects flattened aliases, tampered ids and non-exact A1 WORM keys", async () => {
    const head = await headOne();
    const flattened = {
      ...head,
      activated_record_id: (head.activated as JsonObject).record_id,
    };
    await expect(parseActivatedAuthorityHead(flattened)).rejects.toThrow();
    await expect(parseActivatedAuthorityHead({ ...head, record_id: tagged(99) })).rejects.toThrow(
      "ACTIVATED_AUTHORITY_HEAD_DIGEST_INVALID",
    );
    await expect(
      buildActivatedAuthorityHead({
        ...input(1),
        activatedWorm: { ...activationWorm(), key: "receipts/v1/activation/wrong.json" },
      }),
    ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_INVALID");
  });

  it("binds a fresh DO read without expiring a long-lived head", async () => {
    const head = await headOne();
    const fullDigest = await activatedAuthorityHeadRecordSha256(head);
    const request = parseHeadReadRequest({
      expected_activated_record_id: tagged(1),
      expected_activated_record_sha256: tagged(2),
      expected_activated_service_authorities_sha256: tagged(3),
      expected_ingress_worker_version_id: VERSION,
      request_id: "head-read-request-0001",
      requested_at: "2027-08-15T12:00:00.000Z",
      schema: ACTIVATED_AUTHORITY_HEAD_READ_REQUEST_SCHEMA,
      schema_version: 1,
    });
    const proof = await buildCurrentHeadProof({
      brokerAcceptedAt: "2027-08-15T12:00:01.000Z",
      head,
      observedAt: "2027-08-15T12:00:00.500Z",
      requestId: "head-read-request-0001",
      requestedAt: "2027-08-15T12:00:00.000Z",
      worm: {
        digest: fullDigest,
        key: await activatedAuthorityHeadKey(head),
        retentionUntil: "2034-08-15T12:00:00.000Z",
        versionId: "head-worm-version-0001",
      },
    });

    expect(proof.schema).toBe(ACTIVATED_AUTHORITY_HEAD_CURRENT_SCHEMA);
    await expect(parseCurrentHeadProof(proof)).resolves.toEqual(proof);
    await expect(assertCurrentHeadMatchesRequest(proof, request)).resolves.toEqual(proof);
    await expect(
      assertCurrentHeadMatchesRequest({ ...proof, request_id: "replayed-request-0002" }, request),
    ).rejects.toThrow("ACTIVATED_AUTHORITY_HEAD_STALE");
  });
});

const VERSION = "123e4567-e89b-42d3-a456-426614174000";

async function headOne(): Promise<JsonObject> {
  return buildActivatedAuthorityHead(input(1));
}

function input(generation: number) {
  return {
    activatedRecordId: tagged(1),
    activatedRecordSha256: tagged(2),
    activatedServiceAuthoritiesSha256: tagged(3),
    activatedWorm: activationWorm(),
    committedAt: "2026-08-15T12:00:03.000Z",
    generation,
    ingressWorkerVersionId: VERSION,
    previous: "GENESIS" as const,
  };
}

function activationWorm(): ActivationWorm {
  return {
    digest: tagged(2),
    key: `receipts/v1/activation/${VERSION}/1-${tagged(2).slice(7)}.json`,
    retentionUntil: "2033-08-15T12:00:00.000Z",
    versionId: "activation-a1-version-0001",
  };
}

function activationWormJson(): JsonObject {
  const worm = activationWorm();
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}

function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
