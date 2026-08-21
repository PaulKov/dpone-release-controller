import { beforeAll, describe, expect, it } from "vitest";

import {
  parseActivationActivatedRecordV2,
  parseActivationProvisionedRecordV2,
  parseActivationRecordV2Chain,
} from "../src/activation-record-v2-builder";
import { activationRecordV2Budget } from "../src/activation-record-v2-codec";
import {
  activationRecordV2FullDigest,
  activationRecordV2SelfId,
  activationRecordV2WormKey,
  isActivationRecordV2WormKey,
} from "../src/activation-record-v2-identity";
import { canonicalJson } from "../src/canonical";
import type { JsonObject } from "../src/types";
import {
  compactActivationRecordV2Fixture,
  type CompactActivationRecordV2Fixture,
} from "./activation-record-v2.fixtures";

describe("compact activation record v2", () => {
  let fixture: CompactActivationRecordV2Fixture;
  let worstCase: CompactActivationRecordV2Fixture;

  beforeAll(async () => {
    [fixture, worstCase] = await Promise.all([
      compactActivationRecordV2Fixture(),
      compactActivationRecordV2Fixture(true),
    ]);
  }, 30_000);

  it("builds only explicitly untrusted closed A0/A1 structural values", async () => {
    const a0 = await parseActivationProvisionedRecordV2(fixture.provisioned.canonicalBytes);
    const a1 = await parseActivationActivatedRecordV2(fixture.activated.canonicalBytes);
    const chain = await parseActivationRecordV2Chain(a0.canonicalBytes, a1.canonicalBytes);

    expect([a0.sequence, a1.sequence]).toEqual([0, 1]);
    expect([a0.trust, a1.trust, chain.trust]).toEqual(["UNTRUSTED", "UNTRUSTED", "UNTRUSTED"]);
    expect(Object.isFrozen(a0.document)).toBe(true);
    expect(Object.isFrozen(object(a0.document.component_authority))).toBe(true);
    const owned = a0.canonicalBytes;
    owned.fill(0);
    expect(a0.canonicalBytes[0]).not.toBe(0);
  });

  it("pins actual and conservative budgets below both production gates", () => {
    expect({
      a0: activationRecordV2Budget(fixture.provisioned.document),
      a0Worst: activationRecordV2Budget(worstCase.provisioned.document),
      a1: activationRecordV2Budget(fixture.activated.document),
      a1Worst: activationRecordV2Budget(worstCase.activated.document),
    }).toEqual({
      a0: { bytes: 17_013, depth: 5, maxKeyBytes: 38, maxStringBytes: 279, nodes: 269 },
      a0Worst: {
        bytes: 26_922,
        depth: 5,
        maxKeyBytes: 38,
        maxStringBytes: 512,
        nodes: 269,
      },
      a1: { bytes: 15_242, depth: 5, maxKeyBytes: 38, maxStringBytes: 241, nodes: 244 },
      a1Worst: {
        bytes: 24_036,
        depth: 5,
        maxKeyBytes: 38,
        maxStringBytes: 512,
        nodes: 244,
      },
    });
    expect(worstCase.provisioned.canonicalBytes.byteLength).toBeLessThanOrEqual(65_536);
    expect(worstCase.activated.canonicalBytes.byteLength).toBeLessThanOrEqual(65_536);
  });

  it("fixes controller action as the first of four DIRECT_WORM pointers", () => {
    const direct = array(fixture.provisioned.document.provider_evidence);
    expect(direct.map((entry) => object(entry).slot_id)).toEqual([
      "CONTROLLER_ACTION",
      "CONTROLLER_OIDC",
      "TARGET_OIDC",
      "TARGET_RULESET",
    ]);
    expect(direct.every((entry) => object(entry).worm !== undefined)).toBe(true);
  });

  it("fixes the fourteen roles plus network anchor order", () => {
    const service = object(fixture.provisioned.document.service_authority);
    const records = array(service.records).map(object);
    expect(records).toHaveLength(15);
    expect(records.at(-1)).toMatchObject({
      authority_role: null,
      kind: "cloudflare_network_surface",
      slot_index: 14,
    });
    expect(records.map((record) => record.slot_index)).toEqual(
      Array.from({ length: 15 }, (_, index) => index),
    );
  });

  it("commits self-ID, full digest, and candidate-only record WORM key", async () => {
    const a0 = fixture.provisioned;
    expect(await activationRecordV2SelfId(a0.document)).toBe(a0.recordId);
    expect(await activationRecordV2FullDigest(a0.canonicalBytes)).toBe(a0.recordSha256);
    const key = activationRecordV2WormKey(
      string(a0.document, "worker_version_id"),
      0,
      a0.recordSha256,
    );
    expect(isActivationRecordV2WormKey(key)).toBe(true);
    expect(
      isActivationRecordV2WormKey(key, {
        recordSha256: a0.recordSha256,
        sequence: 0,
        workerVersionId: string(a0.document, "worker_version_id"),
      }),
    ).toBe(true);
    expect(isActivationRecordV2WormKey(key.replace("/0-", "/1-"))).toBe(true);
  });

  it("keeps full component bodies and full Cloudflare batch results off-record", () => {
    const compactText = [fixture.provisioned, fixture.activated]
      .map(({ document }) => canonicalJson(document))
      .join("\n");
    for (const bytes of fixture.rawComponentBodies) {
      const body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      expect(compactText).not.toContain(body);
    }
    for (const result of fixture.fullCloudflareResults) {
      expect(compactText).not.toContain(canonicalJson(result));
    }
    expect(compactText).not.toContain('"service_observation"');
    expect(compactText).not.toContain('"network_surface_observation"');
    expect(compactText).not.toContain('"raw_response_base64url"');
    expect(compactText).not.toContain('"components"');
  });
});

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("compact v2 test object missing");
  }
  return value as JsonObject;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("compact v2 test array missing");
  return value;
}

function string(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`compact v2 test ${key} missing`);
  return candidate;
}
