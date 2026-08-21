import { beforeAll, describe, expect, it } from "vitest";

import {
  buildActivationActivatedRecordV2,
  buildActivationProvisionedRecordV2,
  parseActivationProvisionedRecordV2,
  parseActivationRecordV2,
  parseActivationRecordV2Chain,
} from "../src/activation-record-v2-builder";
import {
  activationRecordV2AttemptId,
  activationRecordV2IntentSha256,
  activationRecordV2IssuanceId,
} from "../src/activation-record-v2-evidence";
import {
  activationRecordV2WormKey,
  isActivationRecordV2WormKey,
} from "../src/activation-record-v2-identity";
import { canonicalBytes, canonicalJson } from "../src/canonical";
import type { JsonObject } from "../src/types";
import {
  compactActivationRecordV2Fixture,
  type CompactActivationRecordV2Fixture,
} from "./activation-record-v2.fixtures";

describe("compact activation record v2 fail-closed boundaries", () => {
  let fixture: CompactActivationRecordV2Fixture;
  let transplanted: CompactActivationRecordV2Fixture;

  beforeAll(async () => {
    [fixture, transplanted] = await Promise.all([
      compactActivationRecordV2Fixture(),
      compactActivationRecordV2Fixture(true),
    ]);
  }, 30_000);

  it("rejects unknown root and nested fields", async () => {
    const root = body(fixture.provisioned.document);
    root.unknown = true;
    await expect(buildActivationProvisionedRecordV2(root)).rejects.toThrow();

    const nested = body(fixture.provisioned.document);
    object(array(nested.provider_evidence)[0]).unknown = true;
    await expect(buildActivationProvisionedRecordV2(nested)).rejects.toThrow();
  });

  it("rejects direct and service anchor reordering", async () => {
    const direct = body(fixture.provisioned.document);
    swap(array(direct.provider_evidence), 0, 1);
    await expect(buildActivationProvisionedRecordV2(direct)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_DIRECT_ORDER_INVALID",
    );

    const service = body(fixture.provisioned.document);
    swap(array(object(service.service_authority).records), 0, 1);
    await expect(buildActivationProvisionedRecordV2(service)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_SERVICE_ORDER_INVALID",
    );
  });

  it("rejects duplicate JSON fields and duplicate WORM identities", async () => {
    const text = canonicalJson(fixture.provisioned.document);
    const duplicate = text.replace(
      '"committed_at":"2026-08-19T12:00:04.000Z"',
      '"committed_at":"2026-08-19T12:00:04.000Z","committed_at":"2026-08-19T12:00:04.000Z"',
    );
    await expect(
      parseActivationProvisionedRecordV2(new TextEncoder().encode(duplicate)),
    ).rejects.toThrow("DUPLICATE_FIELD");

    const alias = body(fixture.provisioned.document);
    const direct = array(alias.provider_evidence).map(object);
    object(direct[1]?.worm).version_id = object(direct[0]?.worm).version_id ?? null;
    await expect(buildActivationProvisionedRecordV2(alias)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_WORM_ALIAS_INVALID",
    );
  });

  it("rejects component, intent, and predecessor transplants", async () => {
    const component = body(fixture.provisioned.document);
    object(component.component_authority).resolved_projection_sha256 = tagged(7777);
    await expect(buildActivationProvisionedRecordV2(component)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_OPERATION_INVALID",
    );

    await expect(
      parseActivationRecordV2Chain(
        transplanted.provisioned.canonicalBytes,
        fixture.activated.canonicalBytes,
      ),
    ).rejects.toThrow("ACTIVATION_RECORD_V2_CHAIN_INVALID");
  });

  it("rejects depth, node, string, shadowed byte, accessor, and proxied inputs", async () => {
    let nested: JsonObject = { leaf: true };
    for (let index = 0; index < 17; index += 1) nested = { nested };
    await expect(
      parseActivationRecordV2(new TextEncoder().encode(JSON.stringify(nested))),
    ).rejects.toThrow();

    await expect(
      buildActivationProvisionedRecordV2({ oversized: Array.from({ length: 513 }, () => 0) }),
    ).rejects.toThrow("ACTIVATION_RECORD_V2_BUDGET_EXCEEDED");
    await expect(
      buildActivationProvisionedRecordV2({ oversized: "x".repeat(513) }),
    ).rejects.toThrow("ACTIVATION_RECORD_V2_BUDGET_EXCEEDED");
    await expect(parseActivationRecordV2(new Uint8Array(65_537))).rejects.toMatchObject({
      status: 413,
    });

    const shadowedByteLength = new Uint8Array(65_537);
    Object.defineProperty(shadowedByteLength, "byteLength", { value: 1 });
    await expect(parseActivationRecordV2(shadowedByteLength)).rejects.toMatchObject({
      status: 413,
    });

    let iteratorCalls = 0;
    const iteratorTrap = Uint8Array.from(fixture.provisioned.canonicalBytes);
    Object.defineProperty(iteratorTrap, Symbol.iterator, {
      value: () => {
        iteratorCalls += 1;
        throw new Error("caller iterator must not execute");
      },
    });
    await expect(parseActivationProvisionedRecordV2(iteratorTrap)).resolves.toMatchObject({
      sequence: 0,
      trust: "UNTRUSTED",
    });
    expect(iteratorCalls).toBe(0);

    let getterCalls = 0;
    const accessor: JsonObject = Object.defineProperty({}, "schema", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "dpone.release-broker-provisioned.v2";
      },
    });
    await expect(buildActivationProvisionedRecordV2(accessor)).rejects.toThrow();
    expect(getterCalls).toBe(0);

    const arrayAccessor = body(fixture.provisioned.document);
    const providerEvidence = array(arrayAccessor.provider_evidence);
    const firstEvidence = providerEvidence[0];
    Object.defineProperty(providerEvidence, "0", {
      configurable: true,
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return firstEvidence;
      },
    });
    await expect(buildActivationProvisionedRecordV2(arrayAccessor)).rejects.toThrow();
    expect(getterCalls).toBe(0);

    const extraArrayKey = body(fixture.provisioned.document);
    Object.defineProperty(array(extraArrayKey.provider_evidence), "extra", { value: true });
    await expect(buildActivationProvisionedRecordV2(extraArrayKey)).rejects.toThrow();

    const proxied = new Proxy(fixture.provisioned.canonicalBytes, {
      get() {
        throw new Error("proxy getter must not execute");
      },
    });
    await expect(parseActivationRecordV2(proxied)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_SIZE_INVALID",
    );
  });

  it("rejects self-ID and every candidate key transplant", async () => {
    const record = clone(fixture.provisioned.document);
    record.record_id = tagged(8001);
    await expect(parseActivationProvisionedRecordV2(canonicalBytes(record))).rejects.toThrow(
      "ACTIVATION_RECORD_V2_SELF_ID_INVALID",
    );

    const activated = body(fixture.activated.document);
    object(object(activated.provisioned).worm).key = "receipts/v1/activation/0.json";
    await expect(buildActivationActivatedRecordV2(activated)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_WORM_INVALID",
    );

    const expectedKey = string(object(object(fixture.activated.document.provisioned).worm), "key");
    expect(
      isActivationRecordV2WormKey(expectedKey, {
        recordSha256: tagged(8002),
        sequence: 0,
        workerVersionId: string(fixture.activated.document, "worker_version_id"),
      }),
    ).toBe(false);
    expect(() =>
      activationRecordV2WormKey(
        string(fixture.activated.document, "worker_version_id"),
        2 as never,
        fixture.provisioned.recordSha256,
      ),
    ).toThrow("ACTIVATION_RECORD_V2_WORM_KEY_INVALID");
  });

  it("rejects service and predecessor chronology inversions", async () => {
    const reboundFreshness = body(fixture.provisioned.document);
    object(object(reboundFreshness.component_authority).session).fresh_until =
      "2026-08-19T12:00:01.000Z";
    await expect(buildActivationProvisionedRecordV2(reboundFreshness)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_COMPONENT_SESSION_INVALID",
    );

    const serviceTime = body(fixture.provisioned.document);
    object(serviceTime.service_authority).observed_at = "2026-08-19T12:00:01.000Z";
    await expect(buildActivationProvisionedRecordV2(serviceTime)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_SERVICE_BINDING_INVALID",
    );

    const activated = body(fixture.activated.document);
    object(activated.promotion).started_at = "2026-08-19T12:00:04.000Z";
    await rebindA1Operation(activated);
    const rebuilt = await buildActivationActivatedRecordV2(activated);
    await expect(
      parseActivationRecordV2Chain(fixture.provisioned.canonicalBytes, rebuilt.canonicalBytes),
    ).rejects.toThrow("ACTIVATION_RECORD_V2_CHAIN_INVALID");
  });

  it("rejects legacy records in either side of a v2 chain", async () => {
    const legacy = canonicalBytes({
      schema: "dpone.release-broker-activated.v1",
      schema_version: 1,
    });
    await expect(parseActivationRecordV2(legacy)).rejects.toThrow(
      "ACTIVATION_RECORD_V2_SCHEMA_INVALID",
    );
    await expect(
      parseActivationRecordV2Chain(fixture.provisioned.canonicalBytes, legacy),
    ).rejects.toThrow("ACTIVATION_RECORD_V2_SCHEMA_INVALID");
  });
});

async function rebindA1Operation(bodyValue: JsonObject): Promise<void> {
  const operation = object(bodyValue.operation);
  const semantic = {
    approvals: bodyValue.approvals ?? null,
    promotion: bodyValue.promotion ?? null,
    provisioned: bodyValue.provisioned ?? null,
    target: bodyValue.target ?? null,
  };
  const intentSha256 = await activationRecordV2IntentSha256(semantic, 1);
  const workerVersionId = string(bodyValue, "worker_version_id");
  const attemptId = await activationRecordV2AttemptId(intentSha256, 1, workerVersionId);
  const issuanceId = await activationRecordV2IssuanceId(attemptId, 1);
  operation.intent_sha256 = intentSha256;
  operation.attempt_id = attemptId;
  operation.issuance_id = issuanceId;
  operation.internal_request_id = `activation-${issuanceId.slice(7)}`;
  const service = object(bodyValue.service_authority);
  service.batch_id = await import("../src/activation-record-v2-service").then(
    ({ activationRecordV2BatchId }) => activationRecordV2BatchId(issuanceId, 1, 1),
  );
  const records = array(service.records).map(object);
  records.forEach((record) => {
    const worm = object(record.worm);
    worm.key = string(worm, "key").replace(
      /cloudflare-observations-v2\/([^/]+)\/[0-9a-f]{64}\//u,
      `cloudflare-observations-v2/$1/${string(service, "batch_id").slice(7)}/`,
    );
  });
  service.records_sha256 = await import("../src/activation-record-v2-service").then(
    ({ activationRecordV2AnchorVectorDigest }) => activationRecordV2AnchorVectorDigest(records),
  );
}

function body(record: JsonObject): JsonObject {
  const value = clone(record);
  delete value.record_id;
  return value;
}

function clone(value: JsonObject): JsonObject {
  return structuredClone(value);
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("compact v2 negative fixture object missing");
  }
  return value as JsonObject;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("compact v2 negative fixture array missing");
  return value;
}

function swap(values: unknown[], left: number, right: number): void {
  const value = values[left];
  if (value === undefined || values[right] === undefined) throw new Error("swap fixture missing");
  values[left] = values[right];
  values[right] = value;
}

function string(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`compact v2 negative ${key} missing`);
  return candidate;
}

function tagged(index: number): string {
  return `sha256:${index.toString(16).padStart(64, "0")}`;
}
