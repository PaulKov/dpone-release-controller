import { beforeAll, describe, expect, it } from "vitest";

import {
  ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES,
  ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
} from "../src/admin-activation-v2-contract";
import { parseAdminActivationV2Ingress } from "../src/admin-activation-v2-codec";
import { FINALIZE_REQUEST_SCHEMA, PROVISION_REQUEST_SCHEMA } from "../src/activation-contract";
import { ACTIVATION_COMPONENT_KINDS } from "../src/activation-component-contract";
import { canonicalBytes, canonicalJson } from "../src/canonical";
import type { JsonObject } from "../src/types";
import {
  adminActivationV2CodecFixture,
  decodeFixtureObject,
  type AdminActivationV2CodecFixture,
} from "./admin-activation-v2-codec.fixtures";

describe("candidate admin activation v2 ingress codec", () => {
  let fixture: AdminActivationV2CodecFixture;

  beforeAll(async () => {
    fixture = await adminActivationV2CodecFixture();
    currentFixture = fixture;
  }, 30_000);

  it("parses all five closed variants without granting authority", () => {
    const begin = parseAdminActivationV2Ingress(fixture.beginBytes, fixture.provisionContext);
    const reissue = parseAdminActivationV2Ingress(fixture.reissueBytes, fixture.provisionContext);
    const stage = parseAdminActivationV2Ingress(fixture.stageBytes, fixture.provisionContext);
    const provision = parseAdminActivationV2Ingress(
      fixture.provisionBytes,
      fixture.provisionContext,
    );
    const finalize = parseAdminActivationV2Ingress(fixture.finalizeBytes, fixture.finalizeContext);

    expect(begin).toMatchObject({ action: "BEGIN", trust: "UNTRUSTED" });
    expect(
      begin.action === "BEGIN" && begin.components.map(({ componentKind }) => componentKind),
    ).toEqual(ACTIVATION_COMPONENT_KINDS);
    expect(reissue).toMatchObject({ action: "REISSUE", trust: "UNTRUSTED" });
    expect(stage).toMatchObject({
      action: "STAGE",
      trust: "UNTRUSTED",
      workerVersionId: fixture.workerVersionId,
    });
    expect("requestId" in stage).toBe(false);
    expect("sessionId" in stage).toBe(false);
    expect(provision).toMatchObject({ action: "PROVISION", trust: "UNTRUSTED" });
    expect(finalize).toMatchObject({
      action: "FINALIZE",
      trust: "UNTRUSTED",
      workerVersionId: fixture.workerVersionId,
    });
    expect("requestId" in finalize).toBe(false);
    expect("request_id" in finalize).toBe(false);
  });

  it("owns canonical bytes and deeply freezes the only returned JSON document", () => {
    const input = Uint8Array.from(fixture.finalizeBytes);
    const parsed = parseAdminActivationV2Ingress(input, fixture.finalizeContext);
    expect(parsed.action).toBe("FINALIZE");
    if (parsed.action !== "FINALIZE") throw new Error("finalize result missing");
    const expected = Uint8Array.from(input);
    input.fill(0);
    const firstCopy = parsed.canonicalBytes;
    firstCopy.fill(0);

    expect(parsed.canonicalBytes).toEqual(expected);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.request)).toBe(true);
    expect(Object.isFrozen(parsed.request.promotion)).toBe(true);
  });

  it("rejects both known v1 schemas before action-specific validation", () => {
    for (const [schema, context] of [
      [PROVISION_REQUEST_SCHEMA, fixture.provisionContext],
      [FINALIZE_REQUEST_SCHEMA, fixture.finalizeContext],
    ] as const) {
      expect(() => parseAdminActivationV2Ingress(canonicalBytes({ schema }), context)).toThrowError(
        expect.objectContaining({ code: "ADMIN_ACTIVATION_V1_SCHEMA_FORBIDDEN", status: 409 }),
      );
    }

    const noncanonical = new TextEncoder().encode(
      `${canonicalJson({ schema: PROVISION_REQUEST_SCHEMA })} `,
    );
    expect(() =>
      parseAdminActivationV2Ingress(noncanonical, fixture.provisionContext),
    ).toThrowError(expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_BODY_NONCANONICAL" }));
  });

  it("enforces URI-to-schema dispatch and trusted Worker context", () => {
    expect(() =>
      parseAdminActivationV2Ingress(fixture.beginBytes, fixture.finalizeContext),
    ).toThrowError(expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_ROUTE_SCHEMA_MISMATCH" }));
    expect(() =>
      parseAdminActivationV2Ingress(fixture.finalizeBytes, fixture.provisionContext),
    ).toThrowError(expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_ROUTE_SCHEMA_MISMATCH" }));
    expect(() =>
      parseAdminActivationV2Ingress(fixture.beginBytes, {
        ...fixture.provisionContext,
        expectedWorkerVersionId: "not-a-worker-version",
      }),
    ).toThrowError(
      expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_CONTEXT_INVALID", status: 500 }),
    );
  });

  it("rejects command extensions, request IDs, roster drift, and invalid actions", () => {
    const extra = decodeFixtureObject(fixture.provisionBytes);
    extra.request_id = "transport-must-not-enter-body";
    expectCommandError(extra);

    const begin = decodeFixtureObject(fixture.beginBytes);
    const components = array(begin.components);
    const first = components[0];
    const second = components[1];
    if (first === undefined || second === undefined) throw new Error("test roster missing");
    components[0] = second;
    components[1] = first;
    expectCommandError(begin, "ADMIN_ACTIVATION_V2_BEGIN_INVALID");

    const malformedDigest = decodeFixtureObject(fixture.reissueBytes);
    malformedDigest.predecessor_session_id = "sha256:not-a-digest";
    expectCommandError(malformedDigest);

    const invalidAction = decodeFixtureObject(fixture.provisionBytes);
    invalidAction.action = "DELETE";
    expectCommandError(invalidAction, "ADMIN_ACTIVATION_V2_ACTION_INVALID");
  });

  it("applies the exact 4 KiB command cap before command-field traversal", () => {
    const oversized = decodeFixtureObject(fixture.beginBytes);
    oversized.padding = "x".repeat(ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES);
    const bytes = canonicalBytes(oversized);
    expect(bytes.byteLength).toBeGreaterThan(ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES);
    expect(() => parseAdminActivationV2Ingress(bytes, fixture.provisionContext)).toThrowError(
      expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_COMMAND_SIZE_INVALID", status: 413 }),
    );
  });

  it("checks the STAGE generic envelope and exact expected Worker", () => {
    const mutations: readonly [string, unknown, string][] = [
      ["activation_sequence", 1, "ADMIN_ACTIVATION_V2_STAGE_INVALID"],
      ["component_kind", "unknown", "ADMIN_ACTIVATION_V2_STAGE_INVALID"],
      ["component_profile", "OTHER", "ADMIN_ACTIVATION_V2_STAGE_INVALID"],
      ["component_set_id", "sha256:bad", "ADMIN_ACTIVATION_V2_STAGE_INVALID"],
      ["payload", [], "ADMIN_ACTIVATION_V2_STAGE_INVALID"],
      [
        "worker_version_id",
        "00000000-0000-0000-0000-000000000001",
        "ADMIN_ACTIVATION_V2_WORKER_VERSION_MISMATCH",
      ],
    ];
    for (const [field, value, code] of mutations) {
      const document = decodeFixtureObject(fixture.stageBytes);
      document[field] = value as never;
      expect(() =>
        parseAdminActivationV2Ingress(canonicalBytes(document), fixture.provisionContext),
      ).toThrowError(expect.objectContaining({ code, status: 409 }));
    }
    for (const field of ["request_id", "session_id"] as const) {
      const extended = decodeFixtureObject(fixture.stageBytes);
      extended[field] = "not-semantic";
      expect(() =>
        parseAdminActivationV2Ingress(canonicalBytes(extended), fixture.provisionContext),
      ).toThrowError(expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_STAGE_INVALID" }));
    }
  });

  it("requires the exact six-field FINALIZE body and validates its Worker binding", () => {
    for (const field of ["request_id", "observed_at"] as const) {
      const document = decodeFixtureObject(fixture.finalizeBytes);
      document[field] = field;
      expectFinalizeError(document);
    }
    const transplanted = decodeFixtureObject(fixture.finalizeBytes);
    object(transplanted.promotion).worker_version_id = "00000000-0000-0000-0000-000000000001";
    expectFinalizeError(transplanted);
  });

  it("rejects duplicate fields, BOM, malformed UTF-8, and noncanonical bytes", () => {
    const text = new TextDecoder().decode(fixture.provisionBytes);
    const duplicate = text.replace(
      `"schema":"${ADMIN_ACTIVATION_V2_COMMAND_SCHEMA}"`,
      `"schema":"${ADMIN_ACTIVATION_V2_COMMAND_SCHEMA}","schema":"${ADMIN_ACTIVATION_V2_COMMAND_SCHEMA}"`,
    );
    expectRawError(new TextEncoder().encode(duplicate), "ADMIN_ACTIVATION_V2_DUPLICATE_FIELD");

    const bom = new Uint8Array(fixture.provisionBytes.byteLength + 3);
    bom.set([0xef, 0xbb, 0xbf]);
    bom.set(fixture.provisionBytes, 3);
    expectRawError(bom, "ADMIN_ACTIVATION_V2_BOM_FORBIDDEN");
    expectRawError(new Uint8Array([0xff]), "ADMIN_ACTIVATION_V2_UTF8_INVALID");
    expectRawError(new TextEncoder().encode('{"schema":'), "ADMIN_ACTIVATION_V2_BODY_INVALID");
    expectRawError(new TextEncoder().encode(`${text}\n`), "ADMIN_ACTIVATION_V2_BODY_NONCANONICAL");
  });

  it("integrates the exact Uint8Array boundary without evaluating decorations", () => {
    let invoked = 0;
    const decorated = Uint8Array.from(fixture.provisionBytes);
    Object.defineProperty(decorated, "byteLength", { value: 1 });
    Object.defineProperty(decorated, Symbol.iterator, {
      get() {
        invoked += 1;
        throw new Error("iterator getter must not execute");
      },
    });
    expect(parseAdminActivationV2Ingress(decorated, fixture.provisionContext)).toMatchObject({
      action: "PROVISION",
    });
    const proxy = new Proxy(fixture.provisionBytes, {
      get() {
        invoked += 1;
        throw new Error("proxy getter must not execute");
      },
    });
    expect(() => parseAdminActivationV2Ingress(proxy, fixture.provisionContext)).toThrowError(
      expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_BODY_INVALID" }),
    );
    expect(invoked).toBe(0);
  });

  it("rejects the global raw-body cap before JSON decoding", () => {
    expect(() =>
      parseAdminActivationV2Ingress(new Uint8Array(65_537), fixture.provisionContext),
    ).toThrowError(
      expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_BODY_INVALID", status: 413 }),
    );
  });
});

function expectCommandError(document: JsonObject, code = "ADMIN_ACTIVATION_V2_COMMAND_INVALID") {
  expect(() =>
    parseAdminActivationV2Ingress(canonicalBytes(document), currentFixture.provisionContext),
  ).toThrowError(expect.objectContaining({ code, status: 409 }));
}

let currentFixture: AdminActivationV2CodecFixture;

function expectFinalizeError(document: JsonObject): void {
  expect(() =>
    parseAdminActivationV2Ingress(canonicalBytes(document), currentFixture.finalizeContext),
  ).toThrowError(expect.objectContaining({ code: "ADMIN_ACTIVATION_V2_FINALIZE_INVALID" }));
}

function expectRawError(bytes: Uint8Array, code: string): void {
  expect(() => parseAdminActivationV2Ingress(bytes, currentFixture.provisionContext)).toThrowError(
    expect.objectContaining({ code, status: 409 }),
  );
}

function array(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) throw new Error("test array missing");
  for (const entry of value) object(entry);
  return value as JsonObject[];
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("test object missing");
  }
  return value as JsonObject;
}
