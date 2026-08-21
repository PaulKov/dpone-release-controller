import { describe, expect, it } from "vitest";

import {
  PUBLIC_V2_MAX_BYTES,
  canonicalPublicV2,
  canonicalPublicV2Bytes,
  parseCanonicalPublicV2,
} from "../src/candidate-public-v2/canonical";
import { CandidatePublicV2Error } from "../src/candidate-public-v2/error";

function expectCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error("expected candidate error");
  } catch (error) {
    expect(error).toBeInstanceOf(CandidatePublicV2Error);
    expect((error as CandidatePublicV2Error).code).toBe(code);
  }
}

describe("candidate public-v2 canonical JSON", () => {
  it("has one exact escape, integer and ordering form", () => {
    expect(canonicalPublicV2({ z: "\u2028🚀", a: '"\\\n\u0001', n: -0 })).toBe(
      '{"a":"\\"\\\\\\n\\u0001","n":0,"z":"\u2028🚀"}',
    );
    expectCode(
      () => parseCanonicalPublicV2(new TextEncoder().encode('{"z":1,"a":2}')),
      "PUBLIC_V2_NOT_CANONICAL",
    );
    expectCode(() => canonicalPublicV2({ value: 0.5 }), "PUBLIC_V2_CANONICAL_NUMBER_INVALID");
    expectCode(
      () => canonicalPublicV2({ value: "\ud800" }),
      "PUBLIC_V2_CANONICAL_SURROGATE_INVALID",
    );
  });

  it("accepts frozen and null-prototype data-only DTOs", () => {
    const frozen = Object.freeze({ values: Object.freeze([1, true, null]) });
    expect(parseCanonicalPublicV2(canonicalPublicV2Bytes(frozen))).toEqual(frozen);
    const nullPrototype = Object.create(null) as Record<string, unknown>;
    nullPrototype.value = "ok";
    expect(canonicalPublicV2(nullPrototype)).toBe('{"value":"ok"}');
  });

  it("rejects prototype, descriptor and array collision vectors", () => {
    class RecordLike {
      public readonly value = true;
    }
    for (const value of [
      new Date(0),
      new Map([["private", "canary"]]),
      new Set([1]),
      new RecordLike(),
    ]) {
      expectCode(() => canonicalPublicV2({ value }), "PUBLIC_V2_CANONICAL_TYPE_INVALID");
    }

    const accessor = {};
    Object.defineProperty(accessor, "private", { enumerable: true, get: () => "canary" });
    expectCode(() => canonicalPublicV2(accessor), "PUBLIC_V2_OBJECT_DESCRIPTOR_INVALID");

    const nonEnumerable = { visible: true };
    Object.defineProperty(nonEnumerable, "private", { enumerable: false, value: "canary" });
    expectCode(() => canonicalPublicV2(nonEnumerable), "PUBLIC_V2_OBJECT_DESCRIPTOR_INVALID");

    const symbolic = { visible: true };
    Object.defineProperty(symbolic, Symbol("private"), { enumerable: true, value: "canary" });
    expectCode(() => canonicalPublicV2(symbolic), "PUBLIC_V2_OBJECT_SYMBOL_INVALID");

    const sparse = new Array<unknown>(2);
    expectCode(() => canonicalPublicV2({ sparse }), "PUBLIC_V2_ARRAY_INVALID");
    const extra = [1] as unknown[] & { private?: string };
    extra.private = "canary";
    expectCode(() => canonicalPublicV2({ extra }), "PUBLIC_V2_ARRAY_INVALID");

    const tooManyKeys = Object.fromEntries(
      Array.from({ length: 1_025 }, (_, index) => [`k${index}`, index]),
    );
    expectCode(() => canonicalPublicV2(tooManyKeys), "PUBLIC_V2_CANONICAL_OBJECT_TOO_LARGE");
  });

  it("bounds before encoding and reports uniform public error codes", () => {
    const exact = canonicalPublicV2Bytes({ x: "a".repeat(PUBLIC_V2_MAX_BYTES - 8) });
    expect(exact.byteLength).toBe(PUBLIC_V2_MAX_BYTES);
    expectCode(
      () => canonicalPublicV2Bytes({ x: "a".repeat(PUBLIC_V2_MAX_BYTES - 7) }),
      "PUBLIC_V2_CANONICAL_SIZE_INVALID",
    );
    expectCode(
      () => parseCanonicalPublicV2(new Uint8Array(PUBLIC_V2_MAX_BYTES + 1)),
      "PUBLIC_V2_RAW_SIZE_INVALID",
    );
    expectCode(() => parseCanonicalPublicV2(Uint8Array.of(0xff)), "PUBLIC_V2_UTF8_INVALID");
    expectCode(
      () =>
        parseCanonicalPublicV2(
          Uint8Array.from([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"a":1}')]),
        ),
      "PUBLIC_V2_BOM_INVALID",
    );
    expectCode(
      () => parseCanonicalPublicV2(new TextEncoder().encode("{")),
      "PUBLIC_V2_JSON_INVALID",
    );
  });
});
