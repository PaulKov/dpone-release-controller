import { describe, expect, it } from "vitest";

import { canonicalJson, sha256Hex } from "../src/canonical";
import { digestDomain } from "../src/identity";
import fixture from "./fixtures/canonical-vectors.json";

describe("canonical JSON and WebCrypto", () => {
  it("matches the shared Python canonical vector", async () => {
    const canonical = canonicalJson(fixture.value);
    expect(canonical).toBe(fixture.canonical);
    expect(await sha256Hex(canonical)).toBe(fixture.sha256);
  });

  it("matches the NIST SHA-256 abc vector", async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("rejects floating-point values", () => {
    expect(() => canonicalJson({ value: 0.5 })).toThrowError("CANONICAL_JSON_NUMBER_INVALID");
  });

  it("enforces the frozen Python/TypeScript bounds and ASCII key domain", () => {
    expect(() => canonicalJson([] as never)).toThrowError("CANONICAL_JSON_ROOT_INVALID");
    expect(() => canonicalJson({ é: 1 })).toThrowError("CANONICAL_JSON_KEY_INVALID");
    expect(() => canonicalJson({ value: "\ud800" })).toThrowError("CANONICAL_JSON_STRING_INVALID");
    expect(() => canonicalJson({ value: "\udc00" })).toThrowError("CANONICAL_JSON_STRING_INVALID");
    expect(canonicalJson({ value: "\ud83d\ude80" })).toBe('{"value":"🚀"}');
    expect(() => canonicalJson({ values: Array.from({ length: 4097 }, () => null) })).toThrowError(
      "CANONICAL_JSON_ARRAY_TOO_LARGE",
    );
    expect(() =>
      canonicalJson(
        Object.fromEntries(Array.from({ length: 1025 }, (_, index) => [`k${index}`, null])),
      ),
    ).toThrowError("CANONICAL_JSON_OBJECT_TOO_LARGE");
  });

  it("requires a bounded non-empty ASCII identity domain", async () => {
    expect(() => digestDomain("", {})).toThrowError("IDENTITY_DOMAIN_INVALID");
    expect(() => digestDomain("dpone.é", {})).toThrowError("IDENTITY_DOMAIN_INVALID");
    await expect(digestDomain("dpone.test.v1", { enabled: true })).resolves.toMatch(
      /^sha256:[0-9a-f]{64}$/u,
    );
  });
});
