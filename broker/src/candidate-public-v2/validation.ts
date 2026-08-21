import { candidateAssert } from "./error";
import { requireDigest } from "./identity";
import type { CandidateJsonObject, CandidateJsonValue, DigestSha256, GitSha } from "./types";

export const GIT_SHA = /^[0-9a-f]{40}$/u;
export const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
export const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
export const TAG_REF = /^refs\/tags\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;

export function exactObject(
  value: unknown,
  keys: readonly string[],
  code: string,
): CandidateJsonObject {
  candidateAssert(isObject(value), code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  candidateAssert(
    actual.length === expected.length && actual.every((key, index) => key === expected[index]),
    code,
  );
  return value;
}

export function objectField(
  object: CandidateJsonObject,
  key: string,
  code: string,
): CandidateJsonObject {
  const value = object[key];
  candidateAssert(isObject(value), code);
  return value;
}

export function arrayField(
  object: CandidateJsonObject,
  key: string,
  code: string,
): CandidateJsonValue[] {
  const value = object[key];
  candidateAssert(Array.isArray(value), code);
  return value;
}

export function stringField(
  object: CandidateJsonObject,
  key: string,
  code: string,
  pattern?: RegExp,
): string {
  const value = object[key];
  candidateAssert(
    typeof value === "string" && (pattern === undefined || pattern.test(value)),
    code,
  );
  return value;
}

export function digestField(object: CandidateJsonObject, key: string, code: string): DigestSha256 {
  return requireDigest(object[key], code);
}

export function gitShaField(object: CandidateJsonObject, key: string, code: string): GitSha {
  return stringField(object, key, code, GIT_SHA);
}

export function integerField(
  object: CandidateJsonObject,
  key: string,
  minimum: number,
  maximum: number,
  code: string,
): number {
  const value = object[key];
  candidateAssert(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= minimum &&
      value <= maximum,
    code,
  );
  return value;
}

export function literalField<T extends CandidateJsonValue>(
  object: CandidateJsonObject,
  key: string,
  expected: T,
  code: string,
): T {
  candidateAssert(object[key] === expected, code);
  return expected;
}

export function cloneWithout(
  object: CandidateJsonObject,
  keys: ReadonlySet<string>,
): CandidateJsonObject {
  return Object.fromEntries(Object.entries(object).filter(([key]) => !keys.has(key)));
}

export function projectObject(
  object: CandidateJsonObject,
  keys: readonly string[],
  code: string,
): CandidateJsonObject {
  const projected: CandidateJsonObject = {};
  for (const key of keys) {
    const value = object[key];
    candidateAssert(value !== undefined, code);
    projected[key] = value;
  }
  return projected;
}

export function jsonEqual(left: CandidateJsonValue, right: CandidateJsonValue): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length &&
      left.every((value, index) => {
        const rightValue = right[index];
        return rightValue !== undefined && jsonEqual(value, rightValue);
      })
    );
  }
  if (isObject(left) && isObject(right)) {
    const keys = Object.keys(left);
    return (
      keys.length === Object.keys(right).length &&
      keys.every((key) => {
        const leftValue = left[key];
        const rightValue = right[key];
        return (
          Object.hasOwn(right, key) &&
          leftValue !== undefined &&
          rightValue !== undefined &&
          jsonEqual(leftValue, rightValue)
        );
      })
    );
  }
  return false;
}

export function isObject(value: unknown): value is CandidateJsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
