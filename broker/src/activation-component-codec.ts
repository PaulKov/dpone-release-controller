import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";
import type { JsonObject, JsonValue } from "./types";

export const ACTIVATION_COMPONENT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const ACTIVATION_COMPONENT_WORKER_VERSION = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;
export const ACTIVATION_COMPONENT_WORM_VERSION = /^[A-Za-z0-9._=-]{1,512}$/u;

export interface ActivationJsonBudget {
  readonly bytes: number;
  readonly depth: number;
  readonly maxStringBytes: number;
  readonly nodes: number;
}

interface ActivationJsonLimits {
  readonly bytes: number;
  readonly depth: number;
  readonly maxStringBytes: number;
  readonly nodes: number;
}

/** Decode exact canonical object bytes under the route-compatible structural budget. */
export function decodeBoundedActivationObject(
  input: Uint8Array,
  limits: ActivationJsonLimits,
  code: string,
): {
  readonly budget: ActivationJsonBudget;
  readonly bytes: Uint8Array;
  readonly value: JsonObject;
} {
  const bytes = ownExactUint8Array(input, {
    code,
    invalidStatus: 409,
    maximum: limits.bytes,
    minimum: 1,
    sizeStatus: 413,
  });
  let text: string;
  let decoded: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text) as unknown;
  } catch {
    throw componentError(code);
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw componentError(code);
  }
  const value = decoded as JsonObject;
  const budget = scanActivationJson(value, limits, code);
  if (budget.bytes !== bytes.byteLength) throw componentError(code, 413);
  let canonical: string;
  try {
    canonical = canonicalJson(value);
  } catch {
    throw componentError(code);
  }
  if (canonical !== text) throw componentError(code);
  return { budget, bytes, value };
}

export function activationJsonBudget(
  value: JsonValue,
  limits?: ActivationJsonLimits,
  code?: string,
): ActivationJsonBudget {
  return scanActivationJson(value, limits, code);
}

export function exactActivationObject(
  value: unknown,
  fields: readonly string[],
  code: string,
): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw componentError(code);
  }
  const object = value as JsonObject;
  const actual = Object.keys(object).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw componentError(code);
  }
  return object;
}

export function activationString(
  object: JsonObject,
  key: string,
  pattern: RegExp,
  code: string,
): string {
  const value = object[key];
  pattern.lastIndex = 0;
  if (typeof value !== "string" || pattern.exec(value)?.[0] !== value) throw componentError(code);
  return value;
}

export function activationLiteral(
  object: JsonObject,
  key: string,
  expected: string | number,
  code: string,
): void {
  if (object[key] !== expected) throw componentError(code);
}

export function activationTimestamp(value: string, code: string): string {
  const milliseconds = Date.parse(value);
  if (
    value.length !== 24 ||
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw componentError(code);
  }
  return value;
}

export function componentError(code: string, status = 409): BrokerError {
  return new BrokerError(code, status, false);
}

function scanActivationJson(
  root: JsonValue,
  limits?: ActivationJsonLimits,
  code = "ACTIVATION_COMPONENT_JSON_INVALID",
): ActivationJsonBudget {
  const stack: { readonly depth: number; readonly value: JsonValue }[] = [
    { depth: 0, value: root },
  ];
  let bytes = 0;
  let maximumDepth = 0;
  let maximumStringBytes = 0;
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) throw componentError(code, 500);
    nodes += 1;
    maximumDepth = Math.max(maximumDepth, current.depth);
    assertActivationBudget(bytes, maximumDepth, maximumStringBytes, nodes, limits, code);

    const value = current.value;
    if (value === null || typeof value === "boolean" || typeof value === "number") {
      bytes += encodedScalarBytes(value);
    } else if (typeof value === "string") {
      const stringBytes = utf8Bytes(value);
      maximumStringBytes = Math.max(maximumStringBytes, stringBytes);
      bytes += encodedScalarBytes(value);
    } else if (Array.isArray(value)) {
      bytes += 2 + Math.max(0, value.length - 1);
      assertChildBudget(current.depth, value.length, nodes, stack.length, limits, code);
      for (let index = value.length - 1; index >= 0; index -= 1) {
        const child = value[index];
        if (child === undefined) throw componentError(code);
        stack.push({ depth: current.depth + 1, value: child });
      }
    } else if (typeof value === "object") {
      const keys = Object.keys(value);
      bytes += 2 + Math.max(0, keys.length - 1);
      assertChildBudget(current.depth, keys.length, nodes, stack.length, limits, code);
      for (let index = keys.length - 1; index >= 0; index -= 1) {
        const key = keys[index];
        if (key === undefined) throw componentError(code, 500);
        const keyBytes = utf8Bytes(key);
        maximumStringBytes = Math.max(maximumStringBytes, keyBytes);
        bytes += encodedScalarBytes(key) + 1;
        const child = value[key];
        if (child === undefined) throw componentError(code);
        stack.push({ depth: current.depth + 1, value: child });
      }
    } else {
      throw componentError(code);
    }
    assertActivationBudget(bytes, maximumDepth, maximumStringBytes, nodes, limits, code);
  }
  return { bytes, depth: maximumDepth, maxStringBytes: maximumStringBytes, nodes };
}

function assertChildBudget(
  parentDepth: number,
  children: number,
  visitedNodes: number,
  pendingNodes: number,
  limits: ActivationJsonLimits | undefined,
  code: string,
): void {
  if (
    limits !== undefined &&
    children > 0 &&
    (parentDepth + 1 > limits.depth || visitedNodes + pendingNodes + children > limits.nodes)
  ) {
    throw componentError(code, 413);
  }
}

function assertActivationBudget(
  bytes: number,
  depth: number,
  maxStringBytes: number,
  nodes: number,
  limits: ActivationJsonLimits | undefined,
  code: string,
): void {
  if (
    limits !== undefined &&
    (bytes > limits.bytes ||
      depth > limits.depth ||
      maxStringBytes > limits.maxStringBytes ||
      nodes > limits.nodes)
  ) {
    throw componentError(code, 413);
  }
}

function encodedScalarBytes(value: string | number | boolean | null): number {
  return utf8Bytes(JSON.stringify(value));
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
