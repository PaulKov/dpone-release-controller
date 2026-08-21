import type { JsonObject } from "./types";
import { canonicalJson } from "./canonical";

export class BrokerError extends Error {
  public constructor(
    public readonly code: string,
    public readonly status: number,
    public readonly retryable: boolean,
  ) {
    super(code);
    this.name = "BrokerError";
  }
}

export function jsonResponse(body: JsonObject, status = 200): Response {
  return canonicalTextResponse(canonicalJson(body), status);
}

export function canonicalTextResponse(text: string, status = 200): Response {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength === 0 || bytes.byteLength > 131_072) {
    throw new BrokerError("INTERNAL_RESPONSE_SIZE_INVALID", 500, false);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new BrokerError("INTERNAL_RESPONSE_JSON_INVALID", 500, false);
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    canonicalJson(parsed) !== text
  ) {
    throw new BrokerError("INTERNAL_RESPONSE_NONCANONICAL", 500, false);
  }
  return new Response(bytes, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

export function errorResponse(error: unknown, requestId: string): Response {
  const known = error instanceof BrokerError;
  const code = known ? error.code : "INTERNAL_ERROR";
  const retryable = known ? error.retryable : false;
  const status = known ? error.status : 500;
  return jsonResponse(
    {
      error: {
        code,
        request_id: requestId,
        retryable,
      },
    },
    status,
  );
}

export function assert(condition: unknown, code: string, status = 400): asserts condition {
  if (!condition) {
    throw new BrokerError(code, status, false);
  }
}
