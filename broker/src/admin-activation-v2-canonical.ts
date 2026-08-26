import { ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES } from "./activation-component-contract";
import { ACTIVATION_RECORD_V2_LIMITS } from "./activation-record-v2-contract";
import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import { ownExactUint8Array } from "./exact-uint8array";
import { parseStrictJsonObject } from "./strict-json";
import type { JsonObject } from "./types";

const BODY_INVALID = "ADMIN_ACTIVATION_V2_BODY_INVALID";

export interface CanonicalAdminActivationV2Body {
  /** Exact, independently owned bytes for the duration of one codec invocation. */
  readonly bytes: Uint8Array;
  /** Strictly decoded object; semantic schema validation remains the codec's responsibility. */
  readonly document: JsonObject;
}

/**
 * Own and decode one candidate-only admin v2 body without granting authority.
 *
 * This boundary rejects decorated/proxied typed arrays, a BOM, malformed UTF-8,
 * duplicate members, non-object roots, and any bytes that differ from the
 * canonical serialization. It intentionally performs no route, replay,
 * persistence, provider, or runtime action.
 */
export function decodeCanonicalAdminActivationV2Body(
  input: unknown,
): CanonicalAdminActivationV2Body {
  const bytes = ownExactUint8Array(input, {
    code: BODY_INVALID,
    invalidStatus: 409,
    maximum: Math.max(ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES, ACTIVATION_RECORD_V2_LIMITS.bytes),
    minimum: 1,
    sizeStatus: 413,
  });
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail("ADMIN_ACTIVATION_V2_BOM_FORBIDDEN");
  }

  const text = decodeUtf8(bytes);
  const document = decodeStrictObject(bytes);
  try {
    if (canonicalJson(document) !== text) fail("ADMIN_ACTIVATION_V2_BODY_NONCANONICAL");
  } catch (error) {
    if (error instanceof BrokerError && error.code === "ADMIN_ACTIVATION_V2_BODY_NONCANONICAL") {
      throw error;
    }
    fail(BODY_INVALID);
  }
  return { bytes, document };
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("ADMIN_ACTIVATION_V2_UTF8_INVALID");
  }
}

function decodeStrictObject(bytes: Uint8Array): JsonObject {
  try {
    return parseStrictJsonObject(
      bytes,
      BODY_INVALID,
      ACTIVATION_RECORD_V2_LIMITS.depth,
      ACTIVATION_RECORD_V2_LIMITS.nodes,
    );
  } catch (error) {
    if (error instanceof BrokerError && error.code.endsWith("_DUPLICATE_FIELD")) {
      fail("ADMIN_ACTIVATION_V2_DUPLICATE_FIELD");
    }
    if (error instanceof BrokerError && error.code.endsWith("_UTF8_INVALID")) {
      fail("ADMIN_ACTIVATION_V2_UTF8_INVALID");
    }
    fail(BODY_INVALID);
  }
}

function fail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
