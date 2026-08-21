import type { ActivationOperationIssuance } from "./activation-operation-contract";
import { decodeCanonicalObject } from "./activation-registry-codec";
import type { JsonObject } from "./types";

/** Rebuild transport-independent request bytes with the durable issuance identity and clock. */
export function durableActivationRequestBody(
  semanticRequestBytes: Uint8Array,
  issuance: Pick<ActivationOperationIssuance, "internalRequestId" | "issuedAt">,
): JsonObject {
  return {
    ...decodeCanonicalObject(semanticRequestBytes),
    observed_at: issuance.issuedAt,
    request_id: issuance.internalRequestId,
  };
}
