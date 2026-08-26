import { candidateAssert } from "./error";

export const PUBLIC_V2_MAX_BYTES = 65_536;
export const PRIVATE_NONCE_BYTES = 32;

/** Check the allocation bound before taking an immutable byte snapshot. */
export function copyPublicV2Bytes(
  input: Uint8Array,
  code = "PUBLIC_V2_RAW_SIZE_INVALID",
): Uint8Array<ArrayBuffer> {
  candidateAssert(input.byteLength >= 1 && input.byteLength <= PUBLIC_V2_MAX_BYTES, code);
  return Uint8Array.from(input);
}

/** The private salt is always exactly 256 bits and is copied before any await. */
export function copyPrivateNonce(input: Uint8Array): Uint8Array<ArrayBuffer> {
  candidateAssert(input.byteLength === PRIVATE_NONCE_BYTES, "PUBLIC_V2_NONCE_INVALID");
  return Uint8Array.from(input);
}
