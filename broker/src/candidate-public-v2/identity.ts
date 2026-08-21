import { copyPublicV2Bytes } from "./bytes";
import { canonicalPublicV2Bytes } from "./canonical";
import { candidateAssert } from "./error";
import type { CandidateJsonObject, DigestSha256 } from "./types";

const DOMAIN = /^[\x20-\x7e]{1,128}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", copyPublicV2Bytes(input).buffer);
  return new Uint8Array(digest);
}

export async function sha256Tagged(input: Uint8Array): Promise<DigestSha256> {
  return `sha256:${hex(await sha256Bytes(input))}`;
}

export async function rawPublicV2Digest(value: CandidateJsonObject): Promise<DigestSha256> {
  return sha256Tagged(canonicalPublicV2Bytes(value));
}

export async function publicV2Id(
  domain: string,
  payload: CandidateJsonObject,
): Promise<DigestSha256> {
  candidateAssert(DOMAIN.test(domain) && !domain.includes("\0"), "PUBLIC_V2_DOMAIN_INVALID");
  return rawPublicV2Digest({ domain, payload });
}

export function requireDigest(value: unknown, code = "PUBLIC_V2_DIGEST_INVALID"): DigestSha256 {
  candidateAssert(typeof value === "string" && DIGEST.test(value), code);
  return value as DigestSha256;
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
