import {
  activationBinding,
  parseCanonicalUntrustedActivationPair,
  parseUntrustedActivatedPublicCore,
  parseUntrustedProvisionedPublicCore,
  publicActivationId,
} from "./activation-core";
import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
  parseCanonicalPublicV2,
} from "./canonical";
import { copyPrivateNonce, copyPublicV2Bytes } from "./bytes";
import { CandidatePublicV2Error, candidateAssert } from "./error";
import { publicV2Id, rawPublicV2Digest, requireDigest } from "./identity";
import { buildUnpersistedSidecarOpeningForOwnedBase, type SidecarOpeningResult } from "./sidecar";
import type {
  UntrustedActivatedPublicCore,
  UntrustedActivationProof,
  UntrustedProvisionedPublicCore,
} from "./trust";
import type { CandidateJsonObject } from "./types";
import { exactObject, literalField, objectField, projectObject, stringField } from "./validation";

export const ACTIVATION_PROOF_PUBLIC_SCHEMA = "dpone.release-broker-activation-proof-public.v2";
export const ACTIVATION_PROOF_REQUEST_SCHEMA = "dpone.release-broker-activation-proof-request.v2";

const PROOF_DOMAIN = "dpone.activation.public-proof.v2";
const MAX_DATE_MS = 8_640_000_000_000_000;
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const PROOF_KEYS = [
  "activation",
  "admitted_at",
  "expires_at",
  "private_sidecar_commitment",
  "proof_id",
  "schema",
  "schema_version",
] as const;
const PROOF_BASE_KEYS = PROOF_KEYS.filter(
  (key) => key !== "private_sidecar_commitment" && key !== "proof_id",
);
const ACTIVATION_KEYS = [
  "activated",
  "activated_record_sha256",
  "activation_id",
  "provisioned",
  "provisioned_record_sha256",
] as const;

export interface UnpersistedActivationProofCandidate extends SidecarOpeningResult {
  readonly document: UntrustedActivationProof;
  readonly documentBytes: Uint8Array;
}

export interface PublicV2Clock {
  nowMs(): number;
}

export async function buildUnpersistedActivationProofCandidate(input: {
  readonly activated: UntrustedActivatedPublicCore;
  readonly clock: PublicV2Clock;
  readonly nonce: Uint8Array;
  readonly privatePayload: CandidateJsonObject;
  readonly provisioned: UntrustedProvisionedPublicCore;
}): Promise<UnpersistedActivationProofCandidate> {
  const nonce = copyPrivateNonce(input.nonce);
  const privatePayloadBytes = canonicalPublicV2Bytes(input.privatePayload);
  const provisionedBytes = canonicalPublicV2Bytes(input.provisioned);
  const activatedBytes = canonicalPublicV2Bytes(input.activated);
  let nowMs: number;
  try {
    nowMs = input.clock.nowMs();
  } catch {
    throw new CandidatePublicV2Error("PUBLIC_V2_PROOF_NOW_INVALID");
  }
  candidateAssert(
    Number.isSafeInteger(nowMs) && nowMs >= 0 && nowMs <= MAX_DATE_MS - 60_000,
    "PUBLIC_V2_PROOF_NOW_INVALID",
  );
  const admittedMs = Math.floor(nowMs / 1_000) * 1_000;
  const admittedAt = formatUtcSeconds(admittedMs);
  const { activated, provisioned } = await parseCanonicalUntrustedActivationPair({
    activated: activatedBytes,
    provisioned: provisionedBytes,
  });
  const expiresAt = formatUtcSeconds(admittedMs + 60_000);
  await activationBinding(provisioned, activated);
  const base: CandidateJsonObject = {
    activation: {
      activated,
      activated_record_sha256: await rawPublicV2Digest(activated),
      activation_id: await publicActivationId(provisioned, activated),
      provisioned,
      provisioned_record_sha256: await rawPublicV2Digest(provisioned),
    },
    admitted_at: admittedAt,
    expires_at: expiresAt,
    schema: ACTIVATION_PROOF_PUBLIC_SCHEMA,
    schema_version: 2,
  };
  await validateProofBase(base);
  const sidecar = await buildUnpersistedSidecarOpeningForOwnedBase({
    kind: "ACTIVATION_PROOF",
    nonce,
    privatePayloadBytes,
    publicBase: base,
  });
  const unsigned: CandidateJsonObject = {
    ...base,
    private_sidecar_commitment: sidecar.commitment,
  };
  const provisional: CandidateJsonObject = {
    ...unsigned,
    proof_id: await publicV2Id(PROOF_DOMAIN, unsigned),
  };
  const documentBytes = canonicalPublicV2Bytes(provisional);
  const document = await parseCanonicalUntrustedActivationProof(documentBytes);
  return { ...sidecar, document, documentBytes: Uint8Array.from(documentBytes) };
}

export async function parseCanonicalUntrustedActivationProof(
  input: Uint8Array,
): Promise<UntrustedActivationProof> {
  return parseUntrustedActivationProof(parseCanonicalPublicV2(copyPublicV2Bytes(input)));
}

export async function parseUntrustedActivationProof(
  value: unknown,
): Promise<UntrustedActivationProof> {
  const proof = exactObject(
    canonicalPublicV2Snapshot(value),
    PROOF_KEYS,
    "PUBLIC_V2_PROOF_INVALID",
  );
  const { activated, provisioned } = await validateProofBase(
    projectObject(proof, PROOF_BASE_KEYS, "PUBLIC_V2_PROOF_INVALID"),
  );
  requireDigest(proof.private_sidecar_commitment, "PUBLIC_V2_PROOF_COMMITMENT_INVALID");
  const proofId = requireDigest(proof.proof_id, "PUBLIC_V2_PROOF_ID_INVALID");
  const unsigned = Object.fromEntries(Object.entries(proof).filter(([key]) => key !== "proof_id"));
  candidateAssert(
    proofId === (await publicV2Id(PROOF_DOMAIN, unsigned)),
    "PUBLIC_V2_PROOF_ID_MISMATCH",
  );
  const activation = objectField(proof, "activation", "PUBLIC_V2_PROOF_ACTIVATION_INVALID");
  candidateAssert(
    activation.activation_id === (await publicActivationId(provisioned, activated)),
    "PUBLIC_V2_PROOF_ACTIVATION_ID_MISMATCH",
  );
  canonicalPublicV2Bytes(proof);
  return proof as UntrustedActivationProof;
}

export function assertUntrustedProofFresh(proof: UntrustedActivationProof, nowMs: number): void {
  candidateAssert(
    Number.isSafeInteger(nowMs) && nowMs >= 0 && nowMs <= MAX_DATE_MS,
    "PUBLIC_V2_PROOF_NOW_INVALID",
  );
  const admittedMs = parseUtcSeconds(
    stringField(proof, "admitted_at", "PUBLIC_V2_PROOF_TIME_INVALID"),
  );
  const expiresMs = parseUtcSeconds(
    stringField(proof, "expires_at", "PUBLIC_V2_PROOF_TIME_INVALID"),
  );
  candidateAssert(admittedMs <= nowMs + 30_000 && nowMs < expiresMs, "PUBLIC_V2_PROOF_NOT_FRESH");
}

export function parseActivationProofRequest(input: Uint8Array): CandidateJsonObject {
  const request = exactObject(
    parseCanonicalPublicV2(input),
    ["schema", "schema_version"],
    "PUBLIC_V2_PROOF_REQUEST_INVALID",
  );
  literalField(
    request,
    "schema",
    ACTIVATION_PROOF_REQUEST_SCHEMA,
    "PUBLIC_V2_PROOF_REQUEST_INVALID",
  );
  literalField(request, "schema_version", 2, "PUBLIC_V2_PROOF_REQUEST_INVALID");
  return request;
}

async function validateProofBase(value: unknown): Promise<{
  readonly activated: UntrustedActivatedPublicCore;
  readonly provisioned: UntrustedProvisionedPublicCore;
}> {
  const base = exactObject(value, PROOF_BASE_KEYS, "PUBLIC_V2_PROOF_BASE_INVALID");
  const activation = exactObject(
    objectField(base, "activation", "PUBLIC_V2_PROOF_ACTIVATION_INVALID"),
    ACTIVATION_KEYS,
    "PUBLIC_V2_PROOF_ACTIVATION_INVALID",
  );
  const provisioned = await parseUntrustedProvisionedPublicCore(
    objectField(activation, "provisioned", "PUBLIC_V2_PROOF_ACTIVATION_INVALID"),
  );
  const activated = await parseUntrustedActivatedPublicCore(
    objectField(activation, "activated", "PUBLIC_V2_PROOF_ACTIVATION_INVALID"),
    provisioned,
  );
  candidateAssert(
    activation.provisioned_record_sha256 === (await rawPublicV2Digest(provisioned)) &&
      activation.activated_record_sha256 === (await rawPublicV2Digest(activated)),
    "PUBLIC_V2_PROOF_RECORD_DIGEST_MISMATCH",
  );
  requireDigest(activation.activation_id, "PUBLIC_V2_PROOF_ACTIVATION_ID_INVALID");
  const admittedMs = parseUtcSeconds(
    stringField(base, "admitted_at", "PUBLIC_V2_PROOF_TIME_INVALID", UTC_SECONDS),
  );
  const expiresMs = parseUtcSeconds(
    stringField(base, "expires_at", "PUBLIC_V2_PROOF_TIME_INVALID", UTC_SECONDS),
  );
  candidateAssert(expiresMs - admittedMs === 60_000, "PUBLIC_V2_PROOF_TTL_INVALID");
  literalField(base, "schema", ACTIVATION_PROOF_PUBLIC_SCHEMA, "PUBLIC_V2_PROOF_BASE_INVALID");
  literalField(base, "schema_version", 2, "PUBLIC_V2_PROOF_BASE_INVALID");
  canonicalPublicV2Bytes(base);
  return { activated, provisioned };
}

function parseUtcSeconds(value: string): number {
  candidateAssert(UTC_SECONDS.test(value), "PUBLIC_V2_PROOF_TIME_INVALID");
  const parsed = Date.parse(value);
  candidateAssert(
    Number.isSafeInteger(parsed) &&
      parsed >= 0 &&
      parsed <= MAX_DATE_MS &&
      formatUtcSeconds(parsed) === value,
    "PUBLIC_V2_PROOF_TIME_INVALID",
  );
  return parsed;
}

function formatUtcSeconds(value: number): string {
  candidateAssert(
    Number.isSafeInteger(value) && value >= 0 && value <= MAX_DATE_MS,
    "PUBLIC_V2_PROOF_TIME_INVALID",
  );
  try {
    return new Date(value).toISOString().replace(".000Z", "Z");
  } catch {
    throw new CandidatePublicV2Error("PUBLIC_V2_PROOF_TIME_INVALID");
  }
}
