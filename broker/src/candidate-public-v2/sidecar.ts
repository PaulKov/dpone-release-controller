import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
  parseCanonicalPublicV2,
} from "./canonical";
import { copyPrivateNonce, copyPublicV2Bytes } from "./bytes";
import { CandidatePublicV2Error, candidateAssert } from "./error";
import { publicV2Id, requireDigest, sha256Tagged } from "./identity";
import {
  SIDECAR_KINDS,
  type CandidateJsonObject,
  type DigestSha256,
  type SidecarKind,
} from "./types";
import { cloneWithout, exactObject, literalField, objectField, stringField } from "./validation";

export const PRIVATE_SIDECAR_SCHEMA = "dpone.release-private-sidecar.v2";
export const PRIVATE_SIDECAR_OPENING_SCHEMA = "dpone.release-private-sidecar-opening.v2";

const COMMITMENT_DOMAIN = "dpone.release.private-sidecar-commitment.v2";
const PUBLIC_CONTEXT_DOMAIN = "dpone.release.public-context.v2";
const SIDECAR_KEYS = [
  "kind",
  "private_payload_schema",
  "private_payload_sha256",
  "public_context_sha256",
  "schema",
  "schema_version",
] as const;
const OPENING_KEYS = ["nonce_b64url", "schema", "schema_version", "sidecar"] as const;
const KINDS = new Set<SidecarKind>(SIDECAR_KINDS);
export const PRIVATE_PAYLOAD_SCHEMAS = Object.freeze({
  ACTIVATION_A0: "dpone.release-broker-provisioned-private-payload.v2",
  ACTIVATION_A1: "dpone.release-broker-activated-private-payload.v2",
  ACTIVATION_PROOF: "dpone.release-broker-activation-proof-private-payload.v2",
  RUNTIME_CLOSURE: "dpone.release-runtime-closure-private-payload.v2",
} satisfies Readonly<Record<SidecarKind, string>>);

const DOCUMENT_BINDINGS = Object.freeze({
  ACTIVATION_A0: {
    schema: "dpone.release-broker-provisioned-public-core.v2",
    terminalId: "record_id",
  },
  ACTIVATION_A1: {
    schema: "dpone.release-broker-activated-public-core.v2",
    terminalId: "record_id",
  },
  ACTIVATION_PROOF: {
    schema: "dpone.release-broker-activation-proof-public.v2",
    terminalId: "proof_id",
  },
  RUNTIME_CLOSURE: {
    schema: "dpone.release-runtime-closure-public.v2",
    terminalId: "closure_id",
  },
} satisfies Readonly<
  Record<SidecarKind, { readonly schema: string; readonly terminalId: TerminalId }>
>);

type TerminalId = "closure_id" | "proof_id" | "record_id";

export interface SidecarOpeningResult {
  readonly commitment: DigestSha256;
  readonly dispatchSafety: "UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE";
  readonly nonceBytes: Uint8Array;
  readonly nonceFingerprintSha256: DigestSha256;
  readonly opening: CandidateJsonObject;
  readonly openingBytes: Uint8Array;
  readonly privatePayloadBytes: Uint8Array;
  readonly sidecar: CandidateJsonObject;
}

export async function publicContextDigest(
  kind: SidecarKind,
  publicBase: CandidateJsonObject,
): Promise<DigestSha256> {
  requireKind(kind);
  canonicalPublicV2Bytes(publicBase);
  return publicV2Id(PUBLIC_CONTEXT_DOMAIN, { document: publicBase, kind });
}

/** Candidate-internal primitive; fused document builders must own publicBase. */
export async function buildUnpersistedSidecarOpeningForOwnedBase(input: {
  readonly kind: SidecarKind;
  readonly nonce: Uint8Array;
  readonly privatePayloadBytes: Uint8Array;
  readonly publicBase: CandidateJsonObject;
}): Promise<SidecarOpeningResult> {
  const nonce = copyPrivateNonce(input.nonce);
  requireNonce(nonce);
  const privatePayloadBytes = copyPublicV2Bytes(
    input.privatePayloadBytes,
    "PUBLIC_V2_PRIVATE_PAYLOAD_SIZE_INVALID",
  );
  const privatePayload = parseCanonicalPublicV2(privatePayloadBytes);
  const privatePayloadSchema = PRIVATE_PAYLOAD_SCHEMAS[input.kind];
  requirePrivatePayload(privatePayload, privatePayloadSchema);
  const publicBase = canonicalPublicV2Snapshot(input.publicBase);
  const sidecar: CandidateJsonObject = {
    kind: input.kind,
    private_payload_schema: privatePayloadSchema,
    private_payload_sha256: await sha256Tagged(privatePayloadBytes),
    public_context_sha256: await publicContextDigest(input.kind, publicBase),
    schema: PRIVATE_SIDECAR_SCHEMA,
    schema_version: 2,
  };
  const sidecarSnapshot = canonicalPublicV2Snapshot(sidecar);
  const opening = canonicalPublicV2Snapshot({
    nonce_b64url: encodeNonce(nonce),
    schema: PRIVATE_SIDECAR_OPENING_SCHEMA,
    schema_version: 2,
    sidecar: sidecarSnapshot,
  });
  const openingBytes = canonicalPublicV2Bytes(opening);
  return {
    commitment: await sidecarCommitment(nonce, sidecarSnapshot),
    dispatchSafety: "UNPERSISTED_CANDIDATE_NOT_DISPATCH_SAFE",
    nonceBytes: Uint8Array.from(nonce),
    nonceFingerprintSha256: await sha256Tagged(nonce),
    opening,
    openingBytes,
    privatePayloadBytes: Uint8Array.from(privatePayloadBytes),
    sidecar: sidecarSnapshot,
  };
}

/** Broker-side opening verification; public consumers cannot perform it. */
export async function verifySidecarOpening(input: {
  readonly kind: SidecarKind;
  readonly opening: unknown;
  readonly privatePayloadBytes: Uint8Array;
  readonly publicDocument: CandidateJsonObject;
}): Promise<void> {
  const privatePayloadBytes = copyPublicV2Bytes(
    input.privatePayloadBytes,
    "PUBLIC_V2_PRIVATE_PAYLOAD_SIZE_INVALID",
  );
  const privatePayload = parseCanonicalPublicV2(privatePayloadBytes);
  const publicDocument = canonicalPublicV2Snapshot(input.publicDocument);
  const commitment = requireDigest(
    publicDocument.private_sidecar_commitment,
    "PUBLIC_V2_COMMITMENT_INVALID",
  );
  const opening = parseOpening(input.opening);
  const sidecar = objectField(opening, "sidecar", "PUBLIC_V2_OPENING_INVALID");
  const nonce = decodeNonce(stringField(opening, "nonce_b64url", "PUBLIC_V2_NONCE_INVALID"));
  requireKindField(sidecar, input.kind);
  const payloadSchema = stringField(
    sidecar,
    "private_payload_schema",
    "PUBLIC_V2_PRIVATE_SCHEMA_INVALID",
  );
  candidateAssert(
    payloadSchema === PRIVATE_PAYLOAD_SCHEMAS[input.kind],
    "PUBLIC_V2_PRIVATE_SCHEMA_MISMATCH",
  );
  requirePrivatePayload(privatePayload, payloadSchema);
  candidateAssert(
    sidecar.private_payload_sha256 === (await sha256Tagged(privatePayloadBytes)),
    "PUBLIC_V2_PRIVATE_PAYLOAD_DIGEST_MISMATCH",
  );
  const publicBase = stripCommittedDocument(publicDocument, input.kind);
  candidateAssert(
    sidecar.public_context_sha256 === (await publicContextDigest(input.kind, publicBase)),
    "PUBLIC_V2_PUBLIC_CONTEXT_MISMATCH",
  );
  candidateAssert(
    commitment === (await sidecarCommitment(nonce, sidecar)),
    "PUBLIC_V2_COMMITMENT_MISMATCH",
  );
}

/** Require both derived fields before stripping, avoiding construction ambiguity. */
export function stripCommittedDocument(
  document: CandidateJsonObject,
  kind: SidecarKind,
): CandidateJsonObject {
  requireKind(kind);
  const snapshot = canonicalPublicV2Snapshot(document);
  const binding = DOCUMENT_BINDINGS[kind];
  candidateAssert(snapshot.schema === binding.schema, "PUBLIC_V2_DOCUMENT_SCHEMA_MISMATCH");
  requireDigest(snapshot.private_sidecar_commitment, "PUBLIC_V2_COMMITMENT_INVALID");
  requireDigest(snapshot[binding.terminalId], "PUBLIC_V2_TERMINAL_ID_INVALID");
  return cloneWithout(snapshot, new Set(["private_sidecar_commitment", binding.terminalId]));
}

export function parseOpening(value: unknown): CandidateJsonObject {
  const opening = exactObject(
    canonicalPublicV2Snapshot(value),
    OPENING_KEYS,
    "PUBLIC_V2_OPENING_INVALID",
  );
  literalField(opening, "schema", PRIVATE_SIDECAR_OPENING_SCHEMA, "PUBLIC_V2_OPENING_INVALID");
  literalField(opening, "schema_version", 2, "PUBLIC_V2_OPENING_INVALID");
  decodeNonce(stringField(opening, "nonce_b64url", "PUBLIC_V2_NONCE_INVALID"));
  parseSidecar(objectField(opening, "sidecar", "PUBLIC_V2_OPENING_INVALID"));
  return canonicalPublicV2Snapshot(opening);
}

export function parseSidecar(value: unknown): CandidateJsonObject {
  const sidecar = exactObject(
    canonicalPublicV2Snapshot(value),
    SIDECAR_KEYS,
    "PUBLIC_V2_SIDECAR_INVALID",
  );
  const kind = requireKindField(sidecar);
  candidateAssert(
    sidecar.private_payload_schema === PRIVATE_PAYLOAD_SCHEMAS[kind],
    "PUBLIC_V2_PRIVATE_SCHEMA_MISMATCH",
  );
  requireDigest(sidecar.private_payload_sha256, "PUBLIC_V2_PRIVATE_PAYLOAD_DIGEST_INVALID");
  requireDigest(sidecar.public_context_sha256, "PUBLIC_V2_PUBLIC_CONTEXT_INVALID");
  literalField(sidecar, "schema", PRIVATE_SIDECAR_SCHEMA, "PUBLIC_V2_SIDECAR_INVALID");
  literalField(sidecar, "schema_version", 2, "PUBLIC_V2_SIDECAR_INVALID");
  return canonicalPublicV2Snapshot(sidecar);
}

export async function sidecarCommitment(
  nonce: Uint8Array,
  sidecarValue: CandidateJsonObject,
): Promise<DigestSha256> {
  requireNonce(nonce);
  const sidecar = parseSidecar(sidecarValue);
  const sidecarBytes = canonicalPublicV2Bytes(sidecar);
  const domain = new TextEncoder().encode(COMMITMENT_DOMAIN);
  const frame = new Uint8Array(domain.length + 1 + 4 + nonce.length + 8 + sidecarBytes.length);
  frame.set(domain, 0);
  const view = new DataView(frame.buffer);
  let offset = domain.length;
  frame[offset] = 0;
  offset += 1;
  view.setUint32(offset, nonce.length, false);
  offset += 4;
  frame.set(nonce, offset);
  offset += nonce.length;
  view.setBigUint64(offset, BigInt(sidecarBytes.length), false);
  offset += 8;
  frame.set(sidecarBytes, offset);
  return sha256Tagged(frame);
}

function requirePrivatePayload(payload: CandidateJsonObject, schema: string): void {
  candidateAssert(payload.schema === schema, "PUBLIC_V2_PRIVATE_SCHEMA_MISMATCH");
}

function requireNonce(nonce: Uint8Array): void {
  candidateAssert(nonce.byteLength === 32, "PUBLIC_V2_NONCE_INVALID");
  candidateAssert(
    nonce.some((byte) => byte !== 0),
    "PUBLIC_V2_NONCE_INVALID",
  );
}

function encodeNonce(nonce: Uint8Array): string {
  requireNonce(nonce);
  let binary = "";
  for (const byte of nonce) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  candidateAssert(encoded.length === 43, "PUBLIC_V2_NONCE_INVALID");
  return encoded;
}

function decodeNonce(value: string): Uint8Array {
  candidateAssert(/^[A-Za-z0-9_-]{43}$/u.test(value), "PUBLIC_V2_NONCE_INVALID");
  let binary: string;
  try {
    binary = atob(`${value.replaceAll("-", "+").replaceAll("_", "/")}=`);
  } catch {
    throw new CandidatePublicV2Error("PUBLIC_V2_NONCE_INVALID");
  }
  const nonce = Uint8Array.from(binary, (unit) => unit.charCodeAt(0));
  requireNonce(nonce);
  candidateAssert(encodeNonce(nonce) === value, "PUBLIC_V2_NONCE_INVALID");
  return nonce;
}

function requireKind(value: string): asserts value is SidecarKind {
  candidateAssert(KINDS.has(value as SidecarKind), "PUBLIC_V2_SIDECAR_KIND_INVALID");
}

function requireKindField(sidecar: CandidateJsonObject, expected?: SidecarKind): SidecarKind {
  const kind = stringField(sidecar, "kind", "PUBLIC_V2_SIDECAR_KIND_INVALID");
  requireKind(kind);
  candidateAssert(expected === undefined || kind === expected, "PUBLIC_V2_SIDECAR_KIND_MISMATCH");
  return kind;
}
