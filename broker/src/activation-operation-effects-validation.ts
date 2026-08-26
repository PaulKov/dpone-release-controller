import { sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type {
  ActivationOperationIssuanceRow,
  ActivationOperationSlotRow,
} from "./activation-operation-schema";
import type { ActivationWorm } from "./types";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const CLOUDFLARE_EVIDENCE_RETENTION_MS = 2_557 * 24 * 60 * 60 * 1_000;

export interface ActivationCloudflareAnchor {
  readonly authorityRole: string | null;
  readonly recordId: string;
  readonly recordSha256: string;
  readonly worm: ActivationWorm;
}

export function isOperationDigest(value: string): boolean {
  return DIGEST.test(value);
}

export function validateOperationAnchors(
  anchors: readonly ActivationCloudflareAnchor[],
  committedAt: string,
  expectedObserverVersion: string,
  expectedBatchId?: string,
): void {
  requireOperationTimestamp(committedAt);
  const minimumRetention = Date.parse(committedAt) + CLOUDFLARE_EVIDENCE_RETENTION_MS;
  if (anchors.length !== 15) operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_ANCHORS_INVALID");
  const recordIds = new Set<string>();
  const keys = new Set<string>();
  const versions = new Set<string>();
  for (let index = 0; index < anchors.length; index += 1) {
    const anchor = requireOperationAnchor(anchors[index]);
    const expectedRole = SERVICE_AUTHORITY_ROLES[index] ?? null;
    const evidenceKind =
      anchor.authorityRole === null
        ? "cloudflare_network_surface"
        : "cloudflare_service_deployments";
    if (
      anchor.authorityRole !== expectedRole ||
      !DIGEST.test(anchor.recordId) ||
      !DIGEST.test(anchor.recordSha256) ||
      anchor.worm.digest !== anchor.recordSha256 ||
      anchor.worm.key !==
        expectedCloudflareAnchorKey(
          expectedObserverVersion,
          evidenceKind,
          anchor.recordId,
          expectedBatchId,
        ) ||
      !/^[A-Za-z0-9._=-]{1,512}$/u.test(anchor.worm.versionId) ||
      !isCanonicalTimestamp(anchor.worm.retentionUntil) ||
      Date.parse(anchor.worm.retentionUntil) < minimumRetention ||
      recordIds.has(anchor.recordId) ||
      keys.has(anchor.worm.key) ||
      versions.has(anchor.worm.versionId)
    ) {
      operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_ANCHORS_INVALID");
    }
    recordIds.add(anchor.recordId);
    keys.add(anchor.worm.key);
    versions.add(anchor.worm.versionId);
  }
}

function expectedCloudflareAnchorKey(
  observerVersion: string,
  evidenceKind: string,
  recordId: string,
  batchId: string | undefined,
): string {
  const recordHex = recordId.slice("sha256:".length);
  return batchId === undefined
    ? `receipts/v1/cloudflare-observations/${observerVersion}/${evidenceKind}/${recordHex}.json`
    : `receipts/v1/cloudflare-observations-v2/${observerVersion}/${batchId.slice("sha256:".length)}/${evidenceKind}/${recordHex}.json`;
}

export function validateOperationWorm(
  worm: ActivationWorm,
  expectedDigest: string | null,
  committedAt: string | null,
  expectedKey: string | null,
): void {
  if (committedAt === null) operationEffectFail("ACTIVATION_OPERATION_WORM_INVALID");
  requireOperationTimestamp(committedAt);
  const minimumRetention = Date.parse(committedAt) + CLOUDFLARE_EVIDENCE_RETENTION_MS;
  if (
    expectedDigest === null ||
    expectedKey === null ||
    worm.digest !== expectedDigest ||
    worm.key !== expectedKey ||
    worm.versionId.length === 0 ||
    !isCanonicalTimestamp(worm.retentionUntil) ||
    Date.parse(worm.retentionUntil) < minimumRetention
  ) {
    operationEffectFail("ACTIVATION_OPERATION_WORM_INVALID");
  }
}

export function assertOperationDelegationChronology(
  issuance: ActivationOperationIssuanceRow,
  row: ActivationOperationSlotRow,
  committedAt: string,
  nowMs: number,
): void {
  requireOperationTimestamp(issuance.issued_at);
  requireOperationTimestamp(issuance.fresh_until);
  requireOperationTimestamp(committedAt);
  if (!Number.isSafeInteger(nowMs)) operationEffectFail("ACTIVATION_OPERATION_TIME_INVALID");
  const issued = Date.parse(issuance.issued_at);
  const freshUntil = Date.parse(issuance.fresh_until);
  const committed = Date.parse(committedAt);
  const observed = row.observed_at === null ? null : Date.parse(row.observed_at);
  if (
    issued > committed ||
    committed > nowMs ||
    nowMs - committed > 60_000 ||
    committed > freshUntil ||
    nowMs > freshUntil ||
    (row.slot_kind === "DIRECT_WORM" &&
      (observed === null || issued > observed || observed > committed))
  ) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_CHRONOLOGY_INVALID");
  }
}

export function expectedDirectOperationWormKey(
  row: ActivationOperationSlotRow,
  ingressWorkerVersion: string,
): string {
  if (row.frozen_payload_sha256 === null) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
  }
  const evidenceKind =
    row.slot_id === "TARGET_RULESET"
      ? "github_branch_ruleset"
      : row.slot_id === "CONTROLLER_OIDC" || row.slot_id === "TARGET_OIDC"
        ? "github_oidc_subject_customization"
        : operationEffectFail("ACTIVATION_OPERATION_SLOT_KIND_INVALID");
  return (
    `receipts/v1/activation-evidence/${ingressWorkerVersion}/${evidenceKind}/` +
    `${row.frozen_payload_sha256.slice("sha256:".length)}.json`
  );
}

export function assertOperationBindingKind(
  row: ActivationOperationSlotRow,
  batchId: string | null,
  effectId: string | null,
): void {
  if (
    (row.slot_kind === "CLOUDFLARE_BATCH" && batchId === null) ||
    (row.slot_kind === "DIRECT_WORM" && effectId === null) ||
    row.slot_kind === "READ_ONLY"
  ) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_BINDING_INVALID");
  }
}

export function assertConfirmedOperationEffect(
  row: ActivationOperationSlotRow,
  resultBytes: Uint8Array,
  resultSha256: string,
  worm: ActivationWorm,
): void {
  assertStoredOperationResult(row, resultBytes, resultSha256);
  if (
    row.worm_digest !== worm.digest ||
    row.worm_key !== worm.key ||
    row.worm_version_id !== worm.versionId ||
    row.worm_retention_until !== worm.retentionUntil
  ) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_CONFLICT");
  }
}

export function assertStoredOperationResult(
  row: ActivationOperationSlotRow,
  resultBytes: Uint8Array,
  resultSha256: string,
): void {
  if (
    row.result_bytes === null ||
    row.result_sha256 === null ||
    !timingSafeEqual(row.result_sha256, resultSha256) ||
    !operationBytesEqual(new Uint8Array(row.result_bytes), resultBytes)
  ) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_CONFLICT");
  }
}

export function assertStoredOperationAnchors(
  rows: readonly Record<string, SqlStorageValue>[],
  anchors: readonly ActivationCloudflareAnchor[],
): void {
  if (
    rows.length !== anchors.length ||
    rows.some((row, index) => {
      const anchor = requireOperationAnchor(anchors[index]);
      return (
        row.authority_role !== anchor.authorityRole ||
        row.record_id !== anchor.recordId ||
        row.record_sha256 !== anchor.recordSha256 ||
        row.worm_key !== anchor.worm.key ||
        row.worm_version_id !== anchor.worm.versionId ||
        row.worm_retention_until !== anchor.worm.retentionUntil
      );
    })
  ) {
    operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_ANCHORS_CONFLICT");
  }
}

export async function operationEffectDigest(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

export function operationEffectSnapshot(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength === 0 || bytes.byteLength > 1_048_576) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_SIZE_INVALID", 413);
  }
  return Uint8Array.from(bytes);
}

export function operationExactResultSnapshot(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength === 0 || bytes.byteLength > 65_536) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_RESULT_SIZE_INVALID", 413);
  }
  return Uint8Array.from(bytes);
}

export function operationRequestSnapshot(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength === 0 || bytes.byteLength > 65_536) {
    operationEffectFail("ACTIVATION_OPERATION_EFFECT_REQUEST_SIZE_INVALID", 413);
  }
  return Uint8Array.from(bytes);
}

export function operationWormSnapshot(worm: ActivationWorm): ActivationWorm {
  return {
    digest: worm.digest,
    key: worm.key,
    retentionUntil: worm.retentionUntil,
    versionId: worm.versionId,
  };
}

export function operationAnchorsSnapshot(
  anchors: readonly ActivationCloudflareAnchor[],
): readonly ActivationCloudflareAnchor[] {
  if (anchors.length !== 15) {
    operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_ANCHORS_INVALID");
  }
  return anchors.map((anchor) => ({
    authorityRole: anchor.authorityRole,
    recordId: anchor.recordId,
    recordSha256: anchor.recordSha256,
    worm: operationWormSnapshot(anchor.worm),
  }));
}

export function requireOperationTimestamp(value: string): void {
  if (!isCanonicalTimestamp(value)) {
    operationEffectFail("ACTIVATION_OPERATION_TIME_INVALID");
  }
}

function isCanonicalTimestamp(value: string): boolean {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

export function requireOperationSlot(
  value: ActivationOperationSlotRow | undefined,
): ActivationOperationSlotRow {
  if (value === undefined) operationEffectFail("ACTIVATION_OPERATION_SLOT_MISSING", 500);
  return value;
}

export function requireOperationAnchor(
  value: ActivationCloudflareAnchor | undefined,
): ActivationCloudflareAnchor {
  if (value === undefined) operationEffectFail("ACTIVATION_OPERATION_CLOUDFLARE_ANCHORS_INVALID");
  return value;
}

export function operationEffectFail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}

function operationBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
