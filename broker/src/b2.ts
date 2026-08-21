import { sha256Hex, timingSafeEqual } from "./canonical";
import { isAllowedB2ExactKey } from "./b2-key";
import { LIMITS, TRUST } from "./config";
import { BrokerError } from "./errors";
import type { MirrorResult } from "./types";
import type { B2VersionObserver, InventorySummary } from "./b2-inventory";
import { validateInventory, validateVersionId } from "./b2-inventory";

export type { B2ObservedVersion, B2VersionInventory, B2VersionObserver } from "./b2-inventory";
export { inventoryDigestPayload } from "./b2-inventory";

const RETENTION_DAYS = 2557;

export interface B2WriteResult {
  readonly versionId: string;
}

export interface B2Writer {
  uploadExact(input: {
    readonly canonicalBytes: Uint8Array;
    readonly contentSha1: string;
    readonly digest: string;
    readonly key: string;
  }): Promise<B2WriteResult>;
}

/**
 * Orchestrates an append-only mirror without giving the writer any read/list
 * capability. The isolated observer is the only component allowed to list,
 * download and inspect retention for the deterministic exact key.
 */
export class B2ReceiptMirror {
  private readonly exact: B2ExactObjectMirror;

  public constructor(writer: B2Writer, observer: B2VersionObserver) {
    this.exact = new B2ExactObjectMirror(writer, observer);
  }

  public async mirror(input: {
    readonly canonicalBytes: Uint8Array;
    readonly committedAt: string;
    readonly digest: string;
    readonly releaseIdentityId: string;
    readonly sequence: number;
    readonly tag: string;
    readonly targetRepoId: number;
  }): Promise<MirrorResult> {
    validateBinding(input);
    const streamHash = await sha256Hex(input.releaseIdentityId);
    const key = receiptKey(
      input.targetRepoId,
      input.tag,
      streamHash,
      input.sequence,
      input.digest.slice("sha256:".length),
    );
    return this.exact.mirror({
      canonicalBytes: input.canonicalBytes,
      committedAt: input.committedAt,
      digest: input.digest,
      key,
    });
  }
}

/** Mirrors one already-derived deterministic key through isolated B2 roles. */
export class B2ExactObjectMirror {
  public constructor(
    private readonly writer: B2Writer,
    private readonly observer: B2VersionObserver,
  ) {}

  public async mirror(input: {
    readonly canonicalBytes: Uint8Array;
    readonly committedAt: string;
    readonly digest: string;
    readonly key: string;
  }): Promise<MirrorResult> {
    validateExactMirrorInput(input);
    const committedAtMs = canonicalTimestampMillis(input.committedAt);
    const minimumRetentionMs = committedAtMs + RETENTION_DAYS * 86_400_000;
    const computedDigest = `sha256:${await sha256Hex(input.canonicalBytes)}`;
    if (!timingSafeEqual(input.digest, computedDigest)) {
      throw new BrokerError("MIRROR_DIGEST_MISMATCH", 500, false);
    }
    const contentSha1 = await sha1Hex(input.canonicalBytes);
    const existing = await this.inspect(
      input.key,
      input.canonicalBytes.byteLength,
      input.digest,
      contentSha1,
      minimumRetentionMs,
    );
    if (existing.identicalVersionIds.length > 0) {
      return resultFor(input.key, input.digest, requireSingleExactVersion(existing), existing);
    }

    let written: B2WriteResult;
    try {
      written = await this.writer.uploadExact({
        canonicalBytes: input.canonicalBytes,
        contentSha1,
        digest: input.digest,
        key: input.key,
      });
      validateVersionId(written.versionId);
    } catch {
      const recovered = await this.inspect(
        input.key,
        input.canonicalBytes.byteLength,
        input.digest,
        contentSha1,
        minimumRetentionMs,
      );
      if (recovered.identicalVersionIds.length === 0) {
        throw new BrokerError("B2_PUT_AMBIGUOUS", 503, true);
      }
      return resultFor(input.key, input.digest, requireSingleExactVersion(recovered), recovered);
    }

    const confirmed = await this.inspect(
      input.key,
      input.canonicalBytes.byteLength,
      input.digest,
      contentSha1,
      minimumRetentionMs,
    );
    if (requireSingleExactVersion(confirmed) !== written.versionId) {
      throw new BrokerError("B2_OBSERVER_VERSION_MISSING", 503, true);
    }
    return resultFor(input.key, input.digest, written.versionId, confirmed);
  }

  private async inspect(
    key: string,
    expectedSize: number,
    expectedDigest: string,
    expectedSha1: string,
    minimumRetentionMs: number,
  ): Promise<InventorySummary> {
    const inventory = await this.observer.inspectExactKey(key);
    return validateInventory(
      inventory,
      key,
      expectedSize,
      expectedDigest,
      expectedSha1,
      minimumRetentionMs,
    );
  }
}

function requireSingleExactVersion(summary: InventorySummary): string {
  const [only] = summary.identicalVersionIds;
  if (
    only === undefined ||
    summary.identicalVersionIds.length !== 1 ||
    summary.latestVersionId !== only
  ) {
    throw new BrokerError("B2_DUPLICATE_DISPATCH_CONFLICT", 409, false);
  }
  return only;
}

function resultFor(
  key: string,
  digest: string,
  versionId: string,
  summary: InventorySummary,
): MirrorResult {
  const retentionUntil = summary.retentionByVersion.get(versionId);
  if (retentionUntil === undefined) {
    throw new BrokerError("B2_OBSERVER_VERSION_MISSING", 503, true);
  }
  return {
    digest,
    identicalVersionIds: summary.identicalVersionIds,
    inventoryDigest: summary.inventoryDigest,
    key,
    retentionUntil,
    versionId,
  };
}

function validateBinding(input: {
  readonly canonicalBytes: Uint8Array;
  readonly digest: string;
  readonly releaseIdentityId: string;
  readonly sequence: number;
  readonly targetRepoId: number;
}): void {
  if (
    input.targetRepoId !== TRUST.targetRepositoryId ||
    !Number.isSafeInteger(input.sequence) ||
    input.sequence < 0 ||
    input.sequence > 1_000_000 ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.releaseIdentityId) ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.digest) ||
    input.canonicalBytes.byteLength === 0 ||
    input.canonicalBytes.byteLength > LIMITS.bodyBytes
  ) {
    throw new BrokerError("MIRROR_BINDING_INVALID", 500, false);
  }
}

function validateExactMirrorInput(input: {
  readonly canonicalBytes: Uint8Array;
  readonly digest: string;
  readonly key: string;
}): void {
  if (
    !isAllowedB2ExactKey(input.key) ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.digest) ||
    input.canonicalBytes.byteLength === 0 ||
    input.canonicalBytes.byteLength > LIMITS.bodyBytes
  ) {
    throw new BrokerError("MIRROR_BINDING_INVALID", 500, false);
  }
}

function canonicalTimestampMillis(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new BrokerError("MIRROR_COMMITTED_AT_INVALID", 500, false);
  }
  const canonical = new Date(parsed).toISOString().replace(".000Z", "Z");
  if (canonical !== value) {
    throw new BrokerError("MIRROR_COMMITTED_AT_INVALID", 500, false);
  }
  return parsed;
}

function receiptKey(
  targetRepoId: number,
  tag: string,
  streamHash: string,
  sequence: number,
  digest: string,
): string {
  if (
    !/^v\d+\.\d+\.\d+$/u.test(tag) ||
    !/^[0-9a-f]{64}$/u.test(streamHash) ||
    !/^[0-9a-f]{64}$/u.test(digest)
  ) {
    throw new BrokerError("B2_KEY_COMPONENT_INVALID", 500, false);
  }
  return [
    "receipts",
    "v1",
    String(targetRepoId),
    tag,
    streamHash,
    `${String(sequence).padStart(12, "0")}-${digest}.json`,
  ].join("/");
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
