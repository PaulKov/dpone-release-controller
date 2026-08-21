import { validateInventory, type B2VersionObserver, type InventorySummary } from "./b2-inventory";
import { sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import type { ActivationWorm } from "./types";

const RETENTION_MILLISECONDS = 2557 * 86_400_000;

/** Observer-only reconciliation after a writer dispatch became ambiguous. */
export async function reconcileExactObject(input: {
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly digest: string;
  readonly key: string;
  readonly observer: B2VersionObserver;
}): Promise<ActivationWorm> {
  const summary = await exactSummary(input);
  const versionId = summary.latestVersionId;
  if (versionId === null || summary.identicalVersionIds.length === 0) {
    throw new BrokerError("B2_RECONCILIATION_PENDING", 503, true);
  }
  if (summary.identicalVersionIds.length !== 1 || summary.identicalVersionIds[0] !== versionId) {
    throw new BrokerError("B2_RECONCILIATION_DUPLICATE_DISPATCH", 409, false);
  }
  const retentionUntil = summary.retentionByVersion.get(versionId);
  if (retentionUntil === undefined) {
    throw new BrokerError("B2_RECONCILIATION_PENDING", 503, true);
  }
  return { digest: input.digest, key: input.key, retentionUntil, versionId };
}

/** Durable pre-dispatch proof that the deterministic key has no versions. */
export async function assertExactObjectAbsent(input: {
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly digest: string;
  readonly key: string;
  readonly observer: B2VersionObserver;
}): Promise<string> {
  const summary = await exactSummary(input);
  if (summary.identicalVersionIds.length !== 0 || summary.latestVersionId !== null) {
    throw new BrokerError("B2_ABSENCE_CONFLICT", 409, false);
  }
  return summary.inventoryDigest;
}

async function exactSummary(input: {
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly digest: string;
  readonly key: string;
  readonly observer: B2VersionObserver;
}): Promise<InventorySummary> {
  const committedAt = Date.parse(input.committedAt);
  if (
    input.bytes.byteLength === 0 ||
    !Number.isFinite(committedAt) ||
    new Date(committedAt).toISOString() !== input.committedAt ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.digest) ||
    !timingSafeEqual(`sha256:${await sha256Hex(input.bytes)}`, input.digest)
  ) {
    throw new BrokerError("B2_RECONCILIATION_INPUT_INVALID", 500, false);
  }
  const inventory = await input.observer.inspectExactKey(input.key);
  return validateInventory(
    inventory,
    input.key,
    input.bytes.byteLength,
    input.digest,
    await sha1Hex(input.bytes),
    committedAt + RETENTION_MILLISECONDS,
  );
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
