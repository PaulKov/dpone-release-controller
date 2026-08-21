import { assertExactObjectAbsent, reconcileExactObject } from "../b2-exact-reconciliation";
import type { B2VersionObserver, B2Writer } from "../b2";
import { canonicalBytes } from "../canonical";
import {
  CLOUDFLARE_EVIDENCE_SLOT_COUNT,
  type CloudflareEvidenceBatchAction,
  type CloudflareEvidenceBatchSlot,
} from "../cloudflare-evidence-batch-contract";
import { BrokerError } from "../errors";
import type { ActivationWorm } from "../types";
import { sha1Hex } from "./b2-native-provider";

const DEFAULT_CONCURRENCY = 4;
const ABSOLUTE_DEADLINE_MS = 45_000;

export interface CloudflareEvidenceBatchJournal {
  accept(slotIndex: number, writerVersionId: string): Promise<void> | void;
  confirm(slotIndex: number, worm: ActivationWorm): Promise<void> | void;
  confirmed():
    | Promise<readonly CloudflareEvidenceBatchSlot[]>
    | readonly CloudflareEvidenceBatchSlot[];
  hold(slotIndex: number): Promise<void> | void;
  markAbsent(slotIndex: number, inventorySha256: string): Promise<void> | void;
  next(slotIndex: number): Promise<CloudflareEvidenceBatchAction> | CloudflareEvidenceBatchAction;
}

/**
 * Executes a sealed sanitized batch with injected writer/observer roles. The
 * writer is invoked only from durable ABSENT state, and every ambiguous or
 * accepted dispatch is resolved solely through the read-only observer.
 */
export class CloudflareEvidenceBatchRunner {
  public constructor(
    private readonly journal: CloudflareEvidenceBatchJournal,
    private readonly writer: B2Writer,
    private readonly observer: B2VersionObserver,
    private readonly now: () => number = Date.now,
    private readonly concurrency = DEFAULT_CONCURRENCY,
  ) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 4) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_CONCURRENCY_INVALID", 500, false);
    }
  }

  public async run(): Promise<readonly CloudflareEvidenceBatchSlot[]> {
    const startedAt = this.now();
    const errors: (Error | undefined)[] = Array.from(
      { length: CLOUDFLARE_EVIDENCE_SLOT_COUNT },
      () => undefined,
    );
    let nextIndex = 0;
    await Promise.all(
      Array.from({ length: this.concurrency }, async () => {
        for (;;) {
          const slotIndex = nextIndex;
          nextIndex += 1;
          if (slotIndex >= CLOUDFLARE_EVIDENCE_SLOT_COUNT) return;
          try {
            await this.completeSlot(slotIndex, startedAt);
          } catch (error) {
            errors[slotIndex] = normalizeError(error);
          }
        }
      }),
    );
    const failure = errors.find((error) => error !== undefined);
    if (failure !== undefined) throw failure;
    return this.journal.confirmed();
  }

  private async completeSlot(slotIndex: number, startedAt: number): Promise<void> {
    for (;;) {
      this.assertDeadline(startedAt);
      const action = await this.journal.next(slotIndex);
      const input = await objectInput(action.slot);
      try {
        if (action.action === "CHECK_ABSENCE") {
          await this.journal.markAbsent(
            slotIndex,
            await assertExactObjectAbsent({ ...input, observer: this.observer }),
          );
          continue;
        }
        if (action.action === "DISPATCH") {
          try {
            const result = await this.writer.uploadExact({
              canonicalBytes: input.bytes,
              contentSha1: input.contentSha1,
              digest: input.digest,
              key: input.key,
            });
            await this.journal.accept(slotIndex, result.versionId);
          } catch {
            // IN_FLIGHT is deliberately retained. Only an observer requery may
            // classify a response-loss or provider timeout from this point.
          }
          continue;
        }
        if (action.action === "RECONCILE") {
          await this.journal.confirm(
            slotIndex,
            await reconcileExactObject({ ...input, observer: this.observer }),
          );
          continue;
        }
        return;
      } catch (error) {
        if (error instanceof BrokerError && !error.retryable) {
          await this.journal.hold(slotIndex);
        }
        throw error;
      }
    }
  }

  private assertDeadline(startedAt: number): void {
    const elapsed = this.now() - startedAt;
    if (!Number.isSafeInteger(elapsed) || elapsed < 0 || elapsed > ABSOLUTE_DEADLINE_MS) {
      throw new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_TIMEOUT", 503, true);
    }
  }
}

async function objectInput(slot: CloudflareEvidenceBatchSlot): Promise<{
  readonly bytes: Uint8Array;
  readonly committedAt: string;
  readonly contentSha1: string;
  readonly digest: string;
  readonly key: string;
}> {
  const bytes = canonicalBytes(slot.sanitized.record);
  return {
    bytes,
    committedAt: slot.committedAt,
    contentSha1: await sha1Hex(bytes),
    digest: slot.sanitized.recordSha256,
    key: slot.expectedWormKey,
  };
}

function normalizeError(value: unknown): Error {
  return value instanceof Error
    ? value
    : new BrokerError("CLOUDFLARE_EVIDENCE_BATCH_UNEXPECTED_ERROR", 500, false);
}
