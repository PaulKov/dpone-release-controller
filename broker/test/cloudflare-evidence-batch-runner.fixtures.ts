import {
  inventoryDigestPayload,
  type B2ObservedVersion,
  type B2VersionInventory,
  type B2VersionObserver,
  type B2Writer,
} from "../src/b2";
import { canonicalBytes, sha256Hex } from "../src/canonical";

type FailureMode = "DUPLICATE" | "OBSERVER_LOSS" | "PUT_LOSS" | "ZERO";

interface StoredObject {
  readonly contentSha1: string;
  readonly digest: string;
  readonly size: number;
  readonly versions: B2ObservedVersion[];
}

/** In-memory split writer/observer roles for deterministic runner crash tests. */
export class CloudflareEvidenceBatchFakeB2 {
  private readonly modes = new Map<string, FailureMode>();
  private readonly objects = new Map<string, StoredObject>();
  private readonly observerLosses = new Set<string>();
  private readonly writeCounts = new Map<string, number>();

  public readonly writer: B2Writer = {
    uploadExact: async (input) => {
      this.writeCounts.set(input.key, this.writesFor(input.key) + 1);
      const mode = this.modes.get(input.key);
      if (mode === "ZERO") throw new Error("simulated write failure before persistence");
      const base = this.version(input, `b2-${await sha256Hex(input.key)}-a`, mode !== "DUPLICATE");
      const versions =
        mode === "DUPLICATE"
          ? [
              { ...base, isLatest: false },
              this.version(input, `b2-${await sha256Hex(input.key)}-b`, true),
            ]
          : [base];
      this.objects.set(input.key, {
        contentSha1: input.contentSha1,
        digest: input.digest,
        size: input.canonicalBytes.byteLength,
        versions,
      });
      if (mode === "PUT_LOSS" || mode === "DUPLICATE") {
        throw new Error("simulated response loss after persistence");
      }
      return { versionId: base.versionId };
    },
  };

  public readonly observer: B2VersionObserver = {
    inspectExactKey: async (key) => {
      const object = this.objects.get(key);
      if (
        object !== undefined &&
        this.modes.get(key) === "OBSERVER_LOSS" &&
        !this.observerLosses.has(key)
      ) {
        this.observerLosses.add(key);
        throw new Error("simulated observer response loss");
      }
      return this.inventory(key, object?.versions ?? []);
    },
  };

  public fail(key: string, mode: FailureMode): void {
    this.modes.set(key, mode);
  }

  public writesFor(key: string): number {
    return this.writeCounts.get(key) ?? 0;
  }

  public totalWrites(): number {
    return [...this.writeCounts.values()].reduce((total, count) => total + count, 0);
  }

  private version(
    input: Parameters<B2Writer["uploadExact"]>[0],
    versionId: string,
    isLatest: boolean,
  ): B2ObservedVersion {
    return {
      contentSha1: input.contentSha1,
      deleteMarker: false,
      digest: input.digest,
      isLatest,
      retentionMode: "COMPLIANCE",
      retentionUntil: "2034-08-20T12:00:00.000Z",
      size: input.canonicalBytes.byteLength,
      versionId,
    };
  }

  private async inventory(
    key: string,
    versions: readonly B2ObservedVersion[],
  ): Promise<B2VersionInventory> {
    const unsigned: B2VersionInventory = {
      bucket: {
        defaultRetentionDays: 2557,
        encryption: "SSE-B2",
        objectLockEnabled: true,
        type: "allPrivate",
      },
      digest: `sha256:${"0".repeat(64)}`,
      key,
      versions,
    };
    return {
      ...unsigned,
      digest: `sha256:${await sha256Hex(canonicalBytes(inventoryDigestPayload(unsigned)))}`,
    };
  }
}
