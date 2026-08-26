import {
  inventoryDigestPayload,
  type B2ObservedVersion,
  type B2VersionInventory,
  type B2VersionObserver,
  type B2Writer,
} from "../src/b2";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type {
  WormExactObjectEffectInput,
  WormExactObjectEffectPins,
} from "../src/worm-exact-object-effect-contract";

export const EFFECT_COMMITTED_AT = "2026-08-19T12:00:00.000Z";
export const EFFECT_RETENTION_UNTIL = "2034-08-20T12:00:00.000Z";
export const WRITER_VERSION_ID = "b2-version-a";

export const EFFECT_PINS: WormExactObjectEffectPins = Object.freeze({
  executorServiceIdentity:
    "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/dpone-worm-mirror@11111111-1111-4111-8111-111111111111",
  executorVersionId: "11111111-1111-4111-8111-111111111111",
  observerServiceIdentity:
    "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/dpone-worm-observer@22222222-2222-4222-8222-222222222222",
  observerVersionId: "22222222-2222-4222-8222-222222222222",
});

export type ExactObjectFailureMode =
  | "DIVERGENT"
  | "DUPLICATE"
  | "PRE_WRITE_ERROR"
  | "RESPONSE_LOSS"
  | "SUCCESS"
  | "WRONG_LATEST";

interface StoredExactObject {
  readonly versions: readonly B2ObservedVersion[];
}

/** Split in-memory roles with deterministic provider faults and call counts. */
export class FakeExactObjectB2 {
  private readonly objects = new Map<string, StoredExactObject>();
  private mode: ExactObjectFailureMode = "SUCCESS";

  public observerCalls = 0;
  public writerCalls = 0;
  public onObserve: (() => void | Promise<void>) | undefined;
  public onWrite: (() => void | Promise<void>) | undefined;

  public readonly writer: B2Writer = {
    uploadExact: async (input) => {
      this.writerCalls += 1;
      if (this.onWrite !== undefined) await this.onWrite();
      if (this.mode === "PRE_WRITE_ERROR") {
        throw new Error("simulated pre-persistence writer failure");
      }
      this.persist(input, this.mode);
      if (this.mode === "RESPONSE_LOSS" || this.mode === "DUPLICATE") {
        throw new Error("simulated writer response loss");
      }
      return { versionId: WRITER_VERSION_ID };
    },
  };

  public readonly observer: B2VersionObserver = {
    inspectExactKey: async (key) => {
      this.observerCalls += 1;
      if (this.onObserve !== undefined) await this.onObserve();
      return inventory(key, this.objects.get(key)?.versions ?? []);
    },
  };

  public setMode(mode: ExactObjectFailureMode): void {
    this.mode = mode;
  }

  public persistExact(input: Parameters<B2Writer["uploadExact"]>[0]): void {
    this.persist(input, "SUCCESS");
  }

  private persist(
    input: Parameters<B2Writer["uploadExact"]>[0],
    mode: ExactObjectFailureMode,
  ): void {
    const exact = version(input, WRITER_VERSION_ID, mode !== "WRONG_LATEST");
    const versions =
      mode === "DUPLICATE"
        ? [{ ...exact, isLatest: false }, version(input, "b2-version-b", true)]
        : mode === "DIVERGENT"
          ? [{ ...exact, digest: `sha256:${"f".repeat(64)}` }]
          : [exact];
    this.objects.set(input.key, { versions });
  }
}

export async function exactEffectInput(byteLength?: number): Promise<WormExactObjectEffectInput> {
  const body =
    byteLength === undefined
      ? canonicalBytes({ payload: "exact-object", schema: "dpone.test.v1" })
      : new Uint8Array(byteLength).fill(0x61);
  const digest = `sha256:${await sha256Hex(body)}`;
  return {
    canonicalBytes: body,
    committedAt: EFFECT_COMMITTED_AT,
    digest,
    key:
      "receipts/v1/activation-evidence/33333333-3333-4333-8333-333333333333/" +
      `generic_worm_effect/${digest.slice("sha256:".length)}.json`,
    pins: EFFECT_PINS,
  };
}

export async function inventory(
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

export async function contentSha1(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function version(
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
    retentionUntil: EFFECT_RETENTION_UNTIL,
    size: input.canonicalBytes.byteLength,
    versionId,
  };
}
