import { describe, expect, it } from "vitest";

import {
  B2ReceiptMirror,
  inventoryDigestPayload,
  type B2ObservedVersion,
  type B2VersionInventory,
  type B2VersionObserver,
  type B2Writer,
} from "../src/b2";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import { TRUST } from "../src/config";

const COMMITTED_AT = "2026-08-15T12:00:00Z";
const VERSION_ID = "4_z-test-version-0001";

describe("B2 Object Lock mirror", () => {
  it("writes once and confirms exact version through the isolated observer", async () => {
    const store = mockB2(false);
    const input = await validInput("1", 7);
    const result = await new B2ReceiptMirror(store.writer, store.observer).mirror(input);
    expect(result.versionId).toBe(VERSION_ID);
    expect(result.identicalVersionIds).toEqual([VERSION_ID]);
    expect(store.writeCalls).toBe(1);
    expect(store.observerCalls).toBe(2);
    expect(store.lastContentSha1).toMatch(/^[0-9a-f]{40}$/u);
  });

  it("recovers timeout-after-write without a second upload authority", async () => {
    const store = mockB2(true);
    const result = await new B2ReceiptMirror(store.writer, store.observer).mirror(
      await validInput("2", 8),
    );
    expect(result.versionId).toBe(VERSION_ID);
    expect(store.writeCalls).toBe(1);
    expect(store.observerCalls).toBe(2);
  });

  it("treats an identical existing version as an idempotent replay", async () => {
    const store = mockB2(false);
    const mirror = new B2ReceiptMirror(store.writer, store.observer);
    const input = await validInput("3", 9);
    await mirror.mirror(input);
    await expect(mirror.mirror(input)).resolves.toMatchObject({
      versionId: VERSION_ID,
    });
    expect(store.writeCalls).toBe(1);
    expect(store.observerCalls).toBe(3);
  });

  it("rejects pre-existing duplicate exact versions without another upload", async () => {
    const input = await validInput("6", 12);
    const versions = await exactVersions(input, [
      { isLatest: false, versionId: VERSION_ID },
      { isLatest: true, versionId: "4_z-test-version-0002" },
    ]);
    const store = scriptedB2(versions, versions);

    await expect(new B2ReceiptMirror(store.writer, store.observer).mirror(input)).rejects.toThrow(
      "B2_DUPLICATE_DISPATCH_CONFLICT",
    );
    expect(store.writeCalls).toBe(0);
    expect(store.observerCalls).toBe(1);
  });

  it("rejects duplicate exact versions observed after one upload", async () => {
    const input = await validInput("7", 13);
    const versions = await exactVersions(input, [
      { isLatest: false, versionId: VERSION_ID },
      { isLatest: true, versionId: "4_z-test-version-0002" },
    ]);
    const store = scriptedB2([], versions);

    await expect(new B2ReceiptMirror(store.writer, store.observer).mirror(input)).rejects.toThrow(
      "B2_DUPLICATE_DISPATCH_CONFLICT",
    );
    expect(store.writeCalls).toBe(1);
    expect(store.observerCalls).toBe(2);
  });

  it("rejects a sole exact version that is not the latest without uploading", async () => {
    const input = await validInput("8", 14);
    const versions = await exactVersions(input, [{ isLatest: false, versionId: VERSION_ID }]);
    const store = scriptedB2(versions, versions);

    await expect(new B2ReceiptMirror(store.writer, store.observer).mirror(input)).rejects.toThrow(
      "B2_VERSION_INVENTORY_INVALID",
    );
    expect(store.writeCalls).toBe(0);
    expect(store.observerCalls).toBe(1);
  });

  it("rejects invalid binding and historical delete markers", async () => {
    const store = mockB2(false);
    const invalid = await validInput("4", 10);
    await expect(
      new B2ReceiptMirror(store.writer, store.observer).mirror({
        ...invalid,
        sequence: -1,
      }),
    ).rejects.toThrowError("MIRROR_BINDING_INVALID");

    const conflicted = mockB2(false);
    conflicted.injectDeleteMarker();
    await expect(
      new B2ReceiptMirror(conflicted.writer, conflicted.observer).mirror(await validInput("5", 11)),
    ).rejects.toThrowError("B2_VERSION_HISTORY_CONFLICT");
  });
});

async function validInput(identity: string, sequence: number) {
  const canonicalReceipt = new TextEncoder().encode(
    '{"schema":"dpone.release-receipt-envelope.v2"}',
  );
  return {
    canonicalBytes: canonicalReceipt,
    committedAt: COMMITTED_AT,
    digest: `sha256:${await sha256Hex(canonicalReceipt)}`,
    releaseIdentityId: `sha256:${identity.repeat(64)}`,
    sequence,
    tag: "v0.74.0",
    targetRepoId: TRUST.targetRepositoryId,
  };
}

function mockB2(timeoutAfterWrite: boolean): {
  readonly injectDeleteMarker: () => void;
  readonly lastContentSha1: string;
  readonly observer: B2VersionObserver;
  readonly observerCalls: number;
  readonly writeCalls: number;
  readonly writer: B2Writer;
} {
  const versions: B2ObservedVersion[] = [];
  let observerCalls = 0;
  let writeCalls = 0;
  let lastContentSha1 = "";
  let injectedDelete = false;
  const writer: B2Writer = {
    async uploadExact(input) {
      writeCalls += 1;
      lastContentSha1 = input.contentSha1;
      versions.splice(0, versions.length, {
        contentSha1: input.contentSha1,
        deleteMarker: false,
        digest: input.digest,
        isLatest: true,
        retentionMode: "COMPLIANCE",
        retentionUntil: retentionUntil(),
        size: input.canonicalBytes.byteLength,
        versionId: VERSION_ID,
      });
      if (timeoutAfterWrite) {
        throw new Error("simulated timeout after durable write");
      }
      return { versionId: VERSION_ID };
    },
  };
  const observer: B2VersionObserver = {
    async inspectExactKey(key) {
      observerCalls += 1;
      const observed = injectedDelete
        ? [
            {
              contentSha1: "0".repeat(40),
              deleteMarker: true,
              digest: null,
              isLatest: true,
              retentionMode: null,
              retentionUntil: null,
              size: 0,
              versionId: "delete-marker-version-0001",
            } satisfies B2ObservedVersion,
          ]
        : [...versions];
      const inventory: B2VersionInventory = {
        bucket: {
          defaultRetentionDays: 2557,
          encryption: "SSE-B2",
          objectLockEnabled: true,
          type: "allPrivate",
        },
        digest: `sha256:${"0".repeat(64)}`,
        key,
        versions: observed,
      };
      return {
        ...inventory,
        digest: `sha256:${await sha256Hex(canonicalBytes(inventoryDigestPayload(inventory)))}`,
      };
    },
  };
  return {
    injectDeleteMarker: () => {
      injectedDelete = true;
    },
    get lastContentSha1() {
      return lastContentSha1;
    },
    get observerCalls() {
      return observerCalls;
    },
    get writeCalls() {
      return writeCalls;
    },
    observer,
    writer,
  };
}

function retentionUntil(): string {
  return new Date(Date.parse(COMMITTED_AT) + 2557 * 86_400_000).toISOString();
}

async function exactVersions(
  input: Awaited<ReturnType<typeof validInput>>,
  versions: readonly { readonly isLatest: boolean; readonly versionId: string }[],
): Promise<readonly B2ObservedVersion[]> {
  const contentSha1 = await sha1Hex(input.canonicalBytes);
  return versions.map(({ isLatest, versionId }) => ({
    contentSha1,
    deleteMarker: false,
    digest: input.digest,
    isLatest,
    retentionMode: "COMPLIANCE",
    retentionUntil: retentionUntil(),
    size: input.canonicalBytes.byteLength,
    versionId,
  }));
}

function scriptedB2(
  initialVersions: readonly B2ObservedVersion[],
  confirmedVersions: readonly B2ObservedVersion[],
): {
  readonly observer: B2VersionObserver;
  readonly observerCalls: number;
  readonly writeCalls: number;
  readonly writer: B2Writer;
} {
  let observerCalls = 0;
  let writeCalls = 0;
  const writer: B2Writer = {
    async uploadExact() {
      writeCalls += 1;
      return { versionId: VERSION_ID };
    },
  };
  const observer: B2VersionObserver = {
    async inspectExactKey(key) {
      observerCalls += 1;
      const inventory: B2VersionInventory = {
        bucket: {
          defaultRetentionDays: 2557,
          encryption: "SSE-B2",
          objectLockEnabled: true,
          type: "allPrivate",
        },
        digest: `sha256:${"0".repeat(64)}`,
        key,
        versions: observerCalls === 1 ? initialVersions : confirmedVersions,
      };
      return {
        ...inventory,
        digest: `sha256:${await sha256Hex(canonicalBytes(inventoryDigestPayload(inventory)))}`,
      };
    },
  };
  return {
    get observerCalls() {
      return observerCalls;
    },
    get writeCalls() {
      return writeCalls;
    },
    observer,
    writer,
  };
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
