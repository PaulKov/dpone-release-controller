import { describe, expect, it } from "vitest";

import { canonicalBytes, sha256Hex } from "../src/canonical";
import { B2NativeVersionObserver, B2NativeWriter } from "../src/private/b2-native";
import {
  CONFIG,
  KEY,
  VERSION_ID,
  observerProvider,
  sha1Hex,
  writerProvider,
} from "./b2-native.fixtures";

describe("native B2 split adapters", () => {
  it("lists, reauthenticates retention and downloads the exact immutable version", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const provider = observerProvider(bytes, digest, contentSha1);

    const inventory = await new B2NativeVersionObserver(CONFIG, provider.fetch).inspectExactKey(
      KEY,
    );

    expect(inventory).toMatchObject({
      bucket: {
        defaultRetentionDays: 2557,
        encryption: "SSE-B2",
        objectLockEnabled: true,
        type: "allPrivate",
      },
      key: KEY,
      versions: [
        {
          deleteMarker: false,
          digest,
          isLatest: true,
          retentionMode: "COMPLIANCE",
          versionId: VERSION_ID,
        },
      ],
    });
    expect(inventory.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(provider.operations).toEqual([
      "authorize",
      "b2_list_buckets",
      "b2_list_file_versions",
      "b2_get_file_info",
      "download",
    ]);
  });

  it("rejects observer privilege expansion and provider-controlled URL redirection", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const expanded = observerProvider(bytes, digest, contentSha1, {
      capabilities: [
        "deleteFiles",
        "listBuckets",
        "listFiles",
        "readBucketEncryption",
        "readBucketReplications",
        "readBucketRetentions",
        "readFileRetentions",
        "readFiles",
      ],
    });
    await expect(
      new B2NativeVersionObserver(CONFIG, expanded.fetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_CAPABILITY_SCOPE_INVALID");

    const redirected = observerProvider(bytes, digest, contentSha1, {
      apiUrl: "https://attacker.invalid",
    });
    await expect(
      new B2NativeVersionObserver(CONFIG, redirected.fetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_PROVIDER_URL_INVALID");
  });

  it("requires explicitly non-expiring writer and observer application keys", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const expired = Date.parse("2026-08-15T00:00:00Z");
    const nearExpiry = expired + 60_000;

    for (const expiration of [expired, nearExpiry, "missing"] as const) {
      const writer = writerProvider(bytes, digest, contentSha1, ["writeFiles"], expiration);
      await expect(
        new B2NativeWriter(CONFIG, writer.fetch).uploadExact({
          canonicalBytes: bytes,
          contentSha1,
          digest,
          key: KEY,
        }),
      ).rejects.toThrow("B2_APPLICATION_KEY_EXPIRY_INVALID");

      const observer = observerProvider(bytes, digest, contentSha1, { keyExpiration: expiration });
      await expect(
        new B2NativeVersionObserver(CONFIG, observer.fetch).inspectExactKey(KEY),
      ).rejects.toThrow("B2_APPLICATION_KEY_EXPIRY_INVALID");
    }
  });

  it("requires the official v4 root authorizationToken shape", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const wrongNested = writerProvider(bytes, digest, contentSha1, ["writeFiles"], null, false);
    await expect(
      new B2NativeWriter(CONFIG, wrongNested.fetch).uploadExact({
        canonicalBytes: bytes,
        contentSha1,
        digest,
        key: KEY,
      }),
    ).rejects.toThrow("B2_PROVIDER_RESPONSE_INVALID");
  });

  it("rejects unauthorized bucket fields and non-exact bucket inventories", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);

    const unreadableLock = observerProvider(bytes, digest, contentSha1, {
      lockAuthorized: false,
    });
    await expect(
      new B2NativeVersionObserver(CONFIG, unreadableLock.fetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_BUCKET_RESPONSE_INVALID");

    const multipleBuckets = observerProvider(bytes, digest, contentSha1, {
      extraBucket: true,
    });
    await expect(
      new B2NativeVersionObserver(CONFIG, multipleBuckets.fetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_BUCKET_RESPONSE_INVALID");
  });

  it("fails closed on historical delete markers and exact-body digest drift", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const hidden = observerProvider(bytes, digest, contentSha1, { hide: true });
    const hiddenInventory = await new B2NativeVersionObserver(CONFIG, hidden.fetch).inspectExactKey(
      KEY,
    );
    expect(hiddenInventory.versions).toEqual([
      {
        contentSha1: null,
        deleteMarker: true,
        digest: null,
        isLatest: true,
        retentionMode: null,
        retentionUntil: null,
        size: 0,
        versionId: VERSION_ID,
      },
    ]);

    const tampered = Uint8Array.from(bytes);
    tampered[0] = tampered[0] === 0x7b ? 0x5b : 0x7b;
    const corrupt = observerProvider(bytes, digest, contentSha1, { downloadBytes: tampered });
    await expect(
      new B2NativeVersionObserver(CONFIG, corrupt.fetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_VERSION_BODY_DIGEST_MISMATCH");
  });

  it("bounds provider responses before allocation", async () => {
    const oversizedFetch = async (): Promise<Response> =>
      new Response(new Uint8Array(65_537), {
        headers: { "content-length": "65537", "content-type": "application/json" },
        status: 200,
      });
    await expect(
      new B2NativeVersionObserver(CONFIG, oversizedFetch).inspectExactKey(KEY),
    ).rejects.toThrow("B2_AUTHORIZE_RESPONSE_INVALID_TOO_LARGE");
  });
});
