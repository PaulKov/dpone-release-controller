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
  it("emits closed redacted authorize/bucket evidence without credentials", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const writer = writerProvider(bytes, digest, contentSha1);
    const writerEvidence = await new B2NativeWriter(CONFIG, writer.fetch).observeAuthorization();
    expect(writerEvidence).toMatchObject({
      allowed: {
        bucket_id: CONFIG.bucketId,
        bucket_name: CONFIG.bucketName,
        capabilities: ["writeFiles"],
        name_prefix: CONFIG.prefix,
      },
      application_key_expiration_timestamp: null,
      raw_provider_response_retained: false,
      provider_api_version: "v4",
    });
    expect(writerEvidence.projection_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(JSON.stringify(writerEvidence)).not.toContain("account-token");
    expect(JSON.stringify(writerEvidence)).not.toContain(CONFIG.applicationKey);

    const observer = observerProvider(bytes, digest, contentSha1);
    const observerEvidence = await new B2NativeVersionObserver(
      CONFIG,
      observer.fetch,
    ).observeConfiguration();
    expect(observerEvidence).toMatchObject({
      authorization: { application_key_expiration_timestamp: null },
      bucket: {
        default_retention_days: 2557,
        encryption: "SSE-B2",
        object_lock_enabled: true,
        raw_provider_response_retained: false,
        type: "allPrivate",
      },
    });
    expect(JSON.stringify(observerEvidence)).not.toContain("account-token");
    for (const secretSentinel of [
      "authorizationToken",
      "upload-capability",
      "uploadUrl",
      CONFIG.applicationKey,
    ]) {
      expect(JSON.stringify({ observerEvidence, writerEvidence })).not.toContain(secretSentinel);
    }
  });

  it("writes with an exact writeFiles-only key and content digests", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const provider = writerProvider(bytes, digest, contentSha1);

    await expect(
      new B2NativeWriter(CONFIG, provider.fetch).uploadExact({
        canonicalBytes: bytes,
        contentSha1,
        digest,
        key: KEY,
      }),
    ).resolves.toEqual({ versionId: VERSION_ID });

    expect(provider.uploadHeaders.get("x-bz-content-sha1")).toBe(contentSha1);
    expect(provider.uploadHeaders.get("x-bz-info-dpone-sha256")).toBe(encodeURIComponent(digest));
    expect(provider.uploadHeaders.get("x-bz-file-name")).toBe(encodeURIComponent(KEY));
    expect(provider.uploadHeaders.get("x-bz-server-side-encryption")).toBe("AES256");
    expect(provider.operations).toEqual(["authorize", "b2_get_upload_url", "upload"]);
  });

  it("rejects any writer capability expansion", async () => {
    const bytes = canonicalBytes({ schema: "test.b2-object.v1" });
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const contentSha1 = await sha1Hex(bytes);
    const provider = writerProvider(bytes, digest, contentSha1, ["readFiles", "writeFiles"]);

    await expect(
      new B2NativeWriter(CONFIG, provider.fetch).uploadExact({
        canonicalBytes: bytes,
        contentSha1,
        digest,
        key: KEY,
      }),
    ).rejects.toThrow("B2_CAPABILITY_SCOPE_INVALID");
    expect(provider.operations).toEqual(["authorize"]);
  });
});
