import { describe, expect, it } from "vitest";

import {
  assertCanonicalCloudflareEvidenceBatchText,
  buildCloudflareEvidenceBatchRequest,
  canonicalCloudflareEvidenceBatchBytes,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
} from "../src/cloudflare-evidence-batch-rpc";
import { cloudflareEvidenceBatchFixture } from "./cloudflare-evidence-batch.fixtures";

describe("Cloudflare evidence batch RPC bounds", () => {
  it("accepts exactly one MiB and rejects one additional canonical byte before parsing", () => {
    const exact = exactCanonicalObject(MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES);
    expect(assertCanonicalCloudflareEvidenceBatchText(exact)).toHaveProperty("value");
    expect(() => assertCanonicalCloudflareEvidenceBatchText(`${exact} `)).toThrow(
      "CLOUDFLARE_EVIDENCE_BATCH_SIZE_INVALID",
    );
  });

  it("pins the measured canonical size of the complete seventy-three-call fixture", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const bytes = canonicalCloudflareEvidenceBatchBytes(
      buildCloudflareEvidenceBatchRequest(fixture.transientResult),
    );
    const callCount = [
      ...fixture.transientResult.evidenceEntries,
      fixture.transientResult.networkEvidenceEntry,
    ].reduce((total, entry) => {
      if (!Array.isArray(entry.raw_responses)) throw new Error("raw response fixture missing");
      return total + entry.raw_responses.length;
    }, 0);
    expect(callCount).toBe(73);
    expect(bytes.byteLength).toBe(163_275);
    expect(bytes.byteLength).toBeLessThan(MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES);
  });
});

function exactCanonicalObject(size: number): string {
  const prefix = '{"value":"';
  const suffix = '"}';
  return `${prefix}${"a".repeat(size - prefix.length - suffix.length)}${suffix}`;
}
