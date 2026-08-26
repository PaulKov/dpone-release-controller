import { describe, expect, it } from "vitest";

import { assertUniqueObservationAnchors } from "../src/service-authority-observation-projections";
import type { JsonObject } from "../src/types";

const OBSERVER_VERSION = "00000000-0000-0000-0000-000000000099";

describe("service-authority observation WORM key families", () => {
  it("accepts one coherent legacy or v2 family", () => {
    expect(() => assertUniqueObservationAnchors(...roster("legacy", digest(90)))).not.toThrow();
    expect(() => assertUniqueObservationAnchors(...roster("v2", digest(91)))).not.toThrow();
  });

  it("rejects mixed key families and multiple v2 batch identities", () => {
    const [mixedServices, mixedNetwork] = roster("v2", digest(92));
    replaceKey(mixedServices[0], legacyKey("cloudflare_service_deployments", 0));
    expect(() => assertUniqueObservationAnchors(mixedServices, mixedNetwork)).toThrow(
      "SERVICE_AUTHORITY_WORM_KEY_FAMILY_MISMATCH",
    );

    const [driftedServices, driftedNetwork] = roster("v2", digest(93));
    replaceKey(
      driftedNetwork,
      v2Key("cloudflare_network_surface", 14, digest(94).slice("sha256:".length)),
    );
    expect(() => assertUniqueObservationAnchors(driftedServices, driftedNetwork)).toThrow(
      "SERVICE_AUTHORITY_WORM_BATCH_MISMATCH",
    );
  });
});

function roster(family: "legacy" | "v2", taggedBatchId: string): [JsonObject[], JsonObject] {
  const batchId = taggedBatchId.slice("sha256:".length);
  const services = Array.from({ length: 14 }, (_, index) => ({
    deployment_observation_record_id: digest(index),
    deployment_observation_record_sha256: digest(index + 20),
    worm: worm(
      family === "legacy"
        ? legacyKey("cloudflare_service_deployments", index)
        : v2Key("cloudflare_service_deployments", index, batchId),
      index,
    ),
  }));
  const network: JsonObject = {
    network_surface_observation_record_id: digest(14),
    network_surface_observation_record_sha256: digest(34),
    worm: worm(
      family === "legacy"
        ? legacyKey("cloudflare_network_surface", 14)
        : v2Key("cloudflare_network_surface", 14, batchId),
      14,
    ),
  };
  return [services, network];
}

function worm(key: string, index: number): JsonObject {
  return {
    digest: digest(index + 20),
    key,
    retention_until: "2033-08-19T12:00:00.000Z",
    version_id: `worm-version-${String(index).padStart(2, "0")}`,
  };
}

function legacyKey(
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  index: number,
): string {
  return `receipts/v1/cloudflare-observations/${OBSERVER_VERSION}/${kind}/${digest(index).slice(
    "sha256:".length,
  )}.json`;
}

function v2Key(
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  index: number,
  batchId: string,
): string {
  return `receipts/v1/cloudflare-observations-v2/${OBSERVER_VERSION}/${batchId}/${kind}/${digest(
    index,
  ).slice("sha256:".length)}.json`;
}

function replaceKey(entry: JsonObject | undefined, key: string): void {
  if (entry === undefined || typeof entry.worm !== "object" || entry.worm === null) {
    throw new Error("invalid observation fixture");
  }
  (entry.worm as JsonObject).key = key;
}

function digest(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
