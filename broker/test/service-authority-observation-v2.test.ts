import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { parseCloudflareEvidenceBatchResultV2 } from "../src/cloudflare-evidence-batch-result-v2";
import { buildServiceAuthorityObservationFromV2 } from "../src/service-authority-observation-v2";
import type { JsonObject } from "../src/types";
import { activationOperationCloudflareFixture } from "./activation-operation-cloudflare.fixtures";
import { operationJournal } from "./activation-operation-effects.fixtures";

afterEach(async () => {
  await reset();
});

describe("service-authority observation v2 adapter", () => {
  it("derives one compact 14+1 observation from the exact parsed batch", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("service-authority-v2-adapter-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const fixture = await activationOperationCloudflareFixture(journal);
      const confirmed = await parseCloudflareEvidenceBatchResultV2(
        fixture.resultBytes,
        fixture.delegation,
      );
      const compact = await buildServiceAuthorityObservationFromV2(confirmed);
      const services = compact.services as JsonObject[];
      const network = compact.network_surface as JsonObject;
      const keys = services.map((service) => wormKey(service));
      keys.push(wormKey(network));
      return {
        batchHex: confirmed.binding.batchId.slice("sha256:".length),
        brokerAcceptedAt: compact.broker_accepted_at,
        keys,
        networkRecordId: network.network_surface_observation_record_id,
        serviceCount: services.length,
      };
    });

    expect(result.serviceCount).toBe(14);
    expect(result.networkRecordId).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(result.brokerAcceptedAt).toBe("2026-08-19T12:00:04.000Z");
    expect(result.keys).toHaveLength(15);
    expect(
      result.keys.every(
        (key) =>
          key.includes(`/cloudflare-observations-v2/`) && key.includes(`/${result.batchHex}/`),
      ),
    ).toBe(true);
  });

  it("rejects an incomplete object instead of inventing a detached anchor", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("service-authority-v2-adapter-0002");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const fixture = await activationOperationCloudflareFixture(journal);
      const confirmed = await parseCloudflareEvidenceBatchResultV2(
        fixture.resultBytes,
        fixture.delegation,
      );
      const incomplete = { ...confirmed, records: confirmed.records.slice(0, -1) };
      await expect(buildServiceAuthorityObservationFromV2(incomplete)).rejects.toThrow(
        "SERVICE_AUTHORITY_V2_RESULT_INVALID",
      );
    });
  });
});

function wormKey(entry: JsonObject): string {
  const worm = entry.worm;
  if (worm === null || typeof worm !== "object" || Array.isArray(worm)) {
    throw new Error("invalid compact WORM fixture");
  }
  const key = worm.key;
  if (typeof key !== "string") throw new Error("compact WORM key missing");
  return key;
}
