import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import type { ActivationOperationCloudflareRequest } from "../src/activation-operation-cloudflare-request";
import {
  cloudflareEvidenceBatchBindingV2,
  isCloudflareEvidenceBatchBindingV2,
  type CloudflareEvidenceBatchExecution,
} from "../src/cloudflare-evidence-batch-contract";
import {
  buildCloudflareEvidenceBatchResumeV2,
  parseCloudflareEvidenceBatchResumeV2,
} from "../src/cloudflare-evidence-batch-resume-v2";
import { parseCloudflareEvidenceBatchResultV2 } from "../src/cloudflare-evidence-batch-result-v2";
import {
  buildCloudflareEvidenceBatchRequest,
  prepareCloudflareEvidenceBatch,
  prepareCloudflareEvidenceBatchV2,
} from "../src/cloudflare-evidence-batch-rpc";
import { CloudflareEvidenceBatchStore } from "../src/cloudflare-evidence-batch-store";
import { activationOperationCloudflareFixture } from "./activation-operation-cloudflare.fixtures";
import { operationJournal } from "./activation-operation-effects.fixtures";
import { cloudflareEvidenceBatchFixture } from "./cloudflare-evidence-batch.fixtures";
import { digest } from "./cloudflare-deployment-observer-provider.fixtures";

const ACTIVATION_ISSUANCE_ID = digest(1_100);
const ALTERNATE_ISSUANCE_ID = digest(1_101);
const ACTIVATION_ISSUANCE_ORDINAL = 7;

afterEach(async () => {
  await reset();
});

describe("Cloudflare evidence batch v2 binding", () => {
  it("keeps the legacy v1 request and binding unchanged", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const request = buildCloudflareEvidenceBatchRequest(fixture.transientResult);
    const prepared = await prepareCloudflareEvidenceBatch(request);

    expect(Object.keys(request).sort()).toEqual([
      "network_surface_evidence_entry",
      "observation",
      "schema",
      "schema_version",
      "service_evidence_entries",
    ]);
    expect(request).toMatchObject({
      schema: "dpone.cloudflare-evidence-worm-batch-request.v1",
      schema_version: 1,
    });
    expect(prepared.binding).toEqual(fixture.binding);
    expect(prepared.binding).not.toHaveProperty("activationIssuanceId");
    expect(prepared.slots).toHaveLength(15);
  });

  it("uses only issuance ID, ordinal, and sequence for the v2 batch ID", async () => {
    const fixture = await cloudflareEvidenceBatchFixture();
    const common = [
      fixture.binding.expectationSha256,
      fixture.binding.observerWorkerVersionId,
      fixture.binding.phase,
    ] as const;
    const base = await cloudflareEvidenceBatchBindingV2(
      ACTIVATION_ISSUANCE_ID,
      ACTIVATION_ISSUANCE_ORDINAL,
      1,
      ...common,
    );
    const identityVariants = await Promise.all([
      cloudflareEvidenceBatchBindingV2(
        ALTERNATE_ISSUANCE_ID,
        ACTIVATION_ISSUANCE_ORDINAL,
        1,
        ...common,
      ),
      cloudflareEvidenceBatchBindingV2(
        ACTIVATION_ISSUANCE_ID,
        ACTIVATION_ISSUANCE_ORDINAL + 1,
        1,
        ...common,
      ),
      cloudflareEvidenceBatchBindingV2(
        ACTIVATION_ISSUANCE_ID,
        ACTIVATION_ISSUANCE_ORDINAL,
        0,
        ...common,
      ),
    ]);
    const projectionDrift = await cloudflareEvidenceBatchBindingV2(
      ACTIVATION_ISSUANCE_ID,
      ACTIVATION_ISSUANCE_ORDINAL,
      1,
      digest(1_102),
      "77777777-7777-7777-7777-777777777777",
      "A0_PRE",
    );

    expect(identityVariants.every(({ batchId }) => batchId !== base.batchId)).toBe(true);
    expect(projectionDrift.batchId).toBe(base.batchId);
  });

  it("parses the nested exact delegation and its two bound clocks", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-v2-codec-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const exchange = await activationOperationCloudflareFixture(journal);
      const prepared = await prepareCloudflareEvidenceBatchV2(exchange.innerRequest);

      expect(Object.keys(exchange.innerRequest).sort()).toEqual([
        "batch_sealed_at",
        "delegation",
        "delegation_sha256",
        "network_surface_evidence_entry",
        "observation",
        "schema",
        "schema_version",
        "service_evidence_entries",
      ]);
      expect(prepared.binding).toEqual(exchange.delegation.binding);
      expect(prepared.delegation.delegationSha256).toBe(exchange.delegation.delegationSha256);
      expect(prepared.delegation.issuance.internalRequestId).toBe(
        journal.issuance.internalRequestId,
      );
      expect(Date.parse(prepared.delegation.committedAt)).toBeLessThanOrEqual(
        Date.parse(prepared.observedAt),
      );
      expect(Date.parse(prepared.observedAt)).toBeLessThanOrEqual(
        Date.parse(prepared.batchSealedAt),
      );
      await expect(
        prepareCloudflareEvidenceBatchV2({
          ...exchange.innerRequest,
          unbound_transport_id: "must-reject",
        }),
      ).rejects.toThrow();
    });
  });

  it("persists and resumes the v2 envelope, delegation, and ordinal-scoped key", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-v2-resume-0001");
    const result = await runInDurableObject(stub, async (_instance, state) => {
      const journal = await operationJournal(state.storage);
      const exchange = await activationOperationCloudflareFixture(journal);
      const prepared = await prepareCloudflareEvidenceBatchV2(exchange.innerRequest);
      const execution = executionFrom(exchange.delegation);
      const store = new CloudflareEvidenceBatchStore(state.storage);
      await store.seal(
        prepared.binding,
        prepared.observedAt,
        prepared.batchSealedAt,
        prepared.observation,
        execution,
        prepared.slots,
        prepared.delegation,
      );
      const envelope = parseCloudflareEvidenceBatchResumeV2(
        buildCloudflareEvidenceBatchResumeV2(exchange.delegation),
      );
      const resumed = store.resumeV2(envelope, execution);
      if (resumed === undefined || !isCloudflareEvidenceBatchBindingV2(resumed.binding)) {
        throw new Error("v2 batch binding was not resumed");
      }
      const row = state.storage.sql
        .exec<PersistedIssuanceRow>(
          `SELECT binding_schema_version, activation_issuance_id,
                  activation_issuance_ordinal, activation_sequence, delegation_sha256
           FROM cloudflare_evidence_batch WHERE singleton = 1`,
        )
        .one();
      const expectedWormKey = state.storage.sql
        .exec<{
          readonly expected_worm_key: string;
        }>(`SELECT expected_worm_key FROM cloudflare_evidence_slots WHERE slot_index = 0`)
        .one().expected_worm_key;
      const conflicts = [
        { ...envelope, binding: { ...envelope.binding, activationIssuanceOrdinal: 2 } },
        {
          ...envelope,
          binding: { ...envelope.binding, activationIssuanceId: ALTERNATE_ISSUANCE_ID },
        },
      ].map((drifted) => capture(() => store.resumeV2(drifted, execution)));
      return {
        batchId: resumed.binding.batchId,
        conflicts,
        expectedWormKey,
        operationSha: resumed.operation?.delegationSha256,
        row,
      };
    });

    expect(result.row).toMatchObject({
      activation_issuance_ordinal: 1,
      activation_sequence: 0,
      binding_schema_version: 2,
    });
    expect(result.row.activation_issuance_id).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(result.row.delegation_sha256).toBe(result.operationSha);
    expect(result.expectedWormKey).toContain(`/${result.batchId.slice("sha256:".length)}/`);
    expect(result.expectedWormKey).toContain("cloudflare-observations-v2");
    expect(result.conflicts.join("\n")).toContain("CLOUDFLARE_EVIDENCE_BATCH_BINDING_CONFLICT");
  });

  it("roundtrips exact v2 result bytes and rejects an issuance transplant", async () => {
    const firstStub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-v2-result-a-0001");
    const first = await runInDurableObject(firstStub, async (_instance, state) => {
      const journal = await operationJournal(state.storage, 1);
      const exchange = await activationOperationCloudflareFixture(journal);
      const parsed = await parseCloudflareEvidenceBatchResultV2(
        exchange.resultBytes,
        exchange.delegation,
      );
      return {
        batchId: parsed.binding.batchId,
        records: parsed.records.length,
        resultBytes: exchange.resultBytes,
      };
    });
    const secondStub = env.ACTIVATION_REGISTRY.getByName("cloudflare-batch-v2-result-b-0001");
    await runInDurableObject(secondStub, async (_instance, state) => {
      const journal = await operationJournal(state.storage, 2);
      const exchange = await activationOperationCloudflareFixture(journal);
      await expect(
        parseCloudflareEvidenceBatchResultV2(first.resultBytes, exchange.delegation),
      ).rejects.toThrow("CLOUDFLARE_EVIDENCE_BATCH_RESULT_BINDING_INVALID");
      expect(exchange.delegation.binding.batchId).not.toBe(first.batchId);
    });
    expect(first.records).toBe(15);
  });
});

interface PersistedIssuanceRow extends Record<string, SqlStorageValue> {
  readonly activation_issuance_id: string;
  readonly activation_issuance_ordinal: number;
  readonly activation_sequence: number;
  readonly binding_schema_version: number;
  readonly delegation_sha256: string;
}

function executionFrom(
  delegation: ActivationOperationCloudflareRequest,
): CloudflareEvidenceBatchExecution {
  return {
    b2ObserverServiceIdentity: delegation.pins.b2ObserverServiceIdentity,
    b2ObserverWorkerVersionId: delegation.pins.b2ObserverWorkerVersionId,
    wormServiceIdentity: delegation.pins.wormServiceIdentity,
    wormWorkerVersionId: delegation.pins.wormWorkerVersionId,
  };
}

function capture(operation: () => unknown): string {
  try {
    operation();
    return "NO_ERROR";
  } catch (error) {
    return String(error);
  }
}
