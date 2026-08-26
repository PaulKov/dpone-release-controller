import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ActivationOperationCloudflareRequest } from "../src/activation-operation-cloudflare-request";
import { canonicalJson } from "../src/canonical";
import {
  buildCloudflareEvidenceBatchResumeMissingV2,
  parseCloudflareEvidenceBatchResumeV2,
} from "../src/cloudflare-evidence-batch-resume-v2";
import type { CloudflareDeploymentObserverConfig } from "../src/private/cloudflare-deployment-observer-config";
import { observeCloudflareDeploymentV2 } from "../src/private/cloudflare-deployment-observer-v2";
import type { JsonObject } from "../src/types";
import { activationOperationCloudflareFixture } from "./activation-operation-cloudflare.fixtures";
import { operationJournal } from "./activation-operation-effects.fixtures";
import {
  ACCOUNT_ID,
  NETWORK_SURFACE,
  NOW,
  OBSERVER_SERVICE,
  providerFixture,
} from "./cloudflare-deployment-observer-provider.fixtures";
import { fetcher } from "./cloudflare-deployment-observer-response.fixtures";

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await reset();
});

describe("Cloudflare deployment observer v2 recovery", () => {
  it("returns a confirmed durable batch without any Cloudflare provider read", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-resume-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const exchange = await activationOperationCloudflareFixture(
        await operationJournal(state.storage),
      );
      let providerCalls = 0;
      let wormCalls = 0;
      vi.stubGlobal("fetch", async () => {
        providerCalls += 1;
        throw new Error("provider must not be called");
      });
      const worm = fetcher(async (request) => {
        wormCalls += 1;
        expect(new URL(request.url).pathname).toBe("/rpc/v2/cloudflare-evidence/batch/resume");
        return exactJsonResponse(exchange.resultBytes);
      });

      const bytes = await observeCloudflareDeploymentV2(
        exchange.delegation.document,
        exchange.delegation.observerRequest.requestId,
        observerConfig(exchange.delegation, worm),
        () => NOW + 300_000,
      );

      expect(bytes).toEqual(exchange.resultBytes);
      expect({ providerCalls, wormCalls }).toEqual({ providerCalls: 0, wormCalls: 1 });
    });
  });

  it("reads the provider once only after MISSING and resumes response loss without rereading", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-missing-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const exchange = await activationOperationCloudflareFixture(
        await operationJournal(state.storage),
      );
      const provider = await providerFixture("A0_PRE");
      vi.stubGlobal("fetch", provider.fetch);
      const paths: string[] = [];
      let confirmed = false;
      const worm = fetcher(async (request) => {
        const path = new URL(request.url).pathname;
        paths.push(path);
        if (path.endsWith("/resume") && !confirmed) return missingResponse(request);
        confirmed = true;
        return exactJsonResponse(exchange.resultBytes);
      });
      const config = observerConfig(exchange.delegation, worm);

      const first = await observeCloudflareDeploymentV2(
        exchange.delegation.document,
        exchange.delegation.observerRequest.requestId,
        config,
        () => NOW + 3_000,
      );
      const providerCallCount = provider.calls.length;
      const second = await observeCloudflareDeploymentV2(
        exchange.delegation.document,
        exchange.delegation.observerRequest.requestId,
        config,
        () => NOW + 300_000,
      );

      expect(first).toEqual(exchange.resultBytes);
      expect(second).toEqual(exchange.resultBytes);
      expect(providerCallCount).toBe(74);
      expect(provider.calls).toHaveLength(providerCallCount);
      expect(paths).toEqual([
        "/rpc/v2/cloudflare-evidence/batch/resume",
        "/rpc/v2/cloudflare-evidence/batch",
        "/rpc/v2/cloudflare-evidence/batch/resume",
      ]);
    });
  });

  it("rejects a stale MISSING request and an authenticated ingress-pin transplant before reads", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-stale-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const exchange = await activationOperationCloudflareFixture(
        await operationJournal(state.storage),
      );
      let providerCalls = 0;
      let wormCalls = 0;
      vi.stubGlobal("fetch", async () => {
        providerCalls += 1;
        throw new Error("provider must not be called");
      });
      const worm = fetcher(async (request) => {
        wormCalls += 1;
        return missingResponse(request);
      });
      const config = observerConfig(exchange.delegation, worm);
      await expect(
        observeCloudflareDeploymentV2(
          exchange.delegation.document,
          exchange.delegation.observerRequest.requestId,
          config,
          () => Date.parse(exchange.delegation.freshUntil) + 1,
        ),
      ).rejects.toThrow("CLOUDFLARE_OBSERVER_V2_STALE");

      const transplanted = structuredClone(exchange.delegation.document);
      const inventory = requireInventory(requireObserverRequest(transplanted));
      const ingress = inventory.find((row) => row.authority_role === "release_authority_ingress");
      if (ingress === undefined) throw new Error("ingress fixture missing");
      const version = "99999999-9999-4999-8999-999999999999";
      ingress.service_identity = `cloudflare-worker:${ACCOUNT_ID}/dpone-release-authority-broker@${version}`;
      ingress.worker_version_id = version;
      await expect(
        observeCloudflareDeploymentV2(
          transplanted,
          exchange.delegation.observerRequest.requestId,
          config,
          () => NOW + 3_000,
        ),
      ).rejects.toThrow("CLOUDFLARE_OBSERVER_V2_INGRESS_PIN_INVALID");
      expect({ providerCalls, wormCalls }).toEqual({ providerCalls: 0, wormCalls: 1 });
    });
  });
});

function observerConfig(
  delegation: ActivationOperationCloudflareRequest,
  wormService: Fetcher,
): CloudflareDeploymentObserverConfig {
  const ingress = delegation.observerRequest.inventory.find(
    (row) => row.authority_role === "release_authority_ingress",
  );
  if (ingress === undefined) throw new Error("ingress fixture missing");
  return {
    accountId: ACCOUNT_ID,
    approvedIngressHostname: NETWORK_SURFACE.hostname,
    approvedIngressZoneId: NETWORK_SURFACE.zone_id,
    apiToken: "token_abcdefghijklmnopqrstuvwxyz",
    expectedIngressServiceIdentity: ingress.service_identity,
    observerRpcAuthKey: "A".repeat(43),
    serviceIdentity: delegation.pins.cloudflareObserverServiceIdentity,
    serviceName: OBSERVER_SERVICE,
    workerVersionId: delegation.pins.cloudflareObserverWorkerVersionId,
    wormCallerAuth: {
      key: "A".repeat(43),
      serviceIdentity: delegation.pins.cloudflareObserverServiceIdentity,
      versionId: delegation.pins.cloudflareObserverWorkerVersionId,
    },
    wormService,
  };
}

async function missingResponse(request: Request): Promise<Response> {
  const expected = parseCloudflareEvidenceBatchResumeV2(await request.json());
  return exactJsonResponse(
    new TextEncoder().encode(canonicalJson(buildCloudflareEvidenceBatchResumeMissingV2(expected))),
  );
}

function exactJsonResponse(bytes: Uint8Array): Response {
  return new Response(Uint8Array.from(bytes), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

function requireObserverRequest(value: JsonObject): JsonObject {
  const request = value.observer_request;
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("observer request fixture missing");
  }
  return request;
}

function requireInventory(value: JsonObject): JsonObject[] {
  const inventory = value.service_authority_inventory;
  if (!Array.isArray(inventory)) throw new Error("inventory fixture missing");
  return inventory as JsonObject[];
}
