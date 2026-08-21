import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ActivationOperationCloudflareRequest } from "../src/activation-operation-cloudflare-request";
import { canonicalJson, sha256Hex } from "../src/canonical";
import { CloudflareDeploymentObserverV2Client } from "../src/cloudflare-deployment-observer-v2-client";
import {
  buildCloudflareEvidenceBatchResumeMissingV2,
  parseCloudflareEvidenceBatchResumeV2,
} from "../src/cloudflare-evidence-batch-resume-v2";
import type { CloudflareDeploymentObserverEnv } from "../src/private/cloudflare-deployment-observer-config";
import cloudflareObserverWorker from "../src/private/cloudflare-deployment-observer-worker";
import type { PrivateServicePin } from "../src/types";
import {
  CLOUDFLARE_OBSERVER_RPC_PATH_V2,
  signCloudflareObserverRpcRequest,
  type WormRpcCallerAuth,
} from "../src/worm-rpc-auth";
import { activationOperationCloudflareFixture } from "./activation-operation-cloudflare.fixtures";
import { operationJournal, WORKER_VERSION } from "./activation-operation-effects.fixtures";
import {
  ACCOUNT_ID,
  NETWORK_SURFACE,
  OBSERVER_SERVICE,
  providerFixture,
} from "./cloudflare-deployment-observer-provider.fixtures";
import { fetcher } from "./cloudflare-deployment-observer-response.fixtures";

const AUTH_KEY = "A".repeat(43);

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await reset();
});

describe("Cloudflare deployment observer v2 RPC boundary", () => {
  it("authenticates the exact v2 path and returns canonical no-store bytes from resume", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-boundary-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const exchange = await activationOperationCloudflareFixture(
        await operationJournal(state.storage),
      );
      let providerCalls = 0;
      let wormCalls = 0;
      let observerResponse: Response | undefined;
      vi.stubGlobal("fetch", async () => {
        providerCalls += 1;
        throw new Error("provider must not be called");
      });
      const worm = fetcher(async () => {
        wormCalls += 1;
        return jsonResponse(exchange.resultBytes);
      });
      const workerEnv = observerEnv(exchange.delegation, worm);
      const observer = fetcher(async (request) => {
        const response = await cloudflareObserverWorker.fetch(request, workerEnv);
        observerResponse = response.clone();
        return response;
      });
      const accepted = await new CloudflareDeploymentObserverV2Client(
        observer,
        observerPin(exchange.delegation),
        ingressCaller(exchange.delegation),
      ).observe(exchange.delegation);

      expect(accepted.canonicalResultBytes).toEqual(exchange.resultBytes);
      expect({ providerCalls, wormCalls }).toEqual({ providerCalls: 0, wormCalls: 1 });
      expect(observerResponse?.status).toBe(200);
      expect(observerResponse?.headers.get("cache-control")).toBe("no-store");
      expect(observerResponse?.headers.get("x-content-type-options")).toBe("nosniff");
      const text = await observerResponse?.text();
      expect(text).toBe(canonicalJson(JSON.parse(text ?? "null")));
    });
  });

  it("recovers a dropped confirmed observer response without a second provider sequence", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-loss-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const exchange = await activationOperationCloudflareFixture(
        await operationJournal(state.storage),
      );
      const provider = await providerFixture("A0_PRE");
      vi.stubGlobal("fetch", provider.fetch);
      vi.spyOn(Date, "now").mockReturnValue(Date.parse(exchange.delegation.committedAt) + 1_000);
      let confirmed = false;
      const wormPaths: string[] = [];
      const worm = fetcher(async (request) => {
        const path = new URL(request.url).pathname;
        wormPaths.push(path);
        if (path.endsWith("/resume") && !confirmed) {
          const resume = parseCloudflareEvidenceBatchResumeV2(await request.json());
          return jsonResponse(
            new TextEncoder().encode(
              canonicalJson(buildCloudflareEvidenceBatchResumeMissingV2(resume)),
            ),
          );
        }
        confirmed = true;
        return jsonResponse(exchange.resultBytes);
      });
      const workerEnv = observerEnv(exchange.delegation, worm);
      let dropConfirmedResponse = true;
      const observer = fetcher(async (request) => {
        const response = await cloudflareObserverWorker.fetch(request, workerEnv);
        if (dropConfirmedResponse) {
          dropConfirmedResponse = false;
          await response.body?.cancel("injected response loss");
          throw new Error("injected response loss");
        }
        return response;
      });
      const client = new CloudflareDeploymentObserverV2Client(
        observer,
        observerPin(exchange.delegation),
        ingressCaller(exchange.delegation),
      );

      await expect(client.observe(exchange.delegation)).rejects.toThrow("injected response loss");
      const providerCallCount = provider.calls.length;
      const recovered = await client.observe(exchange.delegation);

      expect(recovered.canonicalResultBytes).toEqual(exchange.resultBytes);
      expect(providerCallCount).toBe(74);
      expect(provider.calls).toHaveLength(providerCallCount);
      expect(wormPaths).toEqual([
        "/rpc/v2/cloudflare-evidence/batch/resume",
        "/rpc/v2/cloudflare-evidence/batch",
        "/rpc/v2/cloudflare-evidence/batch/resume",
      ]);
    });
  });

  it("rejects path, HMAC, callee, request-id, body-digest, and noncanonical replays pre-provider", async () => {
    const stub = env.ACTIVATION_REGISTRY.getByName("cloudflare-observer-v2-tamper-0001");
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
      const workerEnv = observerEnv(
        exchange.delegation,
        fetcher(async () => {
          wormCalls += 1;
          throw new Error("WORM must not be called");
        }),
      );
      const canonicalText = new TextDecoder().decode(exchange.delegation.canonicalBytes);
      const cases = [
        await signedRequest(exchange.delegation, canonicalText, ({ headers }) => {
          headers.set("x-dpone-rpc-auth-mac", "hmac-sha256:" + "0".repeat(64));
        }),
        await signedRequest(exchange.delegation, canonicalText, ({ path }) => {
          path.value = "/rpc/v1/cloudflare/deployments/observe";
        }),
        await signedRequest(exchange.delegation, canonicalText, ({ headers }) => {
          headers.set("x-dpone-callee-version", "99999999-9999-4999-8999-999999999999");
        }),
        await signedRequest(exchange.delegation, canonicalText, ({ headers }) => {
          headers.set("x-request-id", "activation-tampered-request-0001");
        }),
        await signedRequest(
          exchange.delegation,
          canonicalText.replace('"schema_version":2', '"schema_version":3'),
          undefined,
          true,
        ),
        await signedRequest(exchange.delegation, `${canonicalText} `, undefined, true),
      ];

      const responses = await Promise.all(
        cases.map((request) => cloudflareObserverWorker.fetch(request, workerEnv)),
      );
      expect(responses.every((response) => response.status !== 200)).toBe(true);
      const codes = await Promise.all(responses.map(errorCode));
      expect(codes).toEqual([
        "CLOUDFLARE_OBSERVER_RPC_AUTH_INVALID",
        "CLOUDFLARE_OBSERVER_RPC_AUTH_INVALID",
        "CLOUDFLARE_OBSERVER_CALLEE_MISMATCH",
        "CLOUDFLARE_OBSERVER_RPC_AUTH_INVALID",
        "CLOUDFLARE_OBSERVER_RPC_BODY_DIGEST_MISMATCH",
        "BODY_NOT_CANONICAL",
      ]);
      expect({ providerCalls, wormCalls }).toEqual({ providerCalls: 0, wormCalls: 0 });
    });
  });
});

async function signedRequest(
  delegation: ActivationOperationCloudflareRequest,
  text: string,
  mutate?: (context: { readonly headers: Headers; readonly path: { value: string } }) => void,
  digestCanonicalDocument = false,
): Promise<Request> {
  const bytes = new TextEncoder().encode(text);
  const pin = observerPin(delegation);
  const caller = ingressCaller(delegation);
  const headers = new Headers({
    "content-length": String(bytes.byteLength),
    "content-type": "application/json",
    "x-dpone-callee-service": pin.serviceName,
    "x-dpone-callee-service-identity": pin.serviceIdentity,
    "x-dpone-callee-version": pin.versionId,
    "x-dpone-canonical-sha256": `sha256:${await sha256Hex(
      digestCanonicalDocument ? delegation.canonicalBytes : bytes,
    )}`,
    "x-dpone-ingress-worker-version": caller.versionId,
    "x-request-id": delegation.observerRequest.requestId,
  });
  const path = { value: CLOUDFLARE_OBSERVER_RPC_PATH_V2 as string };
  await signCloudflareObserverRpcRequest(headers, caller, CLOUDFLARE_OBSERVER_RPC_PATH_V2);
  mutate?.({ headers, path });
  return new Request(`https://${pin.serviceName}.internal${path.value}`, {
    body: bytes,
    headers,
    method: "POST",
  });
}

function observerEnv(
  delegation: ActivationOperationCloudflareRequest,
  wormService: Fetcher,
): CloudflareDeploymentObserverEnv {
  return {
    APPROVED_INGRESS_HOSTNAME: NETWORK_SURFACE.hostname,
    APPROVED_INGRESS_ZONE_ID: NETWORK_SURFACE.zone_id,
    CF_ACCOUNT_ID: ACCOUNT_ID,
    CF_VERSION_METADATA: {
      id: delegation.pins.cloudflareObserverWorkerVersionId,
      tag: "test",
      timestamp: "2026-08-19T12:00:00.000Z",
    },
    CLOUDFLARE_API_TOKEN: "token_abcdefghijklmnopqrstuvwxyz",
    CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: AUTH_KEY,
    CLOUDFLARE_OBSERVER_RPC_AUTH_KEY: AUTH_KEY,
    EXPECTED_INGRESS_SERVICE_IDENTITY: ingressCaller(delegation).serviceIdentity,
    OPERATING_MODE: "live",
    SERVICE_NAME: OBSERVER_SERVICE,
    WORM_MIRROR: wormService,
  };
}

function observerPin(delegation: ActivationOperationCloudflareRequest): PrivateServicePin {
  return {
    serviceIdentity: delegation.pins.cloudflareObserverServiceIdentity,
    serviceName: OBSERVER_SERVICE,
    versionId: delegation.pins.cloudflareObserverWorkerVersionId,
  };
}

function ingressCaller(delegation: ActivationOperationCloudflareRequest): WormRpcCallerAuth {
  const ingress = delegation.observerRequest.inventory.find(
    (row) => row.authority_role === "release_authority_ingress",
  );
  if (ingress?.worker_version_id !== WORKER_VERSION) {
    throw new Error("ingress fixture missing");
  }
  return { key: AUTH_KEY, serviceIdentity: ingress.service_identity, versionId: WORKER_VERSION };
}

function jsonResponse(bytes: Uint8Array): Response {
  return new Response(Uint8Array.from(bytes), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

async function errorCode(response: Response): Promise<string | undefined> {
  const body = await response.json<{ readonly error?: { readonly code?: string } }>();
  return body.error?.code;
}
