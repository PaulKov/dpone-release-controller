import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import {
  assertCloudflareDeploymentEvidenceSet,
  assertCloudflareObserverRequestFreshness,
  CloudflareDeploymentObserver,
  sanitizeCloudflareServiceEvidence,
} from "../src/cloudflare-deployment-observation";
import { CloudflareDeploymentObserverClient } from "../src/cloudflare-deployment-observer-client";
import { CloudflareWorkersDeploymentReader } from "../src/private/cloudflare-provider";
import type { ServiceAuthorityInventoryRow } from "../src/service-authority";
import type { JsonObject } from "../src/types";
import { verifyCloudflareObserverRpcRequest } from "../src/worm-rpc-auth";
import {
  ACCOUNT_ID,
  NETWORK_SURFACE,
  NOW,
  OBSERVER_CALLER,
  OBSERVER_IDENTITY,
  OBSERVER_SERVICE,
  OBSERVER_VERSION,
  PIN,
  REQUEST_ID,
  authorityInventory,
  digest,
  providerFixture,
  uuid,
} from "./cloudflare-deployment-observer-provider.fixtures";
import {
  fetcher,
  privateResult,
  requireDefined,
} from "./cloudflare-deployment-observer-response.fixtures";

describe("Cloudflare deployment authority observation", () => {
  it("rejects stale or future signed observer requests before provider reads", () => {
    expect(() =>
      assertCloudflareObserverRequestFreshness("2026-08-19T11:59:00.000Z", NOW),
    ).not.toThrow();
    expect(() => assertCloudflareObserverRequestFreshness("2026-08-19T11:58:59.999Z", NOW)).toThrow(
      "CLOUDFLARE_OBSERVER_RPC_STALE",
    );
    expect(() => assertCloudflareObserverRequestFreshness("2026-08-19T12:00:10.001Z", NOW)).toThrow(
      "CLOUDFLARE_OBSERVER_RPC_STALE",
    );
  });
  it("performs only the closed 14-service GET chain and reproduces WORM evidence", async () => {
    const fixture = await providerFixture("A0_PRE");
    const observer = new CloudflareDeploymentObserver(
      new CloudflareWorkersDeploymentReader(
        ACCOUNT_ID,
        "token_abcdefghijklmnopqrstuvwxyz",
        fixture.fetch,
      ),
      ACCOUNT_ID,
      OBSERVER_IDENTITY,
      OBSERVER_VERSION,
      () => NOW,
    );
    const expectationSha256 = digest(990);
    const result = await observer.observe({
      expectedDeployments: fixture.expectedDeployments,
      expectationSha256,
      expectedNetworkSurface: NETWORK_SURFACE,
      phase: "A0_PRE",
      requestId: REQUEST_ID,
    });

    expect(result.evidenceEntries).toHaveLength(14);
    expect(result.observation.services).toHaveLength(14);
    expect(fixture.calls).toHaveLength(74);
    expect(fixture.calls.every((call) => call.method === "GET" && call.query === "")).toBe(true);
    expect(fixture.calls.every((call) => call.redirect === "error")).toBe(true);
    expect(fixture.calls.every((call) => call.authorization.startsWith("Bearer "))).toBe(true);
    expect(canonicalJson(result.observation)).not.toContain("token_abcdefghijklmnopqrstuvwxyz");
    await expect(
      assertCloudflareDeploymentEvidenceSet(
        result.observation,
        result.evidenceEntries,
        result.networkEvidenceEntry,
      ),
    ).resolves.toBeUndefined();
    const sanitized = await sanitizeCloudflareServiceEvidence(result.evidenceEntries[0]);
    expect(canonicalJson(sanitized.record)).not.toMatch(
      /raw_body_base64|author_email|author_id|operator\+secret@example/u,
    );
  });

  it("accepts through the pinned client only when deployment and resource inventory match", async () => {
    const fixture = await providerFixture("A1_PRECOMMIT");
    const inventory = await authorityInventory();
    const observation = await new CloudflareDeploymentObserver(
      new CloudflareWorkersDeploymentReader(
        ACCOUNT_ID,
        "token_abcdefghijklmnopqrstuvwxyz",
        fixture.fetch,
      ),
      ACCOUNT_ID,
      OBSERVER_IDENTITY,
      OBSERVER_VERSION,
      () => NOW,
    ).observe({
      expectedDeployments: fixture.expectedDeployments,
      expectationSha256: digest(991),
      expectedNetworkSurface: NETWORK_SURFACE,
      phase: "A1_PRECOMMIT",
      requestId: REQUEST_ID,
    });
    let privateRequest: Request | undefined;
    const service = fetcher(async (request) => {
      privateRequest = request;
      return privateResult(observation, REQUEST_ID);
    });

    const accepted = await new CloudflareDeploymentObserverClient(
      service,
      PIN,
      ACCOUNT_ID,
      OBSERVER_CALLER,
      () => NOW + 1_000,
    ).observe({
      expectedDeployments: fixture.expectedDeployments,
      expectationSha256: digest(991),
      expectedNetworkSurface: NETWORK_SURFACE,
      inventory,
      phase: "A1_PRECOMMIT",
      requestId: REQUEST_ID,
    });

    expect(accepted.brokerAcceptedAt).toBe("2026-08-19T12:00:01.000Z");
    expect(privateRequest?.headers.get("authorization")).toBeNull();
    expect(privateRequest?.headers.get("cloudflare-workers-version-overrides")).toBe(
      `${OBSERVER_SERVICE}="${OBSERVER_VERSION}"`,
    );
    await verifyCloudflareObserverRpcRequest(
      privateRequest?.headers ?? new Headers(),
      OBSERVER_CALLER.key,
      OBSERVER_CALLER.serviceIdentity,
    );
    const privateBody = await requireDefined(privateRequest, "missing private observer request")
      .clone()
      .json<JsonObject>();
    expect(privateBody.service_authority_inventory).toHaveLength(14);
    const forgedIngress = new Headers(privateRequest?.headers);
    forgedIngress.set("x-dpone-ingress-worker-version", uuid(998));
    await expect(
      verifyCloudflareObserverRpcRequest(
        forgedIngress,
        OBSERVER_CALLER.key,
        OBSERVER_CALLER.serviceIdentity,
      ),
    ).rejects.toThrow("CLOUDFLARE_OBSERVER_RPC_AUTH_INVALID");

    const drift = structuredClone(inventory) as ServiceAuthorityInventoryRow[];
    const firstInventoryRow = requireDefined(drift[0], "missing first inventory row");
    drift[0] = { ...firstInventoryRow, version_resource_projection_sha256: digest(992) };
    await expect(
      new CloudflareDeploymentObserverClient(
        service,
        PIN,
        ACCOUNT_ID,
        OBSERVER_CALLER,
        () => NOW + 1_000,
      ).observe({
        expectedDeployments: fixture.expectedDeployments,
        expectationSha256: digest(991),
        expectedNetworkSurface: NETWORK_SURFACE,
        inventory: drift,
        phase: "A1_PRECOMMIT",
        requestId: REQUEST_ID,
      }),
    ).rejects.toThrow("CLOUDFLARE_VERSION_RESOURCE_DRIFT");
  });
});
