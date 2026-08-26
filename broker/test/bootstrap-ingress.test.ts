import { describe, expect, it } from "vitest";

import { bootstrapIngress } from "../src/bootstrap-ingress";

const VERSION = "bootstrap-ingress-version-0001";
const ENV = {
  CF_VERSION_METADATA: {
    id: VERSION,
    tag: "bootstrap-deny-v1",
    timestamp: "2026-08-18T12:00:00.000Z",
  },
};

describe("blank-account bootstrap ingress", () => {
  it("exposes only version-bound process liveness", async () => {
    const response = bootstrapIngress.fetch(new Request("https://release.example.test/livez"), ENV);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      schema: "dpone.release-broker-bootstrap-liveness.v1",
      status: "bootstrap-deny",
      worker_version_id: VERSION,
    });
  });

  it("denies readiness, admin, provider, receipt and runtime authority", async () => {
    for (const [method, path] of [
      ["GET", "/readyz"],
      ["POST", "/v1/admin/activation/provision"],
      ["POST", "/v1/providers/github/candidate"],
      ["POST", "/v1/receipts/append"],
      ["POST", "/v1/runtime/closure"],
      ["POST", "/v1/webhooks/github/deployment-protection-rule"],
    ] as const) {
      const response = bootstrapIngress.fetch(
        new Request(`https://release.example.test${path}`, {
          headers: { "x-request-id": "bootstrap-deny-request-0001" },
          method,
        }),
        ENV,
      );
      expect(response.status, path).toBe(503);
      await expect(response.json(), path).resolves.toEqual({
        error: {
          code: "BROKER_BOOTSTRAP_DENY",
          request_id: "bootstrap-deny-request-0001",
          retryable: false,
        },
      });
    }
  });
});
