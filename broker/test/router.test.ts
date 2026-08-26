import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import broker from "../src/index";
import type { Env } from "../src/types";

const HELD_ACTIVATION_PATHS = [
  "/v1/activation/proof",
  "/v1/admin/activation/provision",
  "/v1/admin/activation/finalize",
] as const;

describe("public router activation boundary", () => {
  it("separates process liveness from fail-closed authority readiness", async () => {
    const live = await SELF.fetch("https://broker.invalid/livez");
    expect(live.status).toBe(200);
    const liveValue: unknown = await live.json();
    expect(liveValue).toMatchObject({
      schema: "dpone.release-broker-liveness.v1",
      status: "live",
    });
    expect(typeof (liveValue as Readonly<Record<string, unknown>>).worker_version_id).toBe(
      "string",
    );

    const ready = await SELF.fetch("https://broker.invalid/readyz", {
      headers: { "x-request-id": "request-router-ready-0001" },
    });
    expect(ready.status).toBe(503);
    await expect(ready.json()).resolves.toEqual({
      error: {
        code: "BROKER_PROVISIONING",
        request_id: "request-router-ready-0001",
        retryable: true,
      },
    });

    const retired = await SELF.fetch("https://broker.invalid/healthz", {
      headers: { "x-request-id": "request-router-health-0001" },
    });
    expect(retired.status).toBe(404);
  });

  it("keeps candidate, PyPI and runtime routes unreachable until shared receipts freeze", async () => {
    for (const path of [
      "/v1/providers/github/candidate",
      "/v1/runtime/closure",
      "/v1/webhooks/github/deployment-protection-rule",
    ]) {
      const response = await SELF.fetch(`https://broker.invalid${path}`, {
        headers: { "x-request-id": "request-router-0001" },
        method: "POST",
      });
      expect(response.status, path).toBe(503);
      await expect(response.json(), path).resolves.toEqual({
        error: {
          code: "BROKER_PROTOCOL_UNFROZEN",
          request_id: "request-router-0001",
          retryable: false,
        },
      });
    }
  });

  it.each(HELD_ACTIVATION_PATHS)(
    "holds %s before activation-authority request or runtime access",
    async (path) => {
      let activationAuthorityRead = false;
      let runtimeAuthorityRead = false;
      const headers = new Proxy(
        {
          get(name: string) {
            if (name === "x-request-id") return "request-activation-hold-0001";
            activationAuthorityRead = true;
            throw new Error(`unexpected header read: ${name}`);
          },
        },
        {
          get(target, property, receiver) {
            if (property === "get") return Reflect.get(target, property, receiver);
            activationAuthorityRead = true;
            throw new Error(`unexpected Headers access: ${String(property)}`);
          },
        },
      );
      const envelope = {
        headers,
        url: `https://broker.invalid${path}`,
      };
      const request = new Proxy(envelope, {
        get(target, property, receiver) {
          if (property === "headers" || property === "url") {
            return Reflect.get(target, property, receiver);
          }
          activationAuthorityRead = true;
          throw new Error(`unexpected Request access: ${String(property)}`);
        },
      }) as unknown as Request;
      const env = new Proxy({} as Env, {
        get(_target, property) {
          runtimeAuthorityRead = true;
          throw new Error(`unexpected runtime authority access: ${String(property)}`);
        },
      });

      const response = await broker.fetch(request, env);

      expect(response.status).toBe(503);
      expect(activationAuthorityRead).toBe(false);
      expect(runtimeAuthorityRead).toBe(false);
      expect(Object.fromEntries(response.headers.entries())).toEqual({
        "cache-control": "no-store",
        "content-type": "application/json; charset=utf-8",
        "x-content-type-options": "nosniff",
      });
      await expect(response.text()).resolves.toBe(
        '{"error":{"code":"BROKER_ACTIVATION_HOLD","request_id":"request-activation-hold-0001","retryable":false}}',
      );
    },
  );

  it("rejects query-bearing aliases before every recognized route dispatch", async () => {
    for (const [method, path] of [
      ["GET", "/livez?probe=1"],
      ["GET", "/readyz?probe=1"],
      ["POST", "/v1/admin/activation/provision?replay=1"],
      ["POST", "/v1/admin/activation/finalize?replay=1"],
      ["POST", "/v1/activation/proof?replay=1"],
      ["POST", "/v1/providers/github/candidate?replay=1"],
      ["POST", "/v1/runtime/closure?replay=1"],
      ["POST", "/v1/webhooks/github/deployment-protection-rule?replay=1"],
    ] as const) {
      const response = await SELF.fetch(`https://broker.invalid${path}`, {
        headers: { "x-request-id": "request-router-query-0001" },
        method,
      });
      expect(response.status, path).toBe(404);
      await expect(response.json(), path).resolves.toEqual({
        error: {
          code: "ROUTE_NOT_FOUND",
          request_id: "request-router-query-0001",
          retryable: false,
        },
      });
    }
  });

  it("returns a canonical error without reflecting an invalid request id", async () => {
    for (const invalid of ["short", "x".repeat(129), "request-valid-0001,request-forged-0002"]) {
      const response = await SELF.fetch("https://broker.invalid/v1/unknown", {
        headers: { "x-request-id": invalid },
        method: "POST",
      });
      expect(response.status).toBe(400);
      const value: {
        readonly error: { readonly code: string; readonly request_id: string };
      } = await response.json();
      expect(value.error.code).toBe("REQUEST_ID_INVALID");
      expect(value.error.request_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
      expect(value.error.request_id).not.toContain(invalid);
    }
  });
});
