import { describe, expect, it } from "vitest";

import { BrokerError } from "../src/errors";
import { assertPinnedServiceVersion, callPinnedService } from "../src/service-version";
import type { PrivateServicePin } from "../src/types";

const PIN: PrivateServicePin = {
  serviceIdentity:
    "cloudflare-worker:test-account/worm-mirror-private@worker-version-immutable-0001",
  serviceName: "worm-mirror-private",
  versionId: "worker-version-immutable-0001",
};

describe("private Service Binding version pinning", () => {
  it("creates a fresh request with the exact immutable version override", async () => {
    let observed: Request | undefined;
    const service = {
      fetch: (request: Request) => {
        observed = request;
        return Promise.resolve(new Response(null, { status: 204 }));
      },
    } as unknown as Fetcher;
    const response = await callPinnedService(service, PIN, {
      body: "{}",
      headers: { "content-type": "application/json" },
      method: "POST",
      path: "/rpc/v1/activation",
    });
    expect(response.status).toBe(204);
    expect(observed).toBeInstanceOf(Request);
    expect(observed?.url).toBe("https://worm-mirror-private.internal/rpc/v1/activation");
    expect(observed?.headers.get("Cloudflare-Workers-Version-Overrides")).toBe(
      'worm-mirror-private="worker-version-immutable-0001"',
    );
    expect(observed?.headers.get("authorization")).toBeNull();
  });

  it("forbids caller-selected override and credential headers", () => {
    const service = { fetch: () => Promise.resolve(new Response()) } as unknown as Fetcher;
    for (const name of [
      "Authorization",
      "Cf-Access-Jwt-Assertion",
      "Cloudflare-Workers-Version-Overrides",
      "Cookie",
    ]) {
      expect(() =>
        callPinnedService(service, PIN, {
          headers: { [name]: "attacker-controlled" },
          method: "POST",
          path: "/rpc/v1/test",
        }),
      ).toThrowError("SERVICE_HEADER_FORBIDDEN");
    }
  });

  it("fails closed when the private Worker reports another version", () => {
    expect(() => assertPinnedServiceVersion("worker-version-mutated-0002", PIN)).toThrowError(
      BrokerError,
    );
  });
});
