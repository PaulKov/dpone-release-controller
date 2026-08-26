import { describe, expect, it } from "vitest";

import {
  assertServiceAuthorityExpectationMatchesBroker,
  type ServiceAuthorityExpectation,
} from "../src/service-authority-activation";
import type { JsonObject } from "../src/types";

const HOSTNAME = "release.example.test";
const SERVICE = "dpone-release-authority-broker";

describe("service-authority broker network cross-bind", () => {
  it("binds the expected hostname, HTTPS endpoint, and service exactly", () => {
    const expectation = expectationFixture();
    const broker = brokerFixture();

    expect(() => assertServiceAuthorityExpectationMatchesBroker(expectation, broker)).not.toThrow();

    for (const drift of [
      {
        ...broker,
        endpoint: "https://other.example.test",
      },
      {
        ...broker,
        endpoint: "https://other.example.test",
        worker_hostname: "other.example.test",
      },
      {
        ...broker,
        worker_script: "dpone-release-authority-broker-shadow",
      },
    ]) {
      expect(() => assertServiceAuthorityExpectationMatchesBroker(expectation, drift)).toThrow(
        "SERVICE_AUTHORITY_BROKER_CROSS_BIND_MISMATCH",
      );
    }
  });
});

function expectationFixture(): ServiceAuthorityExpectation {
  return {
    a0PreDeployments: [],
    a1PrecommitDeployments: [],
    authorities: [],
    document: {},
    expectationSha256: `sha256:${"a".repeat(64)}`,
    networkSurface: {
      cert_id: "cert-id",
      domain_id: "domain-id",
      environment: "production",
      hostname: HOSTNAME,
      service: SERVICE,
      zone_id: "zone-id",
      zone_name: "example.test",
    },
  };
}

function brokerFixture(): JsonObject {
  return {
    endpoint: `https://${HOSTNAME}`,
    private_services: {},
    worker_hostname: HOSTNAME,
    worker_script: SERVICE,
  };
}
