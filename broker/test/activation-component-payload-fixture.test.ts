import { describe, expect, it } from "vitest";

import { canonicalBytes } from "../src/canonical";
import {
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
} from "../src/activation-component-contract";
import type { JsonObject } from "../src/types";
import { VALID_A0_SOURCE_COMMIT } from "./activation-component-authority.fixtures";
import {
  measureCanonicalActivationObject,
  productionValidA0Fixture,
} from "./activation-component-payload.fixtures";

describe("production-valid activation component payload fixture", () => {
  it("passes the complete A0 authority and evidence validation chain", async () => {
    const fixture = await productionValidA0Fixture();

    expect(fixture.canonicalBodyBytes).toEqual(canonicalBytes(fixture.body));
    expect(fixture.authorityExpectation.authorities).toHaveLength(14);
    expect(
      fixture.authorityExpectation.authorities.every(
        (authority) => authority.source_commit_sha === VALID_A0_SOURCE_COMMIT,
      ),
    ).toBe(true);
    expect(fixture.request.body).toBe(fixture.body);
    expect(fixture.componentPayloads).toHaveLength(15);

    const evidence = object(fixture.body.evidence);
    const oidc = object(evidence.oidc);
    const rehearsals = object(oidc.rehearsals);
    for (const rehearsal of Object.values(rehearsals)) {
      const row = object(rehearsal);
      expect(row.jti_sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(row).not.toHaveProperty("jti");
    }

    expect(fixture.measurement).toEqual({
      bytes: 71_403,
      depth: 9,
      maxStringBytes: 132,
      nodes: 1_426,
    });
    expect(fixture.measurement.bytes).toBeGreaterThan(65_536);
    expect(fixture.measurement.nodes).toBeGreaterThan(512);
    const componentMeasurements = fixture.componentPayloads.map((payload) => ({
      componentKind: payload.componentKind,
      ...measureCanonicalActivationObject(
        object(JSON.parse(new TextDecoder().decode(payload.canonicalPayloadBytes)) as unknown),
      ),
    }));
    expect(componentMeasurements).toEqual([
      { bytes: 1_786, componentKind: "admin_access", depth: 1, maxStringBytes: 71, nodes: 24 },
      { bytes: 959, componentKind: "b2", depth: 2, maxStringBytes: 71, nodes: 24 },
      { bytes: 1_793, componentKind: "broker_core", depth: 3, maxStringBytes: 71, nodes: 43 },
      { bytes: 3_930, componentKind: "controller", depth: 4, maxStringBytes: 71, nodes: 83 },
      {
        bytes: 3_240,
        componentKind: "controller_governance",
        depth: 5,
        maxStringBytes: 73,
        nodes: 85,
      },
      { bytes: 6_007, componentKind: "github_apps", depth: 3, maxStringBytes: 71, nodes: 160 },
      { bytes: 4_923, componentKind: "oidc", depth: 3, maxStringBytes: 84, nodes: 124 },
      {
        bytes: 309,
        componentKind: "service_authority_header",
        depth: 1,
        maxStringBytes: 71,
        nodes: 6,
      },
      {
        bytes: 9_485,
        componentKind: "service_authority_inventory",
        depth: 3,
        maxStringBytes: 132,
        nodes: 142,
      },
      {
        bytes: 6_244,
        componentKind: "service_authority_a0_deployments",
        depth: 5,
        maxStringBytes: 71,
        nodes: 152,
      },
      {
        bytes: 5_576,
        componentKind: "service_authority_a1_deployments",
        depth: 5,
        maxStringBytes: 71,
        nodes: 142,
      },
      {
        bytes: 275,
        componentKind: "service_authority_network",
        depth: 1,
        maxStringBytes: 36,
        nodes: 8,
      },
      {
        bytes: 1_326,
        componentKind: "service_authority_receipt_bindings",
        depth: 3,
        maxStringBytes: 25,
        nodes: 47,
      },
      {
        bytes: 2_522,
        componentKind: "target_governance",
        depth: 7,
        maxStringBytes: 73,
        nodes: 72,
      },
      {
        bytes: 1_411,
        componentKind: "trusted_publishers",
        depth: 3,
        maxStringBytes: 71,
        nodes: 30,
      },
    ]);
    expect(
      componentMeasurements.every(
        ({ bytes, depth, maxStringBytes, nodes }) =>
          bytes <= ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES &&
          nodes <= ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES &&
          depth <= 14 &&
          maxStringBytes <= ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      ),
    ).toBe(true);
    expect({
      bytes: Math.max(...componentMeasurements.map(({ bytes }) => bytes)),
      depth: Math.max(...componentMeasurements.map(({ depth }) => depth)),
      maxStringBytes: Math.max(
        ...componentMeasurements.map(({ maxStringBytes }) => maxStringBytes),
      ),
      nodes: Math.max(...componentMeasurements.map(({ nodes }) => nodes)),
      totalBytes: componentMeasurements.reduce((total, { bytes }) => total + bytes, 0),
    }).toEqual({
      bytes: 9_485,
      depth: 7,
      maxStringBytes: 132,
      nodes: 160,
      totalBytes: 49_786,
    });
  });
});

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("valid A0 fixture object missing");
  }
  return value as JsonObject;
}
