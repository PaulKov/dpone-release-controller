import { describe, expect, it } from "vitest";

import { activationJsonBudget } from "../src/activation-component-codec";
import {
  ACTIVATION_COMPONENT_KINDS,
  type ActivationComponentKind,
} from "../src/activation-component-contract";
import { buildActivationComponentPayloads } from "../src/activation-component-payload-builder";
import { validateAndReconstructActivationComponentSet } from "../src/activation-component-reconstruction";
import {
  ClosedActivationComponentSetSemanticValidator,
  isActivationComponentSemanticRejection,
} from "../src/activation-component-semantic-validator";
import { BrokerError } from "../src/errors";
import type { JsonObject, JsonValue } from "../src/types";
import {
  productionValidA0Fixture,
  type ProductionValidA0Fixture,
} from "./activation-component-payload.fixtures";
import {
  decodePayload,
  mutatedComponentSetFixture,
  productionValidComponentSetFixture,
} from "./activation-component-semantic.fixtures";

describe("closed activation component payload set", () => {
  it("reconstructs the exact legacy authority and owns its validated projection", async () => {
    const fixture = await productionValidComponentSetFixture();
    const expectedBroker = structuredClone(fixture.source.request.broker);
    const descriptorBytes = fixture.input.descriptor.canonicalBytes;
    const envelopeBytes = fixture.input.envelopes.map(({ canonicalBytes }) => canonicalBytes);
    const validating = validateAndReconstructActivationComponentSet(
      fixture.input,
      fixture.source.config,
    );
    descriptorBytes.fill(0);
    envelopeBytes.forEach((bytes) => bytes.fill(0));
    fixture.source.request.broker.worker_hostname = "attacker.example.invalid";

    const validated = await validating;
    expect(validated).toMatchObject({ trust: "VALIDATED" });
    expect(validated.broker).toEqual(expectedBroker);
    expect(validated.githubApps).toEqual(fixture.source.request.evidence.github_apps);
    expect(validated.serviceAuthorityExpectation.document).toEqual(
      fixture.source.expectationDocument,
    );
    expect(validated.descriptor).not.toHaveProperty("canonicalBytes");
    expect(validated.broker.worker_hostname).not.toBe("attacker.example.invalid");
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.descriptor.components)).toBe(true);
    expect(Object.isFrozen(validated.payloads.target_governance)).toBe(true);
  });

  it("keeps every production envelope under its exact checked-in structural budget", async () => {
    const fixture = await productionValidComponentSetFixture();
    const measurements = fixture.input.envelopes.map(({ canonicalBytes, componentKind }) => ({
      componentKind,
      ...activationJsonBudget(decodePayload(canonicalBytes)),
    }));
    expect(measurements).toEqual([
      row("admin_access", 2_510, 36, 2, 71),
      row("b2", 1_663, 36, 3, 71),
      row("broker_core", 2_506, 55, 4, 71),
      row("controller", 4_642, 95, 5, 71),
      row("controller_governance", 3_963, 97, 6, 73),
      row("github_apps", 6_720, 172, 4, 71),
      row("oidc", 5_629, 136, 4, 84),
      row("service_authority_header", 1_035, 18, 2, 71),
      row("service_authority_inventory", 10_214, 154, 4, 132),
      row("service_authority_a0_deployments", 6_978, 164, 6, 71),
      row("service_authority_a1_deployments", 6_310, 154, 6, 71),
      row("service_authority_network", 1_002, 20, 2, 71),
      row("service_authority_receipt_bindings", 2_062, 59, 4, 71),
      row("target_governance", 3_241, 84, 8, 73),
      row("trusted_publishers", 2_131, 42, 4, 71),
    ]);
    expect(
      measurements.every(
        ({ bytes, depth, maxStringBytes, nodes }) =>
          bytes <= 65_536 && depth <= 16 && maxStringBytes <= 32_768 && nodes <= 399,
      ),
    ).toBe(true);
  });

  it("rejects an extra and a missing top-level field for every fixed kind", async () => {
    const source = await productionValidA0Fixture();
    const validator = new ClosedActivationComponentSetSemanticValidator(source.config);
    for (const componentKind of ACTIVATION_COMPONENT_KINDS) {
      const extra = await mutatedComponentSetFixture(
        componentKind,
        (document) => {
          document.unreviewed = true;
        },
        source,
      );
      await expect(validator.validate(extra.input), `${componentKind} extra`).resolves.toEqual({
        outcome: "REJECT",
      });

      const missing = await mutatedComponentSetFixture(
        componentKind,
        (document) => {
          const first = Object.keys(document)[0];
          if (first === undefined) throw new Error("fixture component has no fields");
          if (!Reflect.deleteProperty(document, first)) {
            throw new Error("fixture component field could not be removed");
          }
        },
        source,
      );
      await expect(validator.validate(missing.input), `${componentKind} missing`).resolves.toEqual({
        outcome: "REJECT",
      });
    }
  });

  it("rejects cross-component transplants and the legacy ruleset semantic 503", async () => {
    const source = await productionValidA0Fixture();
    const validator = new ClosedActivationComponentSetSemanticValidator(source.config);
    const inventoryDrift = await mutatedComponentSetFixture(
      "service_authority_inventory",
      (document) => {
        const first = object(array(document.authorities)[0]);
        first.service = "transplanted-service";
      },
      source,
    );
    await expect(validator.validate(inventoryDrift.input)).resolves.toEqual({ outcome: "REJECT" });

    const duplicateInventoryRole = await mutatedComponentSetFixture(
      "service_authority_inventory",
      (document) => {
        const rows = array(document.authorities);
        object(rows[1]).authority_role = object(rows[0]).authority_role ?? null;
      },
      source,
    );
    await expect(validator.validate(duplicateInventoryRole.input)).resolves.toEqual({
      outcome: "REJECT",
    });

    const swappedInventory = await mutatedComponentSetFixture(
      "service_authority_inventory",
      (document) => {
        const rows = array(document.authorities);
        const first = rows[0];
        const second = rows[1];
        if (first === undefined || second === undefined) throw new Error("fixture rows missing");
        rows[0] = second;
        rows[1] = first;
      },
      source,
    );
    await expect(validator.validate(swappedInventory.input)).resolves.toEqual({
      outcome: "REJECT",
    });

    const deploymentDrift = await mutatedComponentSetFixture(
      "service_authority_a0_deployments",
      (document) => {
        array(document.deployments).reverse();
      },
      source,
    );
    await expect(validator.validate(deploymentDrift.input)).resolves.toEqual({
      outcome: "REJECT",
    });

    const malformedRuleset = await mutatedComponentSetFixture(
      "target_governance",
      (document) => {
        object(document.branch_ruleset_projection).unreviewed = true;
      },
      source,
    );
    await expect(validator.validate(malformedRuleset.input)).resolves.toEqual({
      outcome: "REJECT",
    });

    const malformedTimestamp = await mutatedComponentSetFixture(
      "admin_access",
      (document) => {
        document.certificate_not_before = "2026-99-99T99:99:99.000Z";
      },
      source,
    );
    await expect(validator.validate(malformedTimestamp.input)).resolves.toEqual({
      outcome: "REJECT",
    });
  });

  it("recursively closes normalized array members and nested authority objects", async () => {
    const source = await productionValidA0Fixture();
    const validator = new ClosedActivationComponentSetSemanticValidator(source.config);
    const cases: readonly [ActivationComponentKind, (document: JsonObject) => void][] = [
      ["github_apps", (document) => (object(Object.values(document)[0]).unreviewed = true)],
      [
        "service_authority_inventory",
        (document) => Reflect.deleteProperty(object(array(document.authorities)[0]), "binding"),
      ],
      [
        "service_authority_a0_deployments",
        (document) => {
          const deployment = object(array(document.deployments)[0]);
          object(array(deployment.deployment_versions)[0]).unreviewed = true;
        },
      ],
      [
        "service_authority_receipt_bindings",
        (document) => {
          object(array(document.receipt_role_bindings)[0]).service_role = 42;
        },
      ],
      [
        "trusted_publishers",
        (document) =>
          Reflect.deleteProperty(object(array(document.publishers)[0]), "workflow_path"),
      ],
    ];
    for (const [componentKind, mutate] of cases) {
      const fixture = await mutatedComponentSetFixture(componentKind, mutate, source);
      await expect(validator.validate(fixture.input), componentKind).resolves.toEqual({
        outcome: "REJECT",
      });
    }
  });

  it("excludes transport identity but retains confidential rehearsal JTI in set identity", async () => {
    const source = await productionValidA0Fixture();
    const original = buildActivationComponentPayloads(source.request, source.authorityExpectation);
    const transportRetry = {
      ...source.request,
      body: {
        ...source.request.body,
        observed_at: "2026-08-19T12:00:01.000Z",
        request_id: "activation-request-a0-valid-transport-retry",
      },
      observedAt: "2026-08-19T12:00:01.000Z",
      requestId: "activation-request-a0-valid-transport-retry",
    };
    const retried = buildActivationComponentPayloads(transportRetry, source.authorityExpectation);
    expect(retried.map(({ canonicalPayloadBytes }) => canonicalPayloadBytes)).toEqual(
      original.map(({ canonicalPayloadBytes }) => canonicalPayloadBytes),
    );

    const originalSet = await productionValidComponentSetFixture();
    const changedJti = await mutatedComponentSetFixture(
      "oidc",
      (document) => {
        const rehearsals = object(document.rehearsals);
        object(Object.values(rehearsals)[0]).jti_sha256 = `sha256:${"d".repeat(64)}`;
      },
      source,
    );
    await expect(
      new ClosedActivationComponentSetSemanticValidator(source.config).validate(changedJti.input),
    ).resolves.toMatchObject({ outcome: "ACCEPT" });
    expect(changedJti.input.descriptor.setId).not.toBe(originalSet.input.descriptor.setId);
  });

  it("classifies only known semantic input failures as terminal rejection", () => {
    expect(isActivationComponentSemanticRejection(new Error("local WebCrypto unavailable"))).toBe(
      false,
    );
    expect(
      isActivationComponentSemanticRejection(
        new BrokerError("LOCAL_VALIDATION_UNAVAILABLE", 503, false),
      ),
    ).toBe(false);
    expect(
      isActivationComponentSemanticRejection(
        new BrokerError("GITHUB_RULESET_PROJECTION_INVALID", 503, false),
      ),
    ).toBe(true);
  });

  it("bounds payload bytes, nodes, depth, and strings before canonical encoding", async () => {
    await expectBuildFailure((fixture) => {
      object(fixture.request.evidence.b2).observer_capabilities = Array.from({ length: 10 }, () =>
        "x".repeat(7_000),
      );
    });
    await expectBuildFailure((fixture) => {
      object(fixture.request.evidence.b2).observer_capabilities = Array.from(
        { length: 400 },
        () => "x",
      );
    });
    await expectBuildFailure((fixture) => {
      object(fixture.request.evidence.b2).observer_capabilities = nestedArray(15);
    });
    await expectBuildFailure((fixture) => {
      object(fixture.request.evidence.admin_access).hostname = "x".repeat(32_769);
    });
    await expectBuildFailure((fixture) => {
      fixture.request.evidence.trusted_publishers = oversizedArrayTrap();
    });
  });
});

function row(
  componentKind: ActivationComponentKind,
  bytes: number,
  nodes: number,
  depth: number,
  maxStringBytes: number,
) {
  return { bytes, componentKind, depth, maxStringBytes, nodes };
}

async function expectBuildFailure(mutate: (fixture: ProductionValidA0Fixture) => void) {
  const fixture = await productionValidA0Fixture();
  mutate(fixture);
  expect(() =>
    buildActivationComponentPayloads(fixture.request, fixture.authorityExpectation),
  ).toThrow("ACTIVATION_COMPONENT_PAYLOAD_BUILD_INVALID");
}

function nestedArray(depth: number): JsonValue[] {
  let value: JsonValue[] = ["leaf"];
  for (let index = 1; index < depth; index += 1) value = [value];
  return value;
}

function oversizedArrayTrap(): JsonValue[] {
  return new Proxy([] as JsonValue[], {
    get(target, property, receiver) {
      if (property === "length") return 1_000_000;
      if (typeof property === "string" && /^[0-9]+$/u.test(property)) {
        throw new Error("oversized payload array was traversed before its cardinality bound");
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("fixture object missing");
  }
  return value as JsonObject;
}

function array(value: JsonValue | undefined): JsonValue[] {
  if (!Array.isArray(value)) throw new Error("fixture array missing");
  return value;
}
