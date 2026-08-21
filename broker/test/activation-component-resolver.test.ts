import { beforeAll, describe, expect, it } from "vitest";

import { canonicalBytes, sha256Hex } from "../src/canonical";
import { activationJsonBudget } from "../src/activation-component-codec";
import type { ActivationComponentNamespaceReader } from "../src/activation-component-resolver-contract";
import {
  ConfidentialActivationComponentResolver,
  snapshotResolvedActivationComponentSet,
} from "../src/activation-component-resolver";
import { BrokerError } from "../src/errors";
import type { JsonObject, TrustedRuntimeConfig } from "../src/types";
import {
  cloneSnapshot,
  fixtureReader,
  FixtureActivationComponentNamespaceReader,
  productionResolverFixture,
  resolverFixtureForComponentSet,
  type ActivationComponentResolverFixture,
} from "./activation-component-resolver.fixtures";
import { mutatedComponentSetFixture } from "./activation-component-semantic.fixtures";

describe("confidential activation component resolver", () => {
  let fixture: ActivationComponentResolverFixture;

  beforeAll(async () => {
    fixture = await productionResolverFixture();
  });

  it("resolves complete WORM namespaces into compact branded semantics", async () => {
    const reader = fixtureReader(fixture);
    const fullRuntimeConfig: TrustedRuntimeConfig = fixture.source.source.config;
    const resolver = new ConfidentialActivationComponentResolver(reader, fullRuntimeConfig);
    const resolved = await resolver.resolve(fixture.pointerBytes);

    expect(reader.trace).toEqual([
      {
        kind: "MANIFEST",
        request: {
          maximumObjectBytes: 65_536,
          maximumVersions: 2,
          prefix: fixture.expectedManifestPrefix,
        },
      },
      {
        kind: "COMPONENTS",
        request: {
          maximumObjectBytes: 65_536,
          maximumVersions: 16,
          prefix: fixture.expectedComponentPrefix,
        },
      },
    ]);
    expect(resolved.trust).toBe("RESOLVED_SEMANTICS");
    expect(resolved.canonicalProjectionBytes.byteLength).toBe(6_160);
    expect(resolved.projectionSha256).toBe(
      "sha256:26926bbf4ab158b469d34b260c15ca836cb412311292c9a6f52c7d90f0f6fddf",
    );
    expect(activationJsonBudget(resolved.document)).toEqual({
      bytes: 6_160,
      depth: 4,
      maxStringBytes: 279,
      nodes: 96,
    });
    expect(resolved.document).toMatchObject({
      component_set: {
        component_set_id: fixture.source.input.descriptor.setId,
        worker_version_id: fixture.source.source.config.workerVersionId,
      },
      runtime: {
        cloudflare_account_id: fixture.source.source.config.cloudflareAccountId,
        service_authority_expectation_sha256: fixture.source.source.expectationSha256,
      },
      schema: "dpone.resolved-activation-component-semantics.v2",
      schema_version: 2,
    });
    const text = new TextDecoder().decode(resolved.canonicalProjectionBytes);
    expect(text).not.toContain("admin_access");
    expect(text).not.toContain('branch_ruleset_projection"');
    expect(text).not.toContain("provider_observation_sha256");
    const adminAccess = object(fixture.source.source.request.evidence.admin_access);
    const rehearsals = object(fixture.source.source.request.oidc.rehearsals);
    expect(text).not.toContain(stringField(adminAccess, "access_group_sha256"));
    expect(text).not.toContain(stringField(object(Object.values(rehearsals)[0]), "jti_sha256"));
    expect(Object.isFrozen(resolved.document)).toBe(true);
    expect(Object.isFrozen(object(resolved.document.runtime).private_services)).toBe(true);

    const firstCopy = resolved.canonicalProjectionBytes;
    firstCopy.fill(0);
    expect(resolved.canonicalProjectionBytes[0]).not.toBe(0);
    const snapshot = await snapshotResolvedActivationComponentSet(resolved);
    expect(snapshot).not.toBe(resolved);
    expect(snapshot.canonicalProjectionBytes).toEqual(resolved.canonicalProjectionBytes);
    expect(snapshot.projectionSha256).toBe(resolved.projectionSha256);
  });

  it("owns pointer bytes and semantic trust before the first namespace await", async () => {
    const reader = fixtureReader(fixture);
    const trust = { ...fixture.source.source.config };
    const resolver = new ConfidentialActivationComponentResolver(reader, trust);
    const pointerBytes = Uint8Array.from(fixture.pointerBytes);
    const resolving = resolver.resolve(pointerBytes);
    pointerBytes.fill(0);
    trust.cloudflareAccountId = "b".repeat(32);
    trust.adminHostname = "attacker.example.invalid";

    await expect(resolving).resolves.toMatchObject({ trust: "RESOLVED_SEMANTICS" });
  });

  it("derives historical ingress identity without consuming current resolver worker pins", async () => {
    const unrelatedCurrentWorker = "99999999-9999-4999-8999-999999999999";
    const config: TrustedRuntimeConfig = {
      ...fixture.source.source.config,
      workerServiceIdentity:
        `cloudflare-worker:${fixture.source.source.config.cloudflareAccountId}/` +
        `current-resolver@${unrelatedCurrentWorker}`,
      workerVersionId: unrelatedCurrentWorker,
    };
    await expect(
      new ConfidentialActivationComponentResolver(fixtureReader(fixture), config).resolve(
        fixture.pointerBytes,
      ),
    ).resolves.toMatchObject({ trust: "RESOLVED_SEMANTICS" });
  });

  it("accepts provider listing order only after reordering by the manifest roster", async () => {
    const reader = new FixtureActivationComponentNamespaceReader(fixture.manifestSnapshot, {
      ...fixture.componentSnapshot,
      versions: [...fixture.componentSnapshot.versions].reverse(),
    });
    const baseline = await new ConfidentialActivationComponentResolver(
      fixtureReader(fixture),
      fixture.source.source.config,
    ).resolve(fixture.pointerBytes);
    const reordered = await new ConfidentialActivationComponentResolver(
      reader,
      fixture.source.source.config,
    ).resolve(fixture.pointerBytes);

    expect(reordered.canonicalProjectionBytes).toEqual(baseline.canonicalProjectionBytes);
  });

  it("rejects invalid pointer or structural forgery before any namespace read", async () => {
    const reader = fixtureReader(fixture);
    const resolver = new ConfidentialActivationComponentResolver(
      reader,
      fixture.source.source.config,
    );
    const decoded = JSON.parse(new TextDecoder().decode(fixture.pointerBytes)) as JsonObject;
    object(decoded.worm).key = "receipts/v2/activation-component-manifests/../forged.json";

    await expect(resolver.resolve(canonicalBytes(decoded))).rejects.toBeInstanceOf(BrokerError);
    const proxied = new Proxy(Uint8Array.from(fixture.pointerBytes), {
      get() {
        throw new Error("pointer proxy must not execute");
      },
    });
    await expect(resolver.resolve(proxied)).rejects.toBeInstanceOf(BrokerError);
    expect(reader.trace).toEqual([]);
  });

  it("rejects an oversized pointer with the exact payload-too-large status", async () => {
    const reader = fixtureReader(fixture);
    await expect(
      new ConfidentialActivationComponentResolver(reader, fixture.source.source.config).resolve(
        new Uint8Array(65_537),
      ),
    ).rejects.toMatchObject({
      code: "ACTIVATION_COMPONENT_RESOLVER_INVALID",
      retryable: false,
      status: 413,
    });
    expect(reader.trace).toEqual([]);
  });

  it("stops after one manifest inventory when manifest authority is invalid", async () => {
    const manifestSnapshot = cloneSnapshot(fixture.manifestSnapshot);
    const first = manifestSnapshot.versions[0];
    if (first === undefined) throw new Error("resolver manifest fixture missing");
    const reader = new FixtureActivationComponentNamespaceReader(
      { ...manifestSnapshot, versions: [{ ...first, contentSha1: "0".repeat(40) }] },
      fixture.componentSnapshot,
    );
    await expect(
      new ConfidentialActivationComponentResolver(reader, fixture.source.source.config).resolve(
        fixture.pointerBytes,
      ),
    ).rejects.toBeInstanceOf(BrokerError);
    expect(reader.trace.map(({ kind }) => kind)).toEqual(["MANIFEST"]);
  });

  it.each([
    ["account", { cloudflareAccountId: "b".repeat(32) }],
    ["admin", { adminHostname: "different.example.invalid" }],
  ])("rejects %s trust drift under the legacy full runtime config", async (_name, drift) => {
    const reader = fixtureReader(fixture);
    const config: TrustedRuntimeConfig = { ...fixture.source.source.config, ...drift };
    await expect(
      new ConfidentialActivationComponentResolver(reader, config).resolve(fixture.pointerBytes),
    ).rejects.toBeInstanceOf(BrokerError);
    expect(reader.trace).toHaveLength(2);
  });

  it("propagates reader failure without retry or partial authority", async () => {
    let calls = 0;
    const reader: ActivationComponentNamespaceReader = {
      async readComponentNamespace() {
        throw new Error("component reader must not be reached");
      },
      async readManifestNamespace() {
        calls += 1;
        throw new Error("confidential reader unavailable");
      },
    };
    await expect(
      new ConfidentialActivationComponentResolver(reader, fixture.source.source.config).resolve(
        fixture.pointerBytes,
      ),
    ).rejects.toThrow("confidential reader unavailable");
    expect(calls).toBe(1);
  });

  it("rejects one version reused by the manifest and a component", async () => {
    const collision = await productionResolverFixture({ reuseManifestVersion: true });
    const reader = fixtureReader(collision);
    await expect(
      new ConfidentialActivationComponentResolver(reader, collision.source.source.config).resolve(
        collision.pointerBytes,
      ),
    ).rejects.toThrow("ACTIVATION_COMPONENT_RESOLVER_INVALID");
    expect(reader.trace).toHaveLength(2);
  });

  it("reads all exact objects but rejects a WORM-valid semantically invalid last component", async () => {
    const invalidSet = await mutatedComponentSetFixture(
      "trusted_publishers",
      (document) => {
        const publishers = document.publishers;
        if (!Array.isArray(publishers) || publishers.length === 0) {
          throw new Error("trusted publisher fixture missing");
        }
        object(publishers[publishers.length - 1]).environment = "attacker";
      },
      fixture.source.source,
    );
    const invalidResolverFixture = await resolverFixtureForComponentSet(invalidSet);
    const reader = fixtureReader(invalidResolverFixture);
    await expect(
      new ConfidentialActivationComponentResolver(
        reader,
        invalidResolverFixture.source.source.config,
      ).resolve(invalidResolverFixture.pointerBytes),
    ).rejects.toBeInstanceOf(BrokerError);
    expect(reader.trace.map(({ kind }) => kind)).toEqual(["MANIFEST", "COMPONENTS"]);
  });

  it("runs concurrent resolves independently and returns byte-identical semantics", async () => {
    const leftReader = fixtureReader(fixture);
    const rightReader = fixtureReader(fixture);
    const [left, right] = await Promise.all([
      new ConfidentialActivationComponentResolver(leftReader, fixture.source.source.config).resolve(
        fixture.pointerBytes,
      ),
      new ConfidentialActivationComponentResolver(
        rightReader,
        fixture.source.source.config,
      ).resolve(fixture.pointerBytes),
    ]);
    expect(left.canonicalProjectionBytes).toEqual(right.canonicalProjectionBytes);
    expect(leftReader.trace).toHaveLength(2);
    expect(rightReader.trace).toHaveLength(2);
  });

  it("cross-binds manifest and component bucket identity to closed B2 semantics", async () => {
    const accountDrift = cloneWithComponentBucket(fixture, {
      cloudflareAccountId: "b".repeat(32),
    });
    await expect(
      new ConfidentialActivationComponentResolver(
        accountDrift,
        fixture.source.source.config,
      ).resolve(fixture.pointerBytes),
    ).rejects.toThrow("ACTIVATION_COMPONENT_RESOLVER_INVALID");

    const bucketDrift = cloneWithComponentBucket(fixture, { bucketName: "other-bucket" });
    await expect(
      new ConfidentialActivationComponentResolver(
        bucketDrift,
        fixture.source.source.config,
      ).resolve(fixture.pointerBytes),
    ).rejects.toThrow("ACTIVATION_COMPONENT_RESOLVER_INVALID");

    const bucketIdDrift = cloneWithComponentBucket(fixture, { bucketId: "e".repeat(24) });
    await expect(
      new ConfidentialActivationComponentResolver(
        bucketIdDrift,
        fixture.source.source.config,
      ).resolve(fixture.pointerBytes),
    ).rejects.toThrow("ACTIVATION_COMPONENT_RESOLVER_INVALID");
  });

  it("does not let an unbranded structural projection enter the snapshot boundary", async () => {
    const resolved = await new ConfidentialActivationComponentResolver(
      fixtureReader(fixture),
      fixture.source.source.config,
    ).resolve(fixture.pointerBytes);
    await expect(snapshotResolvedActivationComponentSet({ ...resolved })).rejects.toThrow(
      "ACTIVATION_COMPONENT_RESOLVER_INVALID",
    );
    const resolvedPrototype = Reflect.getPrototypeOf(resolved);
    if (resolvedPrototype === null) throw new Error("resolved prototype missing");
    const prototypeForgery = Object.create(resolvedPrototype) as Record<string, unknown>;
    Object.defineProperties(prototypeForgery, {
      canonicalProjectionBytes: { value: resolved.canonicalProjectionBytes },
      document: { value: resolved.document },
      projectionSha256: { value: resolved.projectionSha256 },
      trust: { value: "RESOLVED_SEMANTICS" },
    });
    await expect(snapshotResolvedActivationComponentSet(prototypeForgery)).rejects.toThrow(
      "ACTIVATION_COMPONENT_RESOLVER_INVALID",
    );
    await expect(snapshotResolvedActivationComponentSet(new Proxy(resolved, {}))).rejects.toThrow(
      "ACTIVATION_COMPONENT_RESOLVER_INVALID",
    );

    const forgedDocument = JSON.parse(
      new TextDecoder().decode(resolved.canonicalProjectionBytes),
    ) as JsonObject;
    object(forgedDocument.runtime).cloudflare_account_id = "b".repeat(32);
    const forgedBytes = canonicalBytes(forgedDocument);
    const forgedDigest = `sha256:${await sha256Hex(forgedBytes)}`;
    const constructorDescriptor = Object.getOwnPropertyDescriptor(resolvedPrototype, "constructor");
    if (constructorDescriptor === undefined || !("value" in constructorDescriptor)) {
      throw new Error("resolved constructor missing");
    }
    const extractedConstructor = constructorDescriptor.value as new (
      document: JsonObject,
      bytes: Uint8Array,
      digest: string,
    ) => Record<string, unknown>;
    const constructorForgery = new extractedConstructor(forgedDocument, forgedBytes, forgedDigest);
    Object.assign(constructorForgery, {
      canonicalProjectionBytes: forgedBytes,
      document: forgedDocument,
      projectionSha256: forgedDigest,
      trust: "RESOLVED_SEMANTICS",
    });
    await expect(snapshotResolvedActivationComponentSet(constructorForgery)).rejects.toThrow(
      "ACTIVATION_COMPONENT_RESOLVER_INVALID",
    );
  });
});

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("resolver test object missing");
  }
  return value as JsonObject;
}

function stringField(value: JsonObject, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`resolver fixture ${key} missing`);
  return field;
}

function cloneWithComponentBucket(
  fixture: ActivationComponentResolverFixture,
  drift: Partial<ActivationComponentResolverFixture["componentSnapshot"]["bucket"]>,
): FixtureActivationComponentNamespaceReader {
  return new FixtureActivationComponentNamespaceReader(fixture.manifestSnapshot, {
    ...fixture.componentSnapshot,
    bucket: { ...fixture.componentSnapshot.bucket, ...drift },
  });
}
