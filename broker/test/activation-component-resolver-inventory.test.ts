import { beforeAll, describe, expect, it } from "vitest";

import type {
  ActivationComponentNamespaceSnapshot,
  ActivationComponentNamespaceVersion,
} from "../src/activation-component-resolver-contract";
import { resolveExactActivationComponentNamespace } from "../src/activation-component-resolver-inventory";
import { BrokerError } from "../src/errors";
import type { ActivationWorm } from "../src/types";
import {
  cloneSnapshot,
  productionResolverFixture,
  type ActivationComponentResolverFixture,
} from "./activation-component-resolver.fixtures";

describe("activation component resolver namespace inventory", () => {
  let fixture: ActivationComponentResolverFixture;
  let expected: readonly { readonly worm: ActivationWorm }[];

  beforeAll(async () => {
    fixture = await productionResolverFixture();
    expected = expectedWorms(fixture.componentSnapshot);
  });

  it("owns bodies synchronously and returns manifest order", async () => {
    const snapshot = cloneSnapshot(fixture.componentSnapshot);
    const reversed = { ...snapshot, versions: [...snapshot.versions].reverse() };
    const resolving = resolveExactActivationComponentNamespace(reversed, expected, 16);
    reversed.versions.forEach(({ canonicalBytes }) => canonicalBytes.fill(0));

    const resolved = await resolving;
    expect(resolved.versions.map(({ key }) => key)).toEqual(expected.map(({ worm }) => worm.key));
    expect(resolved.versions.every(({ canonicalBytes }) => canonicalBytes[0] === 123)).toBe(true);
  });

  it("owns the complete expected WORM roster before the first digest await", async () => {
    const mutableExpected = expected.map(({ worm }) => ({ worm: { ...worm } }));
    const originalKeys = mutableExpected.map(({ worm }) => worm.key);
    const laterAuthority = mutableExpected[1];
    if (laterAuthority === undefined) throw new Error("expected WORM fixture missing");
    const resolving = resolveExactActivationComponentNamespace(
      cloneSnapshot(fixture.componentSnapshot),
      mutableExpected,
      16,
    );

    laterAuthority.worm.key = "receipts/v2/activation-components/forged.json";
    mutableExpected.reverse();
    mutableExpected[0] = { worm: { ...laterAuthority.worm } };

    await expect(resolving).resolves.toMatchObject({
      versions: originalKeys.map((key) => ({ key })),
    });
  });

  it("normalizes a hostile expected-roster boundary without invoking getters", async () => {
    let reads = 0;
    const hostile = new Proxy([...expected], {
      get() {
        reads += 1;
        throw new Error("expected roster get trap must not execute");
      },
      getPrototypeOf() {
        throw new Error("expected roster prototype trap");
      },
    });

    await expect(
      resolveExactActivationComponentNamespace(
        cloneSnapshot(fixture.componentSnapshot),
        hostile,
        16,
      ),
    ).rejects.toMatchObject({
      code: "ACTIVATION_COMPONENT_RESOLVER_INVENTORY_INVALID",
      retryable: false,
    });
    expect(reads).toBe(0);
  });

  it.each([
    [
      "incomplete",
      (value: MutableSnapshot): void => {
        value.complete = false;
      },
    ],
    [
      "bucket encryption",
      (value: MutableSnapshot): void => {
        value.bucket.encryption = "AES256";
      },
    ],
    [
      "bucket lock",
      (value: MutableSnapshot): void => {
        value.bucket.objectLockEnabled = false;
      },
    ],
    [
      "bucket type",
      (value: MutableSnapshot): void => {
        value.bucket.type = "allPublic";
      },
    ],
    [
      "bucket retention",
      (value: MutableSnapshot): void => {
        value.bucket.defaultRetentionDays = 1;
      },
    ],
    ["delete marker", mutateVersion("deleteMarker", true)],
    ["content type", mutateVersion("contentType", "application/octet-stream")],
    ["nonlatest", mutateVersion("isLatest", false)],
    ["object encryption", mutateVersion("encryption", "AES256")],
    ["retention mode", mutateVersion("retentionMode", null)],
    ["retention time", mutateVersion("retentionUntil", "2035-08-20T12:00:00.000Z")],
    [
      "size",
      (value: MutableSnapshot): void => {
        version(value).size += 1;
      },
    ],
    ["sha1", mutateVersion("contentSha1", "0".repeat(40))],
    ["sha256", mutateVersion("digest", `sha256:${"0".repeat(64)}`)],
    ["version", mutateVersion("versionId", "4_z-transplanted-version")],
    ["key", mutateVersion("key", "receipts/v2/activation-components/forged.json")],
    [
      "body",
      (value: MutableSnapshot): void => {
        version(value).canonicalBytes.fill(0);
      },
    ],
  ] as const)("rejects %s drift", async (_name, mutate) => {
    const snapshot = mutableSnapshot(fixture.componentSnapshot);
    mutate(snapshot);
    await expect(resolveExactActivationComponentNamespace(snapshot, expected, 16)).rejects.toThrow(
      "ACTIVATION_COMPONENT_RESOLVER_INVENTORY_INVALID",
    );
  });

  it("rejects missing and extra namespace versions before copying an extra body", async () => {
    const missing = cloneSnapshot(fixture.componentSnapshot);
    await expect(
      resolveExactActivationComponentNamespace(
        { ...missing, versions: missing.versions.slice(0, -1) },
        expected,
        16,
      ),
    ).rejects.toBeInstanceOf(BrokerError);

    let copied = false;
    const extraBody = new Proxy(new Uint8Array([123]), {
      get(target, property, receiver) {
        if (property === "byteLength") copied = true;
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const extra = {
      ...cloneSnapshot(fixture.componentSnapshot),
      versions: [
        ...cloneSnapshot(fixture.componentSnapshot).versions,
        { ...fixture.componentSnapshot.versions[0], canonicalBytes: extraBody },
      ],
    } as ActivationComponentNamespaceSnapshot;
    await expect(
      resolveExactActivationComponentNamespace(extra, expected, 16),
    ).rejects.toBeInstanceOf(BrokerError);
    expect(copied).toBe(false);
  });

  it.each([
    ["accessor", accessorVersion],
    ["symbol", symbolVersion],
    ["non-enumerable", nonEnumerableVersion],
    ["class", classVersion],
    ["array subclass", arraySubclass],
    ["sparse", sparseVersions],
    ["array extra", extraArrayProperty],
    ["proxy", throwingProxy],
  ] as const)("normalizes malformed data-only boundary: %s", async (_name, mutate) => {
    const snapshot = mutableSnapshot(fixture.componentSnapshot);
    const malformed = mutate(snapshot);
    await expect(
      resolveExactActivationComponentNamespace(malformed, expected, 16),
    ).rejects.toMatchObject({
      code: "ACTIVATION_COMPONENT_RESOLVER_INVENTORY_INVALID",
      retryable: false,
    });
  });

  it("rejects duplicate keys and duplicate versions", async () => {
    for (const field of ["key", "versionId"] as const) {
      const snapshot = mutableSnapshot(fixture.componentSnapshot);
      const first = version(snapshot, 0);
      const second = version(snapshot, 1);
      second[field] = first[field];
      await expect(
        resolveExactActivationComponentNamespace(snapshot, expected, 16),
      ).rejects.toBeInstanceOf(BrokerError);
    }
  });

  it("snapshots descriptor values without invoking a Proxy get trap", async () => {
    const snapshot = mutableSnapshot(fixture.componentSnapshot);
    let reads = 0;
    snapshot.versions[0] = new Proxy(version(snapshot), {
      get() {
        reads += 1;
        throw new Error("provider get trap must not execute");
      },
    });
    const resolved = await resolveExactActivationComponentNamespace(snapshot, expected, 16);
    expect(resolved.versions).toHaveLength(expected.length);
    expect(reads).toBe(0);
  });

  it("rejects an oversized body before attempting to copy it", async () => {
    const snapshot = mutableSnapshot(fixture.componentSnapshot);
    let copied = false;
    const oversized = new Proxy(new Uint8Array(65_537), {
      get(target, property, receiver) {
        if (property === Symbol.iterator || property === "0") copied = true;
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    version(snapshot).canonicalBytes = oversized;
    await expect(
      resolveExactActivationComponentNamespace(snapshot, expected, 16),
    ).rejects.toBeInstanceOf(BrokerError);
    expect(copied).toBe(false);
  });
});

type MutableVersion = {
  -readonly [K in keyof ActivationComponentNamespaceVersion]: ActivationComponentNamespaceVersion[K];
};
type MutableBucket = {
  -readonly [K in keyof ActivationComponentNamespaceSnapshot["bucket"]]: ActivationComponentNamespaceSnapshot["bucket"][K];
};
interface MutableSnapshot extends ActivationComponentNamespaceSnapshot {
  bucket: MutableBucket;
  complete: boolean;
  versions: MutableVersion[];
}

function mutableSnapshot(input: ActivationComponentNamespaceSnapshot): MutableSnapshot {
  return cloneSnapshot(input) as MutableSnapshot;
}

function version(input: MutableSnapshot, index = 0): MutableVersion {
  const candidate = input.versions[index];
  if (candidate === undefined) throw new Error("resolver inventory version missing");
  return candidate;
}

function mutateVersion<K extends keyof MutableVersion>(key: K, value: MutableVersion[K]) {
  return (snapshot: MutableSnapshot) => {
    version(snapshot)[key] = value;
  };
}

function expectedWorms(
  input: ActivationComponentNamespaceSnapshot,
): readonly { readonly worm: ActivationWorm }[] {
  return input.versions.map((candidate) => {
    if (candidate.digest === null || candidate.retentionUntil === null) {
      throw new Error("resolver fixture WORM metadata missing");
    }
    return {
      worm: {
        digest: candidate.digest,
        key: candidate.key,
        retentionUntil: candidate.retentionUntil,
        versionId: candidate.versionId,
      },
    };
  });
}

function accessorVersion(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  Object.defineProperty(version(input), "digest", {
    enumerable: true,
    get() {
      throw new Error("accessor must not execute");
    },
  });
  return input;
}

function symbolVersion(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  Object.defineProperty(version(input), Symbol("hidden"), { enumerable: true, value: true });
  return input;
}

function nonEnumerableVersion(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  Object.defineProperty(version(input), "digest", {
    enumerable: false,
    value: version(input).digest,
  });
  return input;
}

function classVersion(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  class ProviderVersion {
    public providerVersion(): true {
      return true;
    }
  }
  input.versions[0] = Object.assign(new ProviderVersion(), version(input));
  return input;
}

function arraySubclass(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  class ProviderVersions extends Array<MutableVersion> {}
  input.versions = ProviderVersions.from(input.versions);
  return input;
}

function sparseVersions(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  Reflect.deleteProperty(input.versions, "1");
  return input;
}

function extraArrayProperty(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  Object.defineProperty(input.versions, "hidden", { enumerable: true, value: true });
  return input;
}

function throwingProxy(input: MutableSnapshot): ActivationComponentNamespaceSnapshot {
  return new Proxy(input, {
    ownKeys() {
      throw new Error("provider proxy trap");
    },
  });
}
