import { sha256Hex } from "../src/canonical";
import type {
  ActivationComponentNamespaceReader,
  ActivationComponentNamespaceRequest,
  ActivationComponentNamespaceSnapshot,
  ActivationComponentNamespaceVersion,
} from "../src/activation-component-resolver-contract";
import {
  activationComponentManifestNamespacePrefix,
  activationComponentNamespacePrefix,
} from "../src/activation-component-resolver";
import {
  buildActivationComponentManifest,
  buildActivationComponentManifestPointer,
} from "../src/activation-component-manifest";
import type { ActivationWorm } from "../src/types";
import {
  confirmedComponentEnvelope,
  confirmedComponentManifest,
} from "./activation-component-manifest.fixtures";
import {
  productionValidComponentSetFixture,
  type ProductionValidComponentSetFixture,
} from "./activation-component-semantic.fixtures";

export interface ActivationComponentResolverFixture {
  readonly componentSnapshot: ActivationComponentNamespaceSnapshot;
  readonly manifestSnapshot: ActivationComponentNamespaceSnapshot;
  readonly pointerBytes: Uint8Array;
  readonly source: Awaited<ReturnType<typeof productionValidComponentSetFixture>>;
  readonly expectedComponentPrefix: string;
  readonly expectedManifestPrefix: string;
}

export interface ResolverReadTrace {
  readonly kind: "COMPONENTS" | "MANIFEST";
  readonly request: ActivationComponentNamespaceRequest;
}

export class FixtureActivationComponentNamespaceReader
  implements ActivationComponentNamespaceReader
{
  public readonly trace: ResolverReadTrace[] = [];

  public constructor(
    public manifestSnapshot: ActivationComponentNamespaceSnapshot,
    public componentSnapshot: ActivationComponentNamespaceSnapshot,
  ) {}

  public async readComponentNamespace(
    request: ActivationComponentNamespaceRequest,
  ): Promise<ActivationComponentNamespaceSnapshot> {
    this.trace.push({ kind: "COMPONENTS", request: { ...request } });
    return this.componentSnapshot;
  }

  public async readManifestNamespace(
    request: ActivationComponentNamespaceRequest,
  ): Promise<ActivationComponentNamespaceSnapshot> {
    this.trace.push({ kind: "MANIFEST", request: { ...request } });
    return this.manifestSnapshot;
  }
}

export async function productionResolverFixture(options?: {
  readonly reuseManifestVersion?: boolean;
}): Promise<ActivationComponentResolverFixture> {
  const source = await productionValidComponentSetFixture();
  return resolverFixtureForComponentSet(source, options);
}

export async function resolverFixtureForComponentSet(
  source: ProductionValidComponentSetFixture,
  options?: { readonly reuseManifestVersion?: boolean },
): Promise<ActivationComponentResolverFixture> {
  const confirmations = await Promise.all(
    source.input.envelopes.map((envelope, index) =>
      confirmedComponentEnvelope(
        source.input.descriptor.canonicalBytes,
        envelope,
        index,
        options?.reuseManifestVersion === true && index === 0
          ? "4_z-activation-component-manifest-0001"
          : undefined,
      ),
    ),
  );
  const manifest = await buildActivationComponentManifest(
    source.input.descriptor.canonicalBytes,
    confirmations,
  );
  const pointer = await buildActivationComponentManifestPointer(
    await confirmedComponentManifest(manifest),
  );
  const b2 = source.source.request.evidence.b2 as Record<string, unknown>;
  const bucket = {
    bucketId: String(b2.bucket_id),
    bucketName: String(b2.bucket_name),
    cloudflareAccountId: source.source.config.cloudflareAccountId,
  };
  return {
    componentSnapshot: namespaceSnapshot(
      await Promise.all(
        manifest.components.map((entry, index) =>
          namespaceVersion(source.input.envelopes[index]?.canonicalBytes, entry.worm),
        ),
      ),
      bucket,
    ),
    expectedComponentPrefix: activationComponentNamespacePrefix(
      manifest.workerVersionId,
      manifest.setId,
      manifest.descriptorId,
      manifest.descriptorSha256,
    ),
    expectedManifestPrefix: activationComponentManifestNamespacePrefix(
      manifest.workerVersionId,
      manifest.setId,
    ),
    manifestSnapshot: namespaceSnapshot(
      [await namespaceVersion(manifest.canonicalBytes, pointer.worm)],
      bucket,
    ),
    pointerBytes: Uint8Array.from(pointer.canonicalBytes),
    source,
  };
}

export function fixtureReader(
  fixture: ActivationComponentResolverFixture,
): FixtureActivationComponentNamespaceReader {
  return new FixtureActivationComponentNamespaceReader(
    fixture.manifestSnapshot,
    fixture.componentSnapshot,
  );
}

export function cloneSnapshot(
  input: ActivationComponentNamespaceSnapshot,
): ActivationComponentNamespaceSnapshot {
  return {
    bucket: { ...input.bucket },
    complete: input.complete,
    versions: input.versions.map((version) => ({
      ...version,
      canonicalBytes: Uint8Array.from(version.canonicalBytes),
    })),
  };
}

export function mutableVersion(
  input: ActivationComponentNamespaceSnapshot,
  index: number,
): ActivationComponentNamespaceVersion {
  const value = input.versions[index];
  if (value === undefined) throw new Error("resolver fixture version missing");
  return value;
}

function namespaceSnapshot(
  versions: readonly ActivationComponentNamespaceVersion[],
  identity: {
    readonly bucketId: string;
    readonly bucketName: string;
    readonly cloudflareAccountId: string;
  },
): ActivationComponentNamespaceSnapshot {
  return {
    bucket: {
      ...identity,
      defaultRetentionDays: 2557,
      encryption: "SSE-B2",
      objectLockEnabled: true,
      type: "allPrivate",
    },
    complete: true,
    versions,
  };
}

async function namespaceVersion(
  bytes: Uint8Array | undefined,
  worm: ActivationWorm,
): Promise<ActivationComponentNamespaceVersion> {
  if (bytes === undefined) throw new Error("resolver fixture body missing");
  return {
    canonicalBytes: Uint8Array.from(bytes),
    contentSha1: await sha1Hex(bytes),
    contentType: "application/json",
    deleteMarker: false,
    digest: `sha256:${await sha256Hex(bytes)}`,
    encryption: "SSE-B2",
    isLatest: true,
    key: worm.key,
    retentionMode: "COMPLIANCE",
    retentionUntil: worm.retentionUntil,
    size: bytes.byteLength,
    versionId: worm.versionId,
  };
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join(
    "",
  );
}
