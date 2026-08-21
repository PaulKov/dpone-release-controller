import { sha256Hex, timingSafeEqual } from "./canonical";
import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  type ActivationComponentDescriptor,
  type PreparedActivationComponentManifest,
} from "./activation-component-contract";
import { componentError } from "./activation-component-codec";
import { buildActivationComponentSetDescriptor } from "./activation-component-descriptor";
import type { ActivationComponentSetSemanticInput } from "./activation-component-journal-contract";
import { parseActivationComponentManifest } from "./activation-component-manifest";
import {
  parseActivationComponentManifestPointer,
  validateActivationManifestWorm,
} from "./activation-component-manifest-worm";
import { validateAndReconstructActivationComponentSet } from "./activation-component-reconstruction";
import {
  ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT,
  ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT,
  type ActivationComponentNamespaceReader,
  type ActivationComponentResolverTrust,
  type ResolvedActivationComponentSet,
} from "./activation-component-resolver-contract";
import {
  RESOLVED_ACTIVATION_COMPONENT_EXECUTION_SOURCE_TRUST,
  type ResolvedActivationComponentExecutionSource,
} from "./activation-component-resolver-execution-contract";
import {
  resolveExactActivationComponentNamespace,
  snapshotActivationComponentNamespaceAuthority,
  type OwnedActivationComponentNamespace,
} from "./activation-component-resolver-inventory";
import {
  activationComponentManifestNamespacePrefix,
  activationComponentNamespacePrefix,
} from "./activation-component-resolver-prefix";
import {
  buildActivationComponentResolverProjection,
  parseActivationComponentResolverProjection,
  type PreparedActivationComponentResolverProjection,
} from "./activation-component-resolver-projection";
import {
  ACTIVATION_COMPONENT_RESOLVER_INVALID,
  assertActivationComponentManifestKey,
  assertActivationComponentResolverBucket,
  historicalActivationComponentResolverTrust,
  ownActivationComponentResolverBytes,
  parseActivationComponentResolverEnvelopes,
  projectActivationComponentResolverTrust,
  sameActivationComponentResolverBytes,
  snapshotActivationComponentResolverTrust,
} from "./activation-component-resolver-validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;

interface ResolverAuthorityState {
  readonly componentNamespace: OwnedActivationComponentNamespace;
  readonly manifestNamespace: OwnedActivationComponentNamespace;
  readonly pointerBytes: Uint8Array<ArrayBuffer>;
  readonly projectionBytes: Uint8Array<ArrayBuffer>;
  readonly projectionSha256: string;
  readonly trust: ActivationComponentResolverTrust;
}

interface ReplayedResolverAuthority {
  readonly projection: PreparedActivationComponentResolverProjection;
  readonly state: ResolverAuthorityState;
}

const RESOLVER_STATES = new WeakMap<object, ResolverAuthorityState>();

/**
 * Resolve one exact WORM pointer into compact semantics while privately
 * retaining all provider inventory needed for deterministic future replay.
 */
export class ConfidentialActivationComponentResolver {
  private readonly reader: ActivationComponentNamespaceReader;
  private readonly trust: ActivationComponentResolverTrust;

  public constructor(
    reader: ActivationComponentNamespaceReader,
    trust: ActivationComponentResolverTrust,
  ) {
    this.reader = reader;
    this.trust = projectActivationComponentResolverTrust(trust);
  }

  public async resolve(canonicalPointerBytes: Uint8Array): Promise<ResolvedActivationComponentSet> {
    return resolvedValue(
      await readResolverAuthority(this.reader, this.trust, canonicalPointerBytes),
    );
  }
}

/** Re-own and fully replay the private provider authority before compact use. */
export async function snapshotResolvedActivationComponentSet(
  input: unknown,
): Promise<ResolvedActivationComponentSet> {
  return resolvedValue(await replayResolverAuthority(resolverState(input)));
}

/**
 * Mint an opaque source only after replaying all provider bodies, metadata,
 * closed semantics and compact projection from private WeakMap state.
 */
export async function snapshotResolvedActivationComponentExecutionSource(
  input: unknown,
): Promise<ResolvedActivationComponentExecutionSource> {
  return executionSourceValue(await replayResolverAuthority(resolverState(input)));
}

async function readResolverAuthority(
  reader: ActivationComponentNamespaceReader,
  trust: ActivationComponentResolverTrust,
  pointerInput: unknown,
): Promise<ReplayedResolverAuthority> {
  const pointerBytes = ownActivationComponentResolverBytes(pointerInput);
  const ownedTrust = snapshotActivationComponentResolverTrust(trust);
  const pointer = parseActivationComponentManifestPointer(pointerBytes);
  assertActivationComponentManifestKey(pointer);
  const manifestNamespace = await resolveExactActivationComponentNamespace(
    await reader.readManifestNamespace(
      Object.freeze({
        maximumObjectBytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
        maximumVersions: ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT,
        prefix: activationComponentManifestNamespacePrefix(pointer.workerVersionId, pointer.setId),
      }),
    ),
    [{ worm: pointer.worm }],
    ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT,
  );
  const manifest = await resolvedManifest(manifestNamespace, pointer);
  const descriptor = await resolvedDescriptor(manifest);
  const componentNamespace = await resolveExactActivationComponentNamespace(
    await reader.readComponentNamespace(
      Object.freeze({
        maximumObjectBytes: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
        maximumVersions: ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT,
        prefix: activationComponentNamespacePrefix(
          descriptor.workerVersionId,
          descriptor.setId,
          descriptor.descriptorId,
          descriptor.descriptorSha256,
        ),
      }),
    ),
    manifest.components.map(({ worm }) => ({ worm })),
    ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT,
  );
  assertDistinctManifestVersion(componentNamespace, pointer.worm.versionId);
  return finalizeResolverAuthority(
    pointerBytes,
    ownedTrust,
    manifestNamespace,
    componentNamespace,
    manifest,
    descriptor,
  );
}

async function replayResolverAuthority(
  owned: ResolverAuthorityState,
): Promise<ReplayedResolverAuthority> {
  const pointer = parseActivationComponentManifestPointer(owned.pointerBytes);
  assertActivationComponentManifestKey(pointer);
  const manifestNamespace = await resolveExactActivationComponentNamespace(
    owned.manifestNamespace,
    [{ worm: pointer.worm }],
    ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT,
  );
  const manifest = await resolvedManifest(manifestNamespace, pointer);
  const descriptor = await resolvedDescriptor(manifest);
  const componentNamespace = await resolveExactActivationComponentNamespace(
    owned.componentNamespace,
    manifest.components.map(({ worm }) => ({ worm })),
    ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT,
  );
  assertDistinctManifestVersion(componentNamespace, pointer.worm.versionId);
  const replayed = await finalizeResolverAuthority(
    owned.pointerBytes,
    owned.trust,
    manifestNamespace,
    componentNamespace,
    manifest,
    descriptor,
  );
  if (
    !sameActivationComponentResolverBytes(
      replayed.projection.canonicalBytes,
      owned.projectionBytes,
    ) ||
    !timingSafeEqual(replayed.state.projectionSha256, owned.projectionSha256)
  ) {
    fail();
  }
  return replayed;
}

async function finalizeResolverAuthority(
  pointerBytes: Uint8Array<ArrayBuffer>,
  trust: ActivationComponentResolverTrust,
  manifestNamespace: OwnedActivationComponentNamespace,
  componentNamespace: OwnedActivationComponentNamespace,
  manifest: PreparedActivationComponentManifest,
  descriptor: ActivationComponentDescriptor,
): Promise<ReplayedResolverAuthority> {
  const envelopes = await parseActivationComponentResolverEnvelopes(
    componentNamespace.versions.map(({ canonicalBytes }) => canonicalBytes),
    descriptor,
    manifest.components,
  );
  const semanticInput: ActivationComponentSetSemanticInput = Object.freeze({
    descriptor,
    envelopes,
  });
  const validated = await validateAndReconstructActivationComponentSet(
    semanticInput,
    historicalActivationComponentResolverTrust(trust, descriptor.workerVersionId),
  );
  assertActivationComponentResolverBucket(
    manifestNamespace.bucket,
    componentNamespace.bucket,
    validated.payloads.b2,
    trust.cloudflareAccountId,
  );
  const pointer = parseActivationComponentManifestPointer(pointerBytes);
  const projection = parseActivationComponentResolverProjection(
    buildActivationComponentResolverProjection(validated, manifest, pointer.worm).canonicalBytes,
  );
  const projectionSha256 = `sha256:${await sha256Hex(projection.canonicalBytes)}`;
  return Object.freeze({
    projection,
    state: Object.freeze({
      componentNamespace,
      manifestNamespace,
      pointerBytes: ownActivationComponentResolverBytes(pointerBytes),
      projectionBytes: ownActivationComponentResolverBytes(projection.canonicalBytes),
      projectionSha256,
      trust,
    }),
  });
}

async function resolvedManifest(
  namespace: OwnedActivationComponentNamespace,
  pointer: ReturnType<typeof parseActivationComponentManifestPointer>,
): Promise<PreparedActivationComponentManifest> {
  const body = namespace.versions[0]?.canonicalBytes;
  if (body === undefined) fail();
  const manifest = await parseActivationComponentManifest(body);
  if (
    manifest.manifestId !== pointer.manifestId ||
    manifest.manifestSha256 !== pointer.manifestSha256 ||
    manifest.setId !== pointer.setId ||
    manifest.workerVersionId !== pointer.workerVersionId
  ) {
    fail();
  }
  validateActivationManifestWorm(pointer.worm, manifest);
  return manifest;
}

async function resolvedDescriptor(
  manifest: PreparedActivationComponentManifest,
): Promise<ActivationComponentDescriptor> {
  const descriptor = await buildActivationComponentSetDescriptor({
    committedAt: manifest.committedAt,
    components: manifest.components.map(({ componentKind, payloadSha256 }) => ({
      componentKind,
      payloadSha256,
    })),
    workerVersionId: manifest.workerVersionId,
  });
  if (
    descriptor.descriptorId !== manifest.descriptorId ||
    descriptor.descriptorSha256 !== manifest.descriptorSha256 ||
    descriptor.setId !== manifest.setId
  ) {
    fail();
  }
  return descriptor;
}

function resolvedValue(replayed: ReplayedResolverAuthority): ResolvedActivationComponentSet {
  const state = registerState(replayed.state);
  const value = Object.freeze({
    get canonicalProjectionBytes(): Uint8Array {
      return Uint8Array.from(state.projectionBytes);
    },
    document: replayed.projection.document,
    projectionSha256: state.projectionSha256,
    trust: "RESOLVED_SEMANTICS" as const,
  });
  RESOLVER_STATES.set(value, state);
  return value;
}

function executionSourceValue(
  replayed: ReplayedResolverAuthority,
): ResolvedActivationComponentExecutionSource {
  const state = registerState(replayed.state);
  const value = Object.freeze({
    projectionSha256: state.projectionSha256,
    trust: RESOLVED_ACTIVATION_COMPONENT_EXECUTION_SOURCE_TRUST,
  });
  RESOLVER_STATES.set(value, state);
  return value;
}

function resolverState(input: unknown): ResolverAuthorityState {
  if (input === null || typeof input !== "object") fail();
  const state = RESOLVER_STATES.get(input);
  if (state === undefined) fail();
  return snapshotState(state);
}

function registerState(input: ResolverAuthorityState): ResolverAuthorityState {
  return snapshotState(input);
}

function snapshotState(input: ResolverAuthorityState): ResolverAuthorityState {
  try {
    if (!DIGEST.test(input.projectionSha256)) fail();
    return Object.freeze({
      componentNamespace: snapshotActivationComponentNamespaceAuthority(
        input.componentNamespace,
        ACTIVATION_COMPONENT_KINDS.length,
        ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT,
      ),
      manifestNamespace: snapshotActivationComponentNamespaceAuthority(
        input.manifestNamespace,
        1,
        ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT,
      ),
      pointerBytes: ownActivationComponentResolverBytes(input.pointerBytes),
      projectionBytes: ownActivationComponentResolverBytes(input.projectionBytes),
      projectionSha256: input.projectionSha256,
      trust: snapshotActivationComponentResolverTrust(input.trust),
    });
  } catch {
    fail();
  }
}

function assertDistinctManifestVersion(
  namespace: OwnedActivationComponentNamespace,
  manifestVersionId: string,
): void {
  if (namespace.versions.some(({ versionId }) => versionId === manifestVersionId)) fail();
}

function fail(): never {
  throw componentError(ACTIVATION_COMPONENT_RESOLVER_INVALID);
}
