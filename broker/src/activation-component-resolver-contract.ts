import type { ActivationAdminSemanticTrust, JsonObject } from "./types";

export const ACTIVATION_COMPONENT_RESOLVER_MANIFEST_VERSION_LIMIT = 2 as const;
export const ACTIVATION_COMPONENT_RESOLVER_COMPONENT_VERSION_LIMIT = 16 as const;

/** Stable semantic commitments consumed by the confidential resolver. */
export type ActivationComponentResolverTrust = ActivationAdminSemanticTrust;

export interface ActivationComponentNamespaceBucket {
  readonly bucketId: string;
  readonly bucketName: string;
  /** Authenticated Cloudflare reader authority; this is not a Backblaze account ID. */
  readonly cloudflareAccountId: string;
  readonly defaultRetentionDays: number;
  readonly encryption: string;
  readonly objectLockEnabled: boolean;
  readonly type: string;
}

/** One exact downloaded version plus independently observed immutable metadata. */
export interface ActivationComponentNamespaceVersion {
  readonly canonicalBytes: Uint8Array;
  readonly contentType: string;
  readonly contentSha1: string;
  readonly deleteMarker: boolean;
  readonly digest: string | null;
  readonly encryption: string;
  readonly isLatest: boolean;
  readonly key: string;
  readonly retentionMode: string | null;
  readonly retentionUntil: string | null;
  readonly size: number;
  readonly versionId: string;
}

/** Complete, non-paginated inventory for one resolver-derived namespace prefix. */
export interface ActivationComponentNamespaceSnapshot {
  readonly bucket: ActivationComponentNamespaceBucket;
  readonly complete: boolean;
  readonly versions: readonly ActivationComponentNamespaceVersion[];
}

export interface ActivationComponentNamespaceRequest {
  readonly maximumObjectBytes: 65_536;
  readonly maximumVersions: 2 | 16;
  readonly prefix: string;
}

/**
 * Specialized confidential port. It cannot read an arbitrary key: the
 * resolver supplies one exact manifest or descriptor namespace prefix.
 * A future adapter must enforce object-size limits while streaming.
 */
export interface ActivationComponentNamespaceReader {
  readComponentNamespace(
    request: ActivationComponentNamespaceRequest,
  ): Promise<ActivationComponentNamespaceSnapshot>;

  readManifestNamespace(
    request: ActivationComponentNamespaceRequest,
  ): Promise<ActivationComponentNamespaceSnapshot>;
}

export interface ResolvedActivationComponentSet {
  readonly canonicalProjectionBytes: Uint8Array;
  readonly document: JsonObject;
  readonly projectionSha256: string;
  readonly trust: "RESOLVED_SEMANTICS";
}
