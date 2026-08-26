import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
  type ActivationComponentDescriptor,
  type PreparedActivationComponentEnvelope,
  type PreparedActivationComponentManifest,
} from "./activation-component-contract";
import { componentError } from "./activation-component-codec";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import type { parseActivationComponentManifestPointer } from "./activation-component-manifest";
import {
  activationComponentManifestWormKey,
  validateActivationComponentWorm,
} from "./activation-component-manifest-worm";
import type { ActivationComponentResolverTrust } from "./activation-component-resolver-contract";
import type { OwnedActivationComponentNamespace } from "./activation-component-resolver-inventory";
import { ownExactUint8Array } from "./exact-uint8array";
import { SERVICE_AUTHORITY_DEFINITIONS } from "./service-authority";
import type { ActivationComponentSemanticTrust, JsonObject } from "./types";

export const ACTIVATION_COMPONENT_RESOLVER_INVALID =
  "ACTIVATION_COMPONENT_RESOLVER_INVALID" as const;

const TRUST_FIELDS = [
  "adminAccessApplicationId",
  "adminAccessAudience",
  "adminAccessGroup",
  "adminAccessIdentity",
  "adminAccessIssuer",
  "adminAccessPolicyId",
  "adminAccessSubjectId",
  "adminHostname",
  "adminMtlsCertSha256",
  "cloudflareAccountId",
] as const;

/** Pure validation helper; it never mints a resolver or execution capability. */
export async function parseActivationComponentResolverEnvelopes(
  bodies: readonly Uint8Array[],
  descriptor: ActivationComponentDescriptor,
  entries: PreparedActivationComponentManifest["components"],
): Promise<readonly PreparedActivationComponentEnvelope[]> {
  if (bodies.length !== ACTIVATION_COMPONENT_KINDS.length) fail();
  const envelopes: PreparedActivationComponentEnvelope[] = [];
  for (let index = 0; index < ACTIVATION_COMPONENT_KINDS.length; index += 1) {
    const body = bodies[index];
    const entry = entries[index];
    if (
      body === undefined ||
      entry === undefined ||
      entry.componentKind !== ACTIVATION_COMPONENT_KINDS[index]
    ) {
      fail();
    }
    const envelope = await parseActivationComponentEnvelope(body, descriptor.canonicalBytes);
    if (
      envelope.componentId !== entry.componentId ||
      envelope.componentKind !== entry.componentKind ||
      envelope.envelopeSha256 !== entry.envelopeSha256 ||
      envelope.payloadSha256 !== entry.payloadSha256 ||
      envelope.key !== entry.worm.key
    ) {
      fail();
    }
    validateActivationComponentWorm(entry.worm, envelope, descriptor);
    envelopes.push(envelope);
  }
  return Object.freeze(envelopes);
}

/** Project trusted resolver scalars from a data-only runtime-config superset. */
export function projectActivationComponentResolverTrust(
  input: unknown,
): ActivationComponentResolverTrust {
  return resolverTrust(input, false);
}

/** Snapshot the exact ten-field private trust state used by every replay. */
export function snapshotActivationComponentResolverTrust(
  input: unknown,
): ActivationComponentResolverTrust {
  return resolverTrust(input, true);
}

function resolverTrust(input: unknown, exact: boolean): ActivationComponentResolverTrust {
  try {
    if (input === null || typeof input !== "object" || Array.isArray(input)) fail();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Reflect.ownKeys(descriptors);
    if (
      Object.getPrototypeOf(input) !== Object.prototype ||
      (exact &&
        (keys.length !== TRUST_FIELDS.length ||
          keys.some(
            (key) => typeof key !== "string" || !(TRUST_FIELDS as readonly string[]).includes(key),
          )))
    ) {
      fail();
    }
    const result: Record<string, string> = {};
    for (const field of TRUST_FIELDS) {
      const descriptor = Reflect.get(descriptors, field) as PropertyDescriptor | undefined;
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor) ||
        typeof descriptor.value !== "string" ||
        descriptor.value.length < 1
      ) {
        fail();
      }
      result[field] = descriptor.value;
    }
    if (!/^[0-9a-f]{32}$/u.test(result.cloudflareAccountId ?? "")) fail();
    return Object.freeze(result) as unknown as ActivationComponentResolverTrust;
  } catch {
    fail();
  }
}

export function historicalActivationComponentResolverTrust(
  trust: ActivationComponentResolverTrust,
  workerVersionId: string,
): ActivationComponentSemanticTrust {
  const service = SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service;
  return Object.freeze({
    ...trust,
    workerServiceIdentity: `cloudflare-worker:${trust.cloudflareAccountId}/${service}@${workerVersionId}`,
    workerVersionId,
  });
}

export function assertActivationComponentManifestKey(
  pointer: ReturnType<typeof parseActivationComponentManifestPointer>,
): void {
  if (
    pointer.worm.key !==
    activationComponentManifestWormKey(
      pointer.workerVersionId,
      pointer.setId,
      pointer.manifestId,
      pointer.manifestSha256,
    )
  ) {
    fail();
  }
}

export function assertActivationComponentResolverBucket(
  manifest: OwnedActivationComponentNamespace["bucket"],
  components: OwnedActivationComponentNamespace["bucket"],
  b2: JsonObject,
  accountId: string,
): void {
  if (
    manifest.cloudflareAccountId !== accountId ||
    components.cloudflareAccountId !== manifest.cloudflareAccountId ||
    components.bucketId !== manifest.bucketId ||
    components.bucketName !== manifest.bucketName ||
    b2.bucket_id !== manifest.bucketId ||
    b2.bucket_name !== manifest.bucketName
  ) {
    fail();
  }
}

export function ownActivationComponentResolverBytes(input: unknown): Uint8Array<ArrayBuffer> {
  return ownExactUint8Array(input, {
    code: ACTIVATION_COMPONENT_RESOLVER_INVALID,
    invalidStatus: 409,
    maximum: ACTIVATION_COMPONENT_MANIFEST_MAX_BYTES,
    minimum: 1,
    sizeStatus: 413,
  });
}

export function sameActivationComponentResolverBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function fail(): never {
  throw componentError(ACTIVATION_COMPONENT_RESOLVER_INVALID);
}
