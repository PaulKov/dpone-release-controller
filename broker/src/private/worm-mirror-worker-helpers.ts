import { canonicalJson } from "../canonical";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { BrokerError } from "../errors";
import type { RawProviderEvidenceKind } from "../provider-evidence";
import type { JsonObject, PrivateServicePin } from "../types";
import { requireInteger, requireString } from "../validation";
import type { B2NativeConfig } from "./b2-native";
import type { CloudflareEvidenceBatch } from "./cloudflare-evidence-batch-do";
import type { WormExactObjectEffect } from "./worm-exact-object-effect-do";

export const VERSION = CLOUDFLARE_UUID;
const SERVICE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u;
const B2_OBSERVER_SERVICE = "dpone-release-worm-version-observer";
export const TAGGED_DIGEST = /^sha256:[0-9a-f]{64}$/u;
export const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

export interface WormMirrorEnv {
  readonly B2_APPLICATION_KEY?: string;
  readonly B2_BUCKET_ID?: string;
  readonly B2_BUCKET_NAME?: string;
  readonly B2_KEY_ID?: string;
  readonly CF_ACCOUNT_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly OPERATING_MODE: string;
  readonly SERVICE_NAME?: string;
  readonly WORM_VERSION_OBSERVER?: Fetcher;
  readonly WORM_EXPECTED_CALLER_SERVICE_IDENTITY?: string;
  readonly WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY?: string;
  readonly WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY?: string;
  readonly WORM_RPC_AUTH_KEY?: string;
  readonly CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY?: string;
  readonly CLOUDFLARE_EVIDENCE_BATCHES?: DurableObjectNamespace<CloudflareEvidenceBatch>;
  readonly WORM_EXACT_OBJECT_EFFECTS?: DurableObjectNamespace<WormExactObjectEffect>;
}

export function assertExpectedCallee(headers: Headers, env: WormMirrorEnv): void {
  const accountId = exactEnvironment(env.CF_ACCOUNT_ID, /^[0-9a-f]{32}$/u, 32);
  const serviceName = exactEnvironment(
    env.SERVICE_NAME,
    /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u,
    128,
  );
  const versionId = requireVersionId(env);
  const expectedIdentity = `cloudflare-worker:${accountId}/${serviceName}@${versionId}`;
  if (
    exactHeader(headers, "x-dpone-callee-service", SERVICE, 128) !== serviceName ||
    exactHeader(headers, "x-dpone-callee-version", VERSION, 128) !== versionId ||
    exactHeader(
      headers,
      "x-dpone-callee-service-identity",
      /^cloudflare-worker:[A-Za-z0-9._-]{1,128}\/[A-Za-z0-9._-]{2,128}@[A-Za-z0-9._-]{16,128}$/u,
      512,
    ) !== expectedIdentity
  ) {
    throw new BrokerError("PRIVATE_SERVICE_VERSION_FALLBACK", 503, false);
  }
}

interface MirrorBinding {
  readonly committedAt: string;
  readonly digest: string;
  readonly ingressWorkerVersion: string;
  readonly observerPin: PrivateServicePin;
}

interface ActivationEvidenceMirrorBinding extends MirrorBinding {
  readonly evidenceKind: RawProviderEvidenceKind;
}

export function parseActivationEvidenceBinding(
  envelope: JsonObject,
  headers: Headers,
): ActivationEvidenceMirrorBinding {
  const evidenceKind = exactHeader(
    headers,
    "x-dpone-evidence-kind",
    /^(?:github_branch_ruleset|github_oidc_subject_customization)$/u,
    64,
  ) as RawProviderEvidenceKind;
  const expectedSchema = "dpone.release-broker-provider-evidence-entry.v1";
  if (
    envelope.schema !== expectedSchema ||
    envelope.schema_version !== 1 ||
    envelope.evidence_kind !== evidenceKind
  ) {
    throw new BrokerError("MIRROR_EVIDENCE_BINDING_INVALID", 400, false);
  }
  const committedAt = exactHeader(headers, "x-dpone-committed-at", TIMESTAMP, 32);
  const observedAt = requireString(envelope, "observed_at", 32, TIMESTAMP);
  const committedMs = Date.parse(committedAt);
  const observedMs = Date.parse(observedAt);
  if (
    !Number.isFinite(committedMs) ||
    !Number.isFinite(observedMs) ||
    committedMs < observedMs ||
    committedMs - observedMs > 900_000
  ) {
    throw new BrokerError("MIRROR_EVIDENCE_TIME_INVALID", 400, false);
  }
  return {
    committedAt,
    digest: exactHeader(headers, "x-dpone-canonical-sha256", TAGGED_DIGEST, 71),
    evidenceKind,
    ingressWorkerVersion: exactHeader(headers, "x-dpone-ingress-worker-version", VERSION, 128),
    observerPin: observerPinFromHeaders(headers),
  };
}

interface ActivationMirrorBinding extends MirrorBinding {
  readonly sequence: 0 | 1;
}

export function parseActivationBinding(
  envelope: JsonObject,
  headers: Headers,
): ActivationMirrorBinding {
  const schema = requireString(envelope, "schema", 64);
  if (
    schema !== "dpone.release-broker-provisioned.v1" &&
    schema !== "dpone.release-broker-activated.v1"
  ) {
    throw new BrokerError("MIRROR_SCHEMA_INVALID", 400, false);
  }
  requireExactInteger(envelope, "schema_version", 1);
  const sequence = requireInteger(envelope, "sequence", 0, 1) as 0 | 1;
  const recordId = requireString(envelope, "record_id", 71, TAGGED_DIGEST);
  const committedAt = requireString(envelope, "committed_at", 32, TIMESTAMP);
  const digest = exactHeader(headers, "x-dpone-canonical-sha256", TAGGED_DIGEST, 71);
  const headerRecordId = exactHeader(headers, "x-dpone-record-id", TAGGED_DIGEST, 71);
  const headerSequence = exactHeader(headers, "x-dpone-sequence", /^[01]$/u, 1);
  const headerCommittedAt = exactHeader(headers, "x-dpone-committed-at", TIMESTAMP, 32);
  if (
    recordId !== headerRecordId ||
    sequence !== Number(headerSequence) ||
    committedAt !== headerCommittedAt
  ) {
    throw new BrokerError("MIRROR_ACTIVATION_BINDING_INVALID", 400, false);
  }
  return {
    committedAt,
    digest,
    ingressWorkerVersion: exactHeader(headers, "x-dpone-ingress-worker-version", VERSION, 128),
    observerPin: observerPinFromHeaders(headers),
    sequence,
  };
}

export function observerPinFromHeaders(headers: Headers): PrivateServicePin {
  const serviceIdentity = exactHeader(
    headers,
    "x-dpone-observer-service-identity",
    /^cloudflare-worker:[A-Za-z0-9._-]{1,128}\/[A-Za-z0-9._-]{2,128}@[A-Za-z0-9._-]{16,128}$/u,
    512,
  );
  const serviceName = exactHeader(headers, "x-dpone-observer-service", SERVICE, 128);
  const versionId = exactHeader(headers, "x-dpone-observer-version", VERSION, 128);
  if (!serviceIdentity.endsWith(`/${serviceName}@${versionId}`)) {
    throw new BrokerError("MIRROR_OBSERVER_BINDING_INVALID", 400, false);
  }
  return { serviceIdentity, serviceName, versionId };
}

/** Resolve and validate the immutable B2 observer identity from WORM config. */
export function requireExpectedB2ObserverPin(env: WormMirrorEnv): PrivateServicePin {
  const accountId = exactEnvironment(env.CF_ACCOUNT_ID, /^[0-9a-f]{32}$/u, 32);
  const serviceIdentity = exactEnvironment(
    env.WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY,
    /^cloudflare-worker:[0-9a-f]{32}\/dpone-release-worm-version-observer@[0-9a-f-]{36}$/u,
    512,
  );
  const prefix = `cloudflare-worker:${accountId}/${B2_OBSERVER_SERVICE}@`;
  const versionId = serviceIdentity.startsWith(prefix) ? serviceIdentity.slice(prefix.length) : "";
  if (!VERSION.test(versionId)) {
    throw new BrokerError("B2_OBSERVER_PIN_INVALID", 503, false);
  }
  return { serviceIdentity, serviceName: B2_OBSERVER_SERVICE, versionId };
}

/** Reject caller-selected/old B2 readers before any body or provider effect. */
export function assertExpectedB2ObserverPin(pin: PrivateServicePin, env: WormMirrorEnv): void {
  const expected = requireExpectedB2ObserverPin(env);
  if (
    pin.serviceIdentity !== expected.serviceIdentity ||
    pin.serviceName !== expected.serviceName ||
    pin.versionId !== expected.versionId
  ) {
    throw new BrokerError("B2_OBSERVER_PIN_INVALID", 503, false);
  }
}

export function requireConfig(env: WormMirrorEnv): B2NativeConfig {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("PRIVATE_SERVICE_PROVISIONING", 503, true);
  }
  return {
    applicationKey: secret(env.B2_APPLICATION_KEY),
    bucketId: required(env.B2_BUCKET_ID),
    bucketName: required(env.B2_BUCKET_NAME),
    keyId: secret(env.B2_KEY_ID),
    prefix: "receipts/v1/",
  };
}

export function exactHeader(
  headers: Headers,
  name: string,
  pattern: RegExp,
  maximum: number,
): string {
  const value = headers.get(name);
  pattern.lastIndex = 0;
  const match = value === null ? null : pattern.exec(value);
  if (value === null || value.length > maximum || match?.[0] !== value) {
    throw new BrokerError("MIRROR_HEADER_INVALID", 400, false);
  }
  return value;
}

export function requireVersionId(env: WormMirrorEnv): string {
  const value = env.CF_VERSION_METADATA?.id;
  if (value === undefined || !VERSION.test(value)) {
    throw new BrokerError("PRIVATE_SERVICE_VERSION_UNAVAILABLE", 503, false);
  }
  return value;
}

export function requireWormServiceIdentity(env: WormMirrorEnv): string {
  const accountId = exactEnvironment(env.CF_ACCOUNT_ID, /^[0-9a-f]{32}$/u, 32);
  const serviceName = exactEnvironment(env.SERVICE_NAME, SERVICE, 128);
  if (serviceName !== "dpone-release-worm-mirror") {
    throw new BrokerError("PRIVATE_SERVICE_IDENTITY_UNAVAILABLE", 503, false);
  }
  return `cloudflare-worker:${accountId}/${serviceName}@${requireVersionId(env)}`;
}

function secret(value: string | undefined): string {
  if (value === undefined || value.length < 16 || value.length > 256) {
    throw new BrokerError("B2_SECRET_UNAVAILABLE", 503, false);
  }
  return value;
}

function required(value: string | undefined): string {
  if (value === undefined || value.length < 1 || value.length > 128) {
    throw new BrokerError("B2_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function exactEnvironment(value: string | undefined, pattern: RegExp, maximum: number): string {
  pattern.lastIndex = 0;
  const match = value === undefined ? null : pattern.exec(value);
  if (value === undefined || value.length > maximum || match?.[0] !== value) {
    throw new BrokerError("PRIVATE_SERVICE_IDENTITY_UNAVAILABLE", 503, false);
  }
  return value;
}

export function canonicalResponse(value: JsonObject): Response {
  return new Response(canonicalJson(value), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
    status: 200,
  });
}

export function decodeCanonicalEnvelope(bytes: Uint8Array): JsonObject {
  let decoded: unknown;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("MIRROR_BODY_INVALID", 400, false);
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new BrokerError("MIRROR_BODY_INVALID", 400, false);
  }
  const envelope = decoded as JsonObject;
  if (text !== canonicalJson(envelope)) {
    throw new BrokerError("MIRROR_BODY_NONCANONICAL", 400, false);
  }
  return envelope;
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  if (requireInteger(object, key, expected, expected) !== expected) {
    throw new BrokerError("MIRROR_BODY_INVALID", 400, false);
  }
}
