import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import {
  parseCloudflareDeploymentObservationRequest,
  type CloudflareDeploymentObservationRpcRequest,
} from "./cloudflare-deployment-observation";
import {
  cloudflareEvidenceBatchBindingV2,
  type CloudflareEvidenceBatchBindingV2,
} from "./cloudflare-evidence-batch-contract";
import { BrokerError } from "./errors";
import {
  validateCloudflareBatchPins,
  type ActivationCloudflareBatchPins,
} from "./activation-operation-pins";
import type { ActivationOperationSequence } from "./activation-operation-contract";
import { SERVICE_AUTHORITY_ROLES } from "./service-authority";
import type { JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export const ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_SCHEMA =
  "dpone.activation-operation-cloudflare-observation-request.v2";

const MAX_REQUEST_BYTES = 65_536;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const IDENTITY = /^cloudflare-worker:([0-9a-f]{32})\/[a-z0-9][a-z0-9-]{1,127}@[0-9a-f-]{36}$/u;

export interface ActivationOperationCloudflareExpectedIssuance {
  readonly ingressWorkerVersionId: string;
  readonly internalRequestId: string;
  readonly issuanceId: string;
  readonly issuedAt: string;
  readonly ordinal: number;
  readonly sequence: ActivationOperationSequence;
  readonly freshUntil: string;
}

export interface ActivationOperationCloudflareRequest {
  readonly binding: CloudflareEvidenceBatchBindingV2;
  readonly canonicalBytes: Uint8Array;
  readonly committedAt: string;
  readonly delegationSha256: string;
  readonly document: JsonObject;
  readonly freshUntil: string;
  readonly issuance: ActivationOperationCloudflareExpectedIssuance;
  readonly observerRequest: CloudflareDeploymentObservationRpcRequest;
  readonly observerRequestObject: JsonObject;
  readonly pins: ActivationCloudflareBatchPins;
}

/** Build and immediately reparse the only request that may authorize provider reads. */
export async function buildActivationOperationCloudflareRequest(input: {
  readonly committedAt: string;
  readonly issuance: ActivationOperationCloudflareExpectedIssuance;
  readonly observerRequest: JsonObject;
  readonly pins: ActivationCloudflareBatchPins;
}): Promise<Uint8Array> {
  const observerRequest = ownedJsonObject(input.observerRequest);
  const pins = pinsProjection(input.pins);
  const accountId = accountFromIdentity(input.pins.cloudflareObserverServiceIdentity);
  const parsedObserver = parseCloudflareDeploymentObservationRequest(observerRequest, accountId);
  const binding = await cloudflareEvidenceBatchBindingV2(
    input.issuance.issuanceId,
    input.issuance.ordinal,
    input.issuance.sequence,
    parsedObserver.expectationSha256,
    input.pins.cloudflareObserverWorkerVersionId,
    parsedObserver.phase,
  );
  const body: JsonObject = {
    batch_id: binding.batchId,
    committed_at: input.committedAt,
    fresh_until: input.issuance.freshUntil,
    issuance_id: input.issuance.issuanceId,
    issuance_ordinal: input.issuance.ordinal,
    issued_at: input.issuance.issuedAt,
    observer_request: observerRequest,
    pins,
    schema: ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_SCHEMA,
    schema_version: 2,
    sequence: input.issuance.sequence,
  };
  const bytes = boundedBytes(canonicalBytes(body));
  await parseActivationOperationCloudflareRequest(bytes, input.issuance);
  return bytes;
}

/** Parse exact canonical bytes and derive every batch identity/pin field from them. */
export async function parseActivationOperationCloudflareRequest(
  canonicalRequestBytes: Uint8Array,
  expected: ActivationOperationCloudflareExpectedIssuance,
): Promise<ActivationOperationCloudflareRequest> {
  const bytes = boundedBytes(canonicalRequestBytes);
  const body = exactObject(decodeCanonical(bytes), [
    "batch_id",
    "committed_at",
    "fresh_until",
    "issuance_id",
    "issuance_ordinal",
    "issued_at",
    "observer_request",
    "pins",
    "schema",
    "schema_version",
    "sequence",
  ]);
  if (
    body.schema !== ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_SCHEMA ||
    requireInteger(body, "schema_version", 2, 2) !== 2 ||
    requireString(body, "issuance_id", 71, DIGEST) !== expected.issuanceId ||
    requireInteger(body, "issuance_ordinal", 1, 1_000_000) !== expected.ordinal ||
    requireInteger(body, "sequence", 0, 1) !== expected.sequence
  ) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_BINDING_INVALID");
  }
  const pins = parsePins(body.pins);
  const accountId = accountFromIdentity(pins.cloudflareObserverServiceIdentity);
  const observerRequestObject = exactObject(body.observer_request, [
    "expected_deployments",
    "expectation_sha256",
    "expected_network_surface",
    "phase",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
    "service_authority_inventory",
  ]);
  const observerRequest = parseCloudflareDeploymentObservationRequest(
    observerRequestObject,
    accountId,
  );
  const expectedPhase = expected.sequence === 0 ? "A0_PRE" : "A1_PRECOMMIT";
  const committedAt = canonicalTimestamp(requireString(body, "committed_at", 24, TIMESTAMP));
  const issuedAt = canonicalTimestamp(requireString(body, "issued_at", 24, TIMESTAMP));
  const freshUntil = canonicalTimestamp(requireString(body, "fresh_until", 24, TIMESTAMP));
  const requestedAt = canonicalTimestamp(observerRequest.requestedAt);
  if (
    observerRequest.phase !== expectedPhase ||
    observerRequest.requestId !== expected.internalRequestId ||
    issuedAt !== expected.issuedAt ||
    freshUntil !== expected.freshUntil ||
    Date.parse(requestedAt) < Date.parse(issuedAt) ||
    Date.parse(issuedAt) > Date.parse(committedAt) ||
    Date.parse(committedAt) > Date.parse(freshUntil) ||
    Date.parse(requestedAt) > Date.parse(committedAt) ||
    Date.parse(committedAt) - Date.parse(requestedAt) > 60_000
  ) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_BINDING_INVALID");
  }
  assertInventoryPins(observerRequest, pins, expected.ingressWorkerVersionId);
  const binding = await cloudflareEvidenceBatchBindingV2(
    expected.issuanceId,
    expected.ordinal,
    expected.sequence,
    observerRequest.expectationSha256,
    pins.cloudflareObserverWorkerVersionId,
    observerRequest.phase,
  );
  if (body.batch_id !== binding.batchId) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_BINDING_INVALID");
  }
  return {
    binding,
    canonicalBytes: bytes,
    committedAt,
    delegationSha256: `sha256:${await sha256Hex(bytes)}`,
    document: body,
    freshUntil,
    issuance: expected,
    observerRequest,
    observerRequestObject,
    pins,
  };
}

/** Reparse a nested delegation when the operation store is not the caller. */
export async function parseEmbeddedActivationOperationCloudflareRequest(
  value: unknown,
): Promise<ActivationOperationCloudflareRequest> {
  const document = exactObject(value, [
    "batch_id",
    "committed_at",
    "fresh_until",
    "issuance_id",
    "issuance_ordinal",
    "issued_at",
    "observer_request",
    "pins",
    "schema",
    "schema_version",
    "sequence",
  ]);
  const issuanceId = requireString(document, "issuance_id", 71, DIGEST);
  const sequence = requireInteger(document, "sequence", 0, 1) as ActivationOperationSequence;
  const observer = exactObject(document.observer_request, [
    "expected_deployments",
    "expectation_sha256",
    "expected_network_surface",
    "phase",
    "request_id",
    "requested_at",
    "schema",
    "schema_version",
    "service_authority_inventory",
  ]);
  if (
    !Array.isArray(observer.service_authority_inventory) ||
    observer.service_authority_inventory.length !== SERVICE_AUTHORITY_ROLES.length
  ) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_BINDING_INVALID");
  }
  const ingress = observer.service_authority_inventory
    .map((entry) =>
      exactObject(entry, [
        "authority_role",
        "binding",
        "configuration_sha256",
        "service",
        "service_identity",
        "source_commit_sha",
        "source_sha256",
        "version_resource_projection_sha256",
        "worker_version_id",
      ]),
    )
    .find((row) => row.authority_role === "release_authority_ingress");
  if (ingress === undefined) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_PIN_INVALID");
  }
  return parseActivationOperationCloudflareRequest(canonicalBytes(document), {
    ingressWorkerVersionId: requireString(
      ingress,
      "worker_version_id",
      36,
      /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u,
    ),
    internalRequestId: `activation-${issuanceId.slice("sha256:".length)}`,
    issuanceId,
    issuedAt: requireString(document, "issued_at", 24, TIMESTAMP),
    ordinal: requireInteger(document, "issuance_ordinal", 1, 1_000_000),
    sequence,
    freshUntil: requireString(document, "fresh_until", 24, TIMESTAMP),
  });
}

function parsePins(value: unknown): ActivationCloudflareBatchPins {
  const pins = exactObject(value, ["b2_observer", "cloudflare_observer", "worm"]);
  const b2 = parsePin(pins.b2_observer);
  const cloudflare = parsePin(pins.cloudflare_observer);
  const worm = parsePin(pins.worm);
  const parsed = {
    b2ObserverServiceIdentity: b2.serviceIdentity,
    b2ObserverWorkerVersionId: b2.workerVersionId,
    cloudflareObserverServiceIdentity: cloudflare.serviceIdentity,
    cloudflareObserverWorkerVersionId: cloudflare.workerVersionId,
    wormServiceIdentity: worm.serviceIdentity,
    wormWorkerVersionId: worm.workerVersionId,
  };
  validateCloudflareBatchPins(parsed);
  return parsed;
}

function parsePin(value: unknown): {
  readonly serviceIdentity: string;
  readonly workerVersionId: string;
} {
  const pin = exactObject(value, ["service_identity", "worker_version_id"]);
  return {
    serviceIdentity: requireString(pin, "service_identity", 512, IDENTITY),
    workerVersionId: requireString(
      pin,
      "worker_version_id",
      36,
      /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u,
    ),
  };
}

function assertInventoryPins(
  request: CloudflareDeploymentObservationRpcRequest,
  pins: ActivationCloudflareBatchPins,
  ingressWorkerVersionId: string,
): void {
  const expected = [
    [
      "cloudflare_deployment_observer",
      pins.cloudflareObserverServiceIdentity,
      pins.cloudflareObserverWorkerVersionId,
    ],
    ["worm_mirror", pins.wormServiceIdentity, pins.wormWorkerVersionId],
    ["worm_version_observer", pins.b2ObserverServiceIdentity, pins.b2ObserverWorkerVersionId],
  ] as const;
  if (
    expected.some(([role, identity, version]) => {
      const row = request.inventory.find((candidate) => candidate.authority_role === role);
      return row?.service_identity !== identity || row.worker_version_id !== version;
    }) ||
    request.inventory.find((row) => row.authority_role === "release_authority_ingress")
      ?.worker_version_id !== ingressWorkerVersionId
  ) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_PIN_INVALID");
  }
}

function pinsProjection(pins: ActivationCloudflareBatchPins): JsonObject {
  validateCloudflareBatchPins(pins);
  return {
    b2_observer: pinProjection(pins.b2ObserverServiceIdentity, pins.b2ObserverWorkerVersionId),
    cloudflare_observer: pinProjection(
      pins.cloudflareObserverServiceIdentity,
      pins.cloudflareObserverWorkerVersionId,
    ),
    worm: pinProjection(pins.wormServiceIdentity, pins.wormWorkerVersionId),
  };
}

function pinProjection(serviceIdentity: string, workerVersionId: string): JsonObject {
  return { service_identity: serviceIdentity, worker_version_id: workerVersionId };
}

function accountFromIdentity(identity: string): string {
  const accountId = IDENTITY.exec(identity)?.[1];
  if (accountId === undefined) fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_PIN_INVALID");
  return accountId;
}

function ownedJsonObject(value: JsonObject): JsonObject {
  return decodeCanonical(boundedBytes(canonicalBytes(value)));
}

function decodeCanonical(bytes: Uint8Array): JsonObject {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    const object = parsed as JsonObject;
    if (canonicalJson(object) !== text) throw new Error();
    return object;
  } catch {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_INVALID");
  }
}

function boundedBytes(value: Uint8Array): Uint8Array {
  if (value.byteLength === 0 || value.byteLength > MAX_REQUEST_BYTES) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_SIZE_INVALID", 413);
  }
  return Uint8Array.from(value);
}

function canonicalTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail("ACTIVATION_OPERATION_CLOUDFLARE_REQUEST_TIME_INVALID");
  }
  return value;
}

function fail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
