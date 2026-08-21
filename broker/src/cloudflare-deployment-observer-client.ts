import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import {
  assertSanitizedCloudflareEvidenceRecord,
  assertCloudflareObservationMatchesInventory,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA,
} from "./cloudflare-deployment-observation";
import { assert, BrokerError } from "./errors";
import {
  parseExpectedServiceDeployments,
  parseExpectedCloudflareNetworkSurface,
  parseServiceAuthorityInventory,
  type DeploymentObservationPhase,
  type ExpectedServiceDeployment,
  type ExpectedCloudflareNetworkSurface,
  type ServiceAuthorityInventoryRow,
} from "./service-authority";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import { parseStrictJsonObject } from "./strict-json";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import { signCloudflareObserverRpcRequest, type WormRpcCallerAuth } from "./worm-rpc-auth";

const MAX_RESULT_BYTES = 1_048_576;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

export interface AcceptedCloudflareDeploymentObservation {
  readonly b2ObserverServiceIdentity: string;
  readonly brokerAcceptedAt: string;
  readonly networkSurfaceEvidenceEntry: JsonObject;
  readonly observation: JsonObject;
  readonly serviceEvidenceEntries: readonly JsonObject[];
  readonly wormServiceIdentity: string;
}

/** Pinned private-service client for the exact fourteen-row deployment read. */
export class CloudflareDeploymentObserverClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly cloudflareAccountId: string,
    private readonly callerAuth: WormRpcCallerAuth,
    private readonly now: () => number = Date.now,
  ) {}

  public async observe(input: {
    readonly expectedDeployments: readonly ExpectedServiceDeployment[];
    readonly expectationSha256: string;
    readonly expectedNetworkSurface: ExpectedCloudflareNetworkSurface;
    readonly inventory: readonly ServiceAuthorityInventoryRow[];
    readonly phase: DeploymentObservationPhase;
    readonly requestId: string;
  }): Promise<AcceptedCloudflareDeploymentObservation> {
    const requestedAtMs = this.now();
    assert(Number.isSafeInteger(requestedAtMs), "CLOUDFLARE_DEPLOYMENT_REQUEST_INVALID", 500);
    const inventory = parseServiceAuthorityInventory(input.inventory, this.cloudflareAccountId);
    const expectedDeployments = parseExpectedServiceDeployments(
      input.expectedDeployments,
      input.phase,
    );
    const expectedNetworkSurface = parseExpectedCloudflareNetworkSurface(
      input.expectedNetworkSurface,
    );
    assert(DIGEST.test(input.expectationSha256), "CLOUDFLARE_DEPLOYMENT_REQUEST_INVALID", 500);
    const body: JsonObject = {
      expected_deployments: expectedDeployments.map((deployment) => ({
        authority_role: deployment.authority_role,
        deployment_id: deployment.deployment_id,
        deployment_versions: deployment.deployment_versions.map((version) => ({ ...version })),
        service: deployment.service,
      })),
      expectation_sha256: input.expectationSha256,
      expected_network_surface: { ...expectedNetworkSurface },
      phase: input.phase,
      request_id: input.requestId,
      requested_at: new Date(requestedAtMs).toISOString(),
      schema: CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
      schema_version: 1,
      service_authority_inventory: inventory.map((row) => ({ ...row })),
    };
    const requestBytes = canonicalBytes(body);
    const headers = new Headers({
      "content-length": String(requestBytes.byteLength),
      "content-type": "application/json",
      "x-dpone-callee-service": this.pin.serviceName,
      "x-dpone-callee-service-identity": this.pin.serviceIdentity,
      "x-dpone-callee-version": this.pin.versionId,
      "x-dpone-canonical-sha256": `sha256:${await sha256Hex(requestBytes)}`,
      "x-dpone-ingress-worker-version": this.callerAuth.versionId,
      "x-request-id": input.requestId,
    });
    await signCloudflareObserverRpcRequest(headers, this.callerAuth);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(requestBytes).buffer,
      headers: Object.fromEntries(headers),
      method: "POST",
      path: CLOUDFLARE_DEPLOYMENT_OBSERVATION_RPC_PATH,
    });
    await requireExactPrivateResponse(response, input.requestId);
    const bytes = await readBoundedBytes(
      response,
      MAX_RESULT_BYTES,
      "CLOUDFLARE_DEPLOYMENT_RESULT_INVALID",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const result = exactObject(
      parseStrictJsonObject(bytes, "CLOUDFLARE_DEPLOYMENT_RESULT_INVALID"),
      [
        "b2_observer_service_identity",
        "network_surface_evidence_entry",
        "observation",
        "schema",
        "schema_version",
        "service_evidence_entries",
        "worm_service_identity",
      ],
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    assert(text === canonicalJson(result), "CLOUDFLARE_DEPLOYMENT_RESULT_NONCANONICAL", 503);
    requireLiteral(result, "schema", CLOUDFLARE_DEPLOYMENT_RESULT_SCHEMA);
    requireExactInteger(result, "schema_version", 1);
    const b2ObserverServiceIdentity = requireString(result, "b2_observer_service_identity", 512);
    const b2ObserverAuthority = inventory.find(
      (row) => row.authority_role === "worm_version_observer",
    );
    if (b2ObserverServiceIdentity !== b2ObserverAuthority?.service_identity) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_B2_OBSERVER_PIN_INVALID", 503, false);
    }
    const wormServiceIdentity = requireString(result, "worm_service_identity", 512);
    const wormAuthority = inventory.find((row) => row.authority_role === "worm_mirror");
    if (wormServiceIdentity !== wormAuthority?.service_identity) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_WORM_PIN_INVALID", 503, false);
    }
    const observation = requireObject(result.observation);
    requireLiteral(observation, "schema", CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA);
    if (!Array.isArray(result.service_evidence_entries)) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_SET_INVALID", 503, false);
    }
    const serviceEvidenceEntries = await Promise.all(
      result.service_evidence_entries.map((entry) =>
        parseServiceEvidenceEntry(entry, this.pin.versionId),
      ),
    );
    const networkSurfaceEvidenceEntry = requireObject(result.network_surface_evidence_entry);
    await parseNetworkEvidenceEntry(networkSurfaceEvidenceEntry, observation, this.pin.versionId);
    if (
      !Array.isArray(observation.services) ||
      observation.services.length !== serviceEvidenceEntries.length
    ) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_SET_INVALID", 503, false);
    }
    for (let index = 0; index < serviceEvidenceEntries.length; index += 1) {
      const entry = serviceEvidenceEntries[index];
      if (entry === undefined) {
        throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_SET_INVALID", 503, false);
      }
      const record = requireObject(entry.deployment_observation_record);
      const observedService = requireObject(observation.services[index]);
      if (
        record.provider_observation_sha256 !== observation.provider_observation_sha256 ||
        record.expectation_sha256 !== observation.expectation_sha256 ||
        record.observed_at !== observation.observed_at ||
        canonicalJson(record.service_observation) !== canonicalJson(observedService)
      ) {
        throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BINDING_INVALID", 503, false);
      }
    }
    if (
      observation.cloudflare_account_id !== this.cloudflareAccountId ||
      observation.expectation_sha256 !== input.expectationSha256 ||
      observation.phase !== input.phase ||
      observation.observer_service_identity !== this.pin.serviceIdentity ||
      observation.observer_worker_version_id !== this.pin.versionId
    ) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVER_BINDING_INVALID", 503, false);
    }
    assertPinnedServiceVersion(
      requireString(observation, "observer_worker_version_id", 128),
      this.pin,
    );
    const acceptedAtMs = this.now();
    const observedAtMs = Date.parse(requireString(observation, "observed_at", 32, TIMESTAMP));
    if (
      !Number.isSafeInteger(acceptedAtMs) ||
      !Number.isFinite(observedAtMs) ||
      observedAtMs > acceptedAtMs ||
      acceptedAtMs - observedAtMs > 60_000
    ) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVATION_STALE", 503, false);
    }
    assertCloudflareObservationMatchesInventory(
      observation,
      inventory,
      expectedDeployments,
      expectedNetworkSurface,
    );
    return {
      b2ObserverServiceIdentity,
      brokerAcceptedAt: new Date(acceptedAtMs).toISOString(),
      networkSurfaceEvidenceEntry,
      observation,
      serviceEvidenceEntries: Object.freeze(serviceEvidenceEntries),
      wormServiceIdentity,
    };
  }
}

async function parseServiceEvidenceEntry(
  value: unknown,
  observerVersionId: string,
): Promise<JsonObject> {
  const entry = exactObject(value, [
    "authority_role",
    "deployment_observation_record",
    "deployment_observation_record_id",
    "deployment_observation_record_sha256",
    "deployment_observation_sha256",
    "worm",
  ]);
  const sanitized = await assertSanitizedCloudflareEvidenceRecord(
    entry.deployment_observation_record,
  );
  if (
    entry.authority_role !== sanitized.record.authority_role ||
    entry.deployment_observation_record_id !== sanitized.recordId ||
    entry.deployment_observation_record_sha256 !== sanitized.recordSha256 ||
    entry.deployment_observation_sha256 !== sanitized.record.deployment_observation_sha256
  ) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_EVIDENCE_BINDING_INVALID", 503, false);
  }
  parseWormPointer(
    entry.worm,
    sanitized.recordId,
    sanitized.recordSha256,
    requireString(sanitized.record, "observed_at", 32, TIMESTAMP),
    "cloudflare_service_deployments",
    observerVersionId,
  );
  return entry;
}

async function parseNetworkEvidenceEntry(
  value: JsonObject,
  observation: JsonObject,
  observerVersionId: string,
): Promise<void> {
  const entry = exactObject(value, [
    "network_surface_observation_record",
    "network_surface_observation_record_id",
    "network_surface_observation_record_sha256",
    "network_surface_observation_sha256",
    "worm",
  ]);
  const sanitized = await assertSanitizedCloudflareEvidenceRecord(
    entry.network_surface_observation_record,
  );
  if (
    entry.network_surface_observation_record_id !== sanitized.recordId ||
    entry.network_surface_observation_record_sha256 !== sanitized.recordSha256 ||
    entry.network_surface_observation_sha256 !==
      sanitized.record.network_surface_observation_sha256 ||
    sanitized.record.provider_observation_sha256 !== observation.provider_observation_sha256 ||
    sanitized.record.expectation_sha256 !== observation.expectation_sha256 ||
    sanitized.record.observed_at !== observation.observed_at ||
    canonicalJson(sanitized.record.network_surface_observation) !==
      canonicalJson(observation.network_surface)
  ) {
    throw new BrokerError("CLOUDFLARE_NETWORK_EVIDENCE_BINDING_INVALID", 503, false);
  }
  parseWormPointer(
    entry.worm,
    sanitized.recordId,
    sanitized.recordSha256,
    requireString(sanitized.record, "observed_at", 32, TIMESTAMP),
    "cloudflare_network_surface",
    observerVersionId,
  );
}

function parseWormPointer(
  value: unknown,
  expectedRecordId: string,
  expectedDigest: string,
  observedAt: string,
  kind: "cloudflare_network_surface" | "cloudflare_service_deployments",
  observerVersionId: string,
): void {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  if (requireString(worm, "digest", 71, DIGEST) !== expectedDigest) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_BINDING_INVALID", 503, false);
  }
  const expectedKey =
    `receipts/v1/cloudflare-observations/${observerVersionId}/${kind}/` +
    `${expectedRecordId.slice("sha256:".length)}.json`;
  if (requireString(worm, "key", expectedKey.length) !== expectedKey) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_BINDING_INVALID", 503, false);
  }
  const retentionUntil = requireString(
    worm,
    "retention_until",
    32,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
  );
  if (
    new Date(Date.parse(retentionUntil)).toISOString() !== retentionUntil ||
    Date.parse(retentionUntil) < Date.parse(observedAt) + 2557 * 86_400_000
  ) {
    throw new BrokerError("CLOUDFLARE_EVIDENCE_WORM_BINDING_INVALID", 503, false);
  }
  requireString(worm, "version_id", 512, /^[A-Za-z0-9._=-]{1,512}$/u);
}

async function requireExactPrivateResponse(response: Response, requestId: string): Promise<void> {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    response.status !== 200 ||
    mediaType !== "application/json" ||
    response.headers.get("x-request-id") !== requestId ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel("CLOUDFLARE_DEPLOYMENT_RESULT_INVALID").catch(() => undefined);
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_RESULT_INVALID", 503, false);
  }
}

function requireObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("CLOUDFLARE_DEPLOYMENT_RESULT_INVALID", 503, false);
  }
  return value as JsonObject;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, expected.length) === expected,
    "CLOUDFLARE_CONTRACT_INVALID",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CLOUDFLARE_CONTRACT_INVALID",
    503,
  );
}
