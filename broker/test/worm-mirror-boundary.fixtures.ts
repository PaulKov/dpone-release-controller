import { canonicalBytes, digestObject, sha256Hex } from "../src/canonical";
import { TRUST } from "../src/config";
import type { JsonObject, JsonValue, PrivateServicePin } from "../src/types";
import wormMirrorWorker from "../src/private/worm-mirror-worker";
import { signWormRpcRequest, type WormRpcCallerAuth } from "../src/worm-rpc-auth";
import rulesetProjectionFixture from "./fixtures/github-ruleset-projection-v1-golden.json";

export const WORM_VERSION = "00000000-0000-0000-0000-000000000001";
export const OBSERVER_VERSION = "00000000-0000-0000-0000-000000000002";
export const INGRESS_VERSION = "00000000-0000-0000-0000-000000000003";
export const PIN: PrivateServicePin = {
  serviceIdentity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/worm-mirror@${WORM_VERSION}`,
  serviceName: "worm-mirror",
  versionId: WORM_VERSION,
};
export const OBSERVER: PrivateServicePin = {
  serviceIdentity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/dpone-release-worm-version-observer@${OBSERVER_VERSION}`,
  serviceName: "dpone-release-worm-version-observer",
  versionId: OBSERVER_VERSION,
};
export const RPC_AUTH_KEY = "A".repeat(43);
export const CALLER: WormRpcCallerAuth = {
  key: RPC_AUTH_KEY,
  serviceIdentity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/authority-broker@${INGRESS_VERSION}`,
  versionId: INGRESS_VERSION,
};

export function calleeHeaders(): Headers {
  return new Headers({
    "x-dpone-callee-service": PIN.serviceName,
    "x-dpone-callee-service-identity": PIN.serviceIdentity,
    "x-dpone-callee-version": PIN.versionId,
  });
}

export function workerEnv(versionId: string) {
  return {
    CF_ACCOUNT_ID: "a".repeat(32),
    CF_VERSION_METADATA: { id: versionId, tag: "test", timestamp: "2026-08-15T12:00:00Z" },
    OPERATING_MODE: "live",
    SERVICE_NAME: PIN.serviceName,
    WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: OBSERVER.serviceIdentity,
    WORM_EXPECTED_CALLER_SERVICE_IDENTITY: CALLER.serviceIdentity,
    WORM_RPC_AUTH_KEY: RPC_AUTH_KEY,
  };
}

export async function fetchEvidenceWorker(
  evidence: JsonObject,
  evidenceKind:
    | "github_branch_ruleset"
    | "github_oidc_subject_customization" = "github_oidc_subject_customization",
): Promise<Response> {
  const bytes = canonicalBytes(evidence);
  const headers = new Headers({
    ...Object.fromEntries(calleeHeaders()),
    "content-length": String(bytes.byteLength),
    "content-type": "application/json",
    "x-dpone-canonical-sha256": `sha256:${await sha256Hex(bytes)}`,
    "x-dpone-committed-at": "2026-08-15T12:00:00Z",
    "x-dpone-evidence-kind": evidenceKind,
    "x-dpone-ingress-worker-version": CALLER.versionId,
    "x-dpone-observer-service": OBSERVER.serviceName,
    "x-dpone-observer-service-identity": OBSERVER.serviceIdentity,
    "x-dpone-observer-version": OBSERVER.versionId,
    "x-request-id": "request-worm-evidence-worker-0001",
  });
  await signWormRpcRequest(headers, "/rpc/v1/activation-evidence", CALLER);
  return wormMirrorWorker.fetch(
    new Request("https://worm-mirror.internal/rpc/v1/activation-evidence", {
      body: Uint8Array.from(bytes).buffer,
      headers,
      method: "POST",
    }),
    workerEnv(PIN.versionId),
  );
}

export async function retainableRulesetEvidence(): Promise<JsonObject> {
  const projection = rulesetProjectionFixture as JsonObject;
  const rawObject: JsonObject = {
    _links: {},
    bypass_actors: fixtureValue(projection, "bypass_actors"),
    conditions: { ref_name: fixtureValue(projection, "conditions") },
    created_at: "2026-07-11T14:17:56.651Z",
    enforcement: fixtureValue(projection, "enforcement"),
    id: fixtureValue(projection, "id"),
    name: fixtureValue(projection, "name"),
    node_id: "RRS_fixture",
    rules: fixtureValue(projection, "rules"),
    source: fixtureValue(projection, "source"),
    source_type: fixtureValue(projection, "source_type"),
    target: fixtureValue(projection, "target"),
    updated_at: "2026-07-19T18:37:47.596Z",
  };
  const raw = canonicalBytes(rawObject);
  const unsigned: JsonObject = {
    evidence_kind: "github_branch_ruleset",
    http_status: 200,
    method: "GET",
    observed_at: "2026-08-15T12:00:00Z",
    observer_role: "governance_reader",
    observer_service_identity:
      "cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/governance-reader@" + uuid(401),
    observer_worker_version_id: uuid(401),
    path: `/repos/${TRUST.targetRepository}/rulesets/18806829`,
    projection,
    projection_sha256: "sha256:e2f8ec4f9677839da2ccd1644d543d17c41446dc8305dd9529ca8c8f5484fe39",
    provider: "github",
    provider_api_version: "2026-03-10",
    query: "",
    raw_response_base64url: encodeBase64url(raw),
    raw_response_sha256: `sha256:${await sha256Hex(raw)}`,
    repository: TRUST.targetRepository,
    repository_id: TRUST.targetRepositoryId,
    request_id: "request-worm-ruleset-evidence-0001",
    response_headers: { content_type: "application/json" },
    schema: "dpone.release-broker-provider-evidence-entry.v1",
    schema_version: 1,
  };
  return { ...unsigned, observation_sha256: await digestObject(unsigned) };
}

function fixtureValue(projection: JsonObject, key: string): JsonValue {
  const value = projection[key];
  if (value === undefined) throw new Error(`missing fixture ${key}`);
  return structuredClone(value);
}

export function objectAt(value: unknown, index: number): JsonObject {
  if (!Array.isArray(value)) throw new Error("missing object fixture array");
  const item: unknown = value[index];
  if (item === null || typeof item !== "object" || Array.isArray(item)) {
    throw new Error("missing object fixture");
  }
  return item as JsonObject;
}

export function decodeBase64url(value: string): Uint8Array {
  const binary = atob(
    value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "="),
  );
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function retainableEvidence(rawExtra: JsonObject = {}): Promise<JsonObject> {
  const rawProjection: JsonObject = {
    sub_claim_prefix: "repo:PaulKov@74862786/dpone-release-controller@1305993853",
    use_default: true,
    use_immutable_subject: true,
    ...rawExtra,
  };
  const raw = canonicalBytes(rawProjection);
  const projection: JsonObject = {
    sub_claim_prefix: "repo:PaulKov@74862786/dpone-release-controller@1305993853",
    use_default: true,
    use_immutable_subject: true,
  };
  const unsigned: JsonObject = {
    evidence_kind: "github_oidc_subject_customization",
    http_status: 200,
    method: "GET",
    observed_at: "2026-08-15T12:00:00Z",
    observer_role: "controller_run_reader",
    observer_service_identity: `cloudflare-worker:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controller-reader@${uuid(402)}`,
    observer_worker_version_id: uuid(402),
    path: `/repos/${TRUST.controllerRepository}/actions/oidc/customization/sub`,
    projection,
    projection_sha256: await digestObject(projection),
    provider: "github",
    provider_api_version: "2026-03-10",
    query: "",
    raw_response_base64url: base64url(raw),
    raw_response_sha256: `sha256:${await sha256Hex(raw)}`,
    repository: TRUST.controllerRepository,
    repository_id: TRUST.controllerRepositoryId,
    request_id: "request-worm-evidence-0001",
    response_headers: { content_type: "application/json" },
    schema: "dpone.release-broker-provider-evidence-entry.v1",
    schema_version: 1,
  };
  return { ...unsigned, observation_sha256: await digestObject(unsigned) };
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function uuid(value: number): string {
  return `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`;
}
