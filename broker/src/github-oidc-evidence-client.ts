import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, digestObject, sha256Hex } from "./canonical";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const OBSERVATION_FIELDS = [
  "evidence_kind",
  "http_status",
  "method",
  "observed_at",
  "observation_sha256",
  "observer_role",
  "observer_service_identity",
  "observer_worker_version_id",
  "path",
  "projection",
  "projection_sha256",
  "provider",
  "provider_api_version",
  "query",
  "raw_response_base64url",
  "raw_response_sha256",
  "repository",
  "repository_id",
  "request_id",
  "response_headers",
  "schema",
  "schema_version",
] as const;

export interface GitHubOidcEvidenceExpectation {
  readonly observerRole: "controller_run_reader" | "governance_reader";
  readonly repository: typeof TRUST.controllerRepository | typeof TRUST.targetRepository;
  readonly repositoryId: number;
}

/** Version-pinned ingress client that independently verifies raw provider bytes. */
export class GitHubOidcEvidenceClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly expected: GitHubOidcEvidenceExpectation,
    private readonly now: () => number = Date.now,
  ) {
    validateExpectation(expected);
  }

  public async observe(requestId: string): Promise<JsonObject> {
    const bytes = buildGitHubOidcEvidenceRequest(requestId);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
        "x-request-id": requestId,
      },
      method: "POST",
      path: "/rpc/v1/a0/oidc-subject-customization",
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new BrokerError("A0_OIDC_EVIDENCE_SERVICE_FAILED", 503, response.status >= 500);
    }
    if (
      response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json" ||
      response.headers.get("x-request-id") !== requestId ||
      response.headers.has("content-encoding") ||
      response.headers.has("content-range") ||
      response.headers.has("location") ||
      response.headers.has("set-cookie") ||
      response.headers.has("transfer-encoding")
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new BrokerError("A0_OIDC_EVIDENCE_SERVICE_RESPONSE_INVALID", 503, false);
    }
    const responseBytes = await readBoundedBytes(
      response,
      16_384,
      "A0_OIDC_EVIDENCE_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
    let decoded: unknown;
    try {
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("A0_OIDC_EVIDENCE_INVALID", 503, false);
    }
    const observation = exactObject(decoded, OBSERVATION_FIELDS);
    assert(text === canonicalJson(observation), "A0_OIDC_EVIDENCE_NONCANONICAL", 503);
    await this.verifyObservation(observation, requestId);
    return observation;
  }

  private async verifyObservation(observation: JsonObject, requestId: string): Promise<void> {
    requireLiteral(observation, "schema", "dpone.release-broker-provider-evidence-entry.v1");
    requireExactInteger(observation, "schema_version", 1);
    requireLiteral(observation, "evidence_kind", "github_oidc_subject_customization");
    requireLiteral(observation, "provider", "github");
    requireLiteral(observation, "provider_api_version", "2026-03-10");
    requireLiteral(observation, "method", "GET");
    assert(observation.query === "", "A0_OIDC_EVIDENCE_MISMATCH", 503);
    requireLiteral(observation, "repository", this.expected.repository);
    requireExactInteger(observation, "repository_id", this.expected.repositoryId);
    requireLiteral(observation, "request_id", requestId);
    requireLiteral(observation, "observer_role", this.expected.observerRole);
    requireLiteral(observation, "observer_service_identity", this.pin.serviceIdentity);
    assertPinnedServiceVersion(
      requireString(observation, "observer_worker_version_id", 128),
      this.pin,
    );
    requireLiteral(
      observation,
      "path",
      `/repos/${this.expected.repository}/actions/oidc/customization/sub`,
    );
    requireExactInteger(observation, "http_status", 200);
    const headers = exactObject(observation.response_headers, ["content_type"]);
    requireLiteral(headers, "content_type", "application/json");
    const observedAt = requireString(
      observation,
      "observed_at",
      32,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u,
    );
    const observedMs = Date.parse(observedAt);
    const nowMs = this.now();
    assert(
      Number.isFinite(observedMs) && observedMs >= nowMs - 60_000 && observedMs <= nowMs + 30_000,
      "A0_OIDC_EVIDENCE_STALE",
      503,
    );

    const raw = decodeBase64url(requireString(observation, "raw_response_base64url", 8_192));
    requireLiteral(observation, "raw_response_sha256", `sha256:${await sha256Hex(raw)}`);
    const provider = decodeRawProvider(raw);
    const projection = exactObject(provider, [
      "sub_claim_prefix",
      "use_default",
      "use_immutable_subject",
    ]);
    assert(
      projection.use_default === true &&
        projection.use_immutable_subject === true &&
        projection.sub_claim_prefix === immutableSubjectPrefix(this.expected),
      "A0_OIDC_CONFIGURATION_INVALID",
      503,
    );
    const normalized = exactObject(observation.projection, [
      "sub_claim_prefix",
      "use_default",
      "use_immutable_subject",
    ]);
    assert(
      canonicalJson(normalized) === canonicalJson(projection),
      "A0_OIDC_PROJECTION_MISMATCH",
      503,
    );
    requireLiteral(observation, "projection_sha256", await digestObject(normalized));
    const unsigned = { ...observation };
    delete unsigned.observation_sha256;
    requireLiteral(observation, "observation_sha256", await digestObject(unsigned));
  }
}

/** Build the exact request bytes that must be journaled before provider I/O. */
export function buildGitHubOidcEvidenceRequest(requestId: string): Uint8Array {
  assert(/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u.test(requestId), "REQUEST_ID_INVALID", 500);
  return canonicalBytes({
    evidence_kind: "github_oidc_subject_customization",
    request_id: requestId,
    schema: "dpone.release-broker-provider-evidence-request.v1",
    schema_version: 1,
  });
}

function decodeRawProvider(bytes: Uint8Array): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError("A0_OIDC_RAW_RESPONSE_INVALID", 503, false);
  }
  return exactObject(value, ["sub_claim_prefix", "use_default", "use_immutable_subject"]);
}

function immutableSubjectPrefix(expected: GitHubOidcEvidenceExpectation): string {
  return `repo:PaulKov@74862786/${expected.repository.split("/")[1]}@${expected.repositoryId}`;
}

function decodeBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{2,8192}$/u.test(value) || value.length % 4 === 1) {
    throw new BrokerError("A0_EVIDENCE_BASE64URL_INVALID", 503, false);
  }
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new BrokerError("A0_EVIDENCE_BASE64URL_INVALID", 503, false);
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validateExpectation(expected: GitHubOidcEvidenceExpectation): void {
  const valid =
    (expected.repository === TRUST.controllerRepository &&
      expected.repositoryId === TRUST.controllerRepositoryId &&
      expected.observerRole === "controller_run_reader") ||
    (expected.repository === TRUST.targetRepository &&
      expected.repositoryId === TRUST.targetRepositoryId &&
      expected.observerRole === "governance_reader");
  assert(valid, "A0_OIDC_EXPECTATION_INVALID", 500);
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "A0_OIDC_EVIDENCE_MISMATCH",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "A0_OIDC_EVIDENCE_MISMATCH",
    503,
  );
}
