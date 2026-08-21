import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { canonicalJson, digestObject, sha256Hex } from "../canonical";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { TRUST } from "../config";
import { BrokerError } from "../errors";
import { assertRetainableProviderEvidence } from "../provider-evidence";
import type { JsonObject } from "../types";
import { exactObject, requireInteger, requireString } from "../validation";
import type { InstallationTokenSource } from "./github-app";
import {
  githubRequest,
  type ProviderFetch,
  requireExactGitHubJsonResponse,
  requireGitHubOk,
  requireProviderLiteral,
} from "./github-provider";

const API_VERSION = "2026-03-10";
const BODY_LIMIT = 4_096;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const WORKER_VERSION = CLOUDFLARE_UUID;
const CF_ACCOUNT_ID = /^[0-9a-f]{32}$/u;
const SERVICE_NAME = /^[a-z0-9][a-z0-9-]{1,127}$/u;

export interface GitHubOidcEvidenceConfig {
  readonly cloudflareAccountId: string;
  readonly observerRole: "controller_run_reader" | "governance_reader";
  readonly repository: typeof TRUST.controllerRepository | typeof TRUST.targetRepository;
  readonly repositoryId: number;
  readonly serviceName: string;
  readonly workerVersionId: string;
}

export function parseGitHubOidcEvidenceRequest(value: unknown): string {
  const body = exactObject(value, ["evidence_kind", "request_id", "schema", "schema_version"]);
  if (
    requireString(body, "schema", 64) !== "dpone.release-broker-provider-evidence-request.v1" ||
    requireInteger(body, "schema_version", 1, 1) !== 1 ||
    requireString(body, "evidence_kind", 64) !== "github_oidc_subject_customization"
  ) {
    throw new BrokerError("A0_EVIDENCE_REQUEST_INVALID", 400, false);
  }
  return requireString(body, "request_id", 128, REQUEST_ID);
}

/**
 * Closed GitHub OIDC subject-customization observer used during A0 admission.
 *
 * The caller cannot choose a URL, repository, API version, or projection. Raw
 * provider bytes are retained for audit, while security semantics are derived
 * again from those bytes and fail closed on any unknown provider shape.
 */
export class GitHubOidcEvidenceReader {
  public constructor(
    private readonly config: GitHubOidcEvidenceConfig,
    private readonly tokens: InstallationTokenSource,
    private readonly providerFetch: ProviderFetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    validateConfig(config);
  }

  public async observe(requestId: string): Promise<JsonObject> {
    if (!REQUEST_ID.test(requestId)) {
      throw new BrokerError("A0_EVIDENCE_REQUEST_ID_INVALID", 400, false);
    }
    const path = `/repos/${this.config.repository}/actions/oidc/customization/sub` as const;
    const response = await githubRequest(this.providerFetch, {
      authorization: `Bearer ${await this.tokens.installationToken()}`,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, "A0_OIDC_PROVIDER_REQUEST_FAILED");
    await requireExactGitHubJsonResponse(response, 200, "A0_OIDC_PROVIDER_RESPONSE_INVALID");
    const raw = await readBoundedBytes(
      response,
      BODY_LIMIT,
      "A0_OIDC_PROVIDER_RESPONSE_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    const value = decodeProviderJson(raw);
    const projection = exactObject(value, [
      "sub_claim_prefix",
      "use_default",
      "use_immutable_subject",
    ]);
    requireProviderLiteral(projection, "use_default", true, "A0_OIDC_CONFIGURATION_INVALID");
    requireProviderLiteral(
      projection,
      "use_immutable_subject",
      true,
      "A0_OIDC_CONFIGURATION_INVALID",
    );
    requireProviderLiteral(
      projection,
      "sub_claim_prefix",
      immutableSubjectPrefix(this.config.repository, this.config.repositoryId),
      "A0_OIDC_CONFIGURATION_INVALID",
    );
    const normalizedProjection: JsonObject = {
      sub_claim_prefix: immutableSubjectPrefix(this.config.repository, this.config.repositoryId),
      use_default: true,
      use_immutable_subject: true,
    };
    const observedAt = canonicalTimestamp(this.now());
    const unsigned: JsonObject = {
      evidence_kind: "github_oidc_subject_customization",
      http_status: 200,
      method: "GET",
      observed_at: observedAt,
      observer_role: this.config.observerRole,
      observer_service_identity:
        `cloudflare-worker:${this.config.cloudflareAccountId}/${this.config.serviceName}@` +
        this.config.workerVersionId,
      observer_worker_version_id: this.config.workerVersionId,
      path,
      projection: normalizedProjection,
      projection_sha256: await digestObject(normalizedProjection),
      provider: "github",
      provider_api_version: API_VERSION,
      query: "",
      raw_response_base64url: encodeBase64url(raw),
      raw_response_sha256: `sha256:${await sha256Hex(raw)}`,
      repository: this.config.repository,
      repository_id: this.config.repositoryId,
      request_id: requestId,
      response_headers: { content_type: "application/json" },
      schema: "dpone.release-broker-provider-evidence-entry.v1",
      schema_version: 1,
    };
    const evidence = { ...unsigned, observation_sha256: await digestObject(unsigned) };
    await assertRetainableProviderEvidence(evidence, "github_oidc_subject_customization");
    return evidence;
  }
}

function immutableSubjectPrefix(repository: string, repositoryId: number): string {
  return `repo:PaulKov@74862786/${repository.split("/")[1]}@${repositoryId}`;
}

function decodeProviderJson(bytes: Uint8Array): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new BrokerError("A0_OIDC_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("A0_OIDC_PROVIDER_RESPONSE_INVALID", 503, false);
  }
  return value as JsonObject;
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function canonicalTimestamp(nowMs: number): string {
  if (!Number.isFinite(nowMs)) {
    throw new BrokerError("A0_EVIDENCE_CLOCK_INVALID", 500, false);
  }
  return new Date(Math.floor(nowMs / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function validateConfig(config: GitHubOidcEvidenceConfig): void {
  const expectedRepositoryId =
    config.repository === TRUST.controllerRepository
      ? TRUST.controllerRepositoryId
      : TRUST.targetRepositoryId;
  const expectedRole =
    config.repository === TRUST.controllerRepository
      ? "controller_run_reader"
      : "governance_reader";
  if (
    !CF_ACCOUNT_ID.test(config.cloudflareAccountId) ||
    !SERVICE_NAME.test(config.serviceName) ||
    !WORKER_VERSION.test(config.workerVersionId) ||
    config.repositoryId !== expectedRepositoryId ||
    config.observerRole !== expectedRole
  ) {
    throw new BrokerError("A0_OIDC_READER_CONFIGURATION_INVALID", 503, false);
  }
}

/** Canonical provider response bytes used by contract tests and offline review. */
export function oidcProviderFixtureBytes(value: JsonObject): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}
