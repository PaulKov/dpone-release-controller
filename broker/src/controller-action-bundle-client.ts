import { POSITIVE_ID, SAFE_NAME, SHA1 } from "./activation-contract";
import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "./bounded";
import { canonicalBytes, canonicalJson, digestObject } from "./canonical";
import {
  controllerActionBundleSha256,
  parseControllerActionBundle,
} from "./controller-action-bundle";
import { TRUST } from "./config";
import { assert, BrokerError } from "./errors";
import {
  CONTROLLER_ACTION_BUNDLE_OBSERVATION_REQUEST_SCHEMA,
  CONTROLLER_ACTION_BUNDLE_OBSERVATION_SCHEMA,
} from "./private/controller-action-bundle-reader";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { GitHubAppPin, JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RESPONSE_MAX_BYTES = 16_384;
const OBSERVATION_FIELDS = [
  "app_id",
  "app_slug",
  "commit_tree_sha",
  "controller_action_bundle",
  "controller_action_bundle_sha256",
  "installation_id",
  "provider_api_version",
  "provider_observation_sha256",
  "provider_tree_walk_sha256",
  "repository",
  "repository_id",
  "request_id",
  "schema",
  "schema_version",
  "worker_version_id",
] as const;

export interface ControllerActionBundleObservation {
  readonly bundle: JsonObject;
  readonly bundleSha256: string;
  readonly observation: JsonObject;
  readonly observationSha256: string;
}

/** Closed ingress client for the independently recomputing Commit-A reader. */
export class ControllerActionBundleClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
    private readonly app: GitHubAppPin,
  ) {}

  public async observe(
    commitSha: string,
    requestId: string,
  ): Promise<ControllerActionBundleObservation> {
    const bytes = buildControllerActionBundleObservationRequest(commitSha, requestId, this.app);
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(bytes).buffer,
      headers: {
        "content-length": String(bytes.byteLength),
        "content-type": "application/json",
        "x-request-id": requestId,
      },
      method: "POST",
      path: "/rpc/v1/a0/controller-action-bundle",
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new BrokerError(
        "CONTROLLER_ACTION_OBSERVATION_FAILED",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    const responseBytes = await readBoundedBytes(
      response,
      RESPONSE_MAX_BYTES,
      "CONTROLLER_ACTION_OBSERVATION_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    let text: string;
    let decoded: unknown;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
      decoded = JSON.parse(text);
    } catch {
      throw new BrokerError("CONTROLLER_ACTION_OBSERVATION_INVALID", 503, false);
    }
    const observation = exactObject(decoded, OBSERVATION_FIELDS);
    assert(text === canonicalJson(observation), "CONTROLLER_ACTION_OBSERVATION_NONCANONICAL", 503);
    return parseControllerActionBundleObservation(observation, {
      app: this.app,
      commitSha,
      pin: this.pin,
      requestId,
    });
  }
}

/** Build the exact request bytes that must be journaled before provider I/O. */
export function buildControllerActionBundleObservationRequest(
  commitSha: string,
  requestId: string,
  app: GitHubAppPin,
): Uint8Array {
  assert(SHA1.test(commitSha), "CONTROLLER_ACTION_COMMIT_INVALID", 500);
  return canonicalBytes({
    app_id: app.appId,
    app_slug: app.appSlug,
    controller_action_commit_sha: commitSha,
    installation_id: app.installationId,
    repository_id: TRUST.controllerRepositoryId,
    request_id: requestId,
    schema: CONTROLLER_ACTION_BUNDLE_OBSERVATION_REQUEST_SCHEMA,
    schema_version: 1,
  });
}

/** Re-validate one frozen canonical provider response without performing I/O. */
export async function parseControllerActionBundleObservation(
  value: unknown,
  expected: {
    readonly app: GitHubAppPin;
    readonly commitSha: string;
    readonly pin: PrivateServicePin;
    readonly requestId: string;
  },
): Promise<ControllerActionBundleObservation> {
  const observation = exactObject(value, OBSERVATION_FIELDS);
  requireLiteral(observation, "schema", CONTROLLER_ACTION_BUNDLE_OBSERVATION_SCHEMA);
  requireExactInteger(observation, "schema_version", 1);
  requireLiteral(observation, "repository", TRUST.controllerRepository);
  requireExactInteger(observation, "repository_id", TRUST.controllerRepositoryId);
  requireLiteral(observation, "request_id", expected.requestId);
  requireLiteral(observation, "provider_api_version", "2026-03-10");
  requireLiteral(observation, "app_id", expected.app.appId);
  requireLiteral(observation, "app_slug", expected.app.appSlug);
  requireLiteral(observation, "installation_id", expected.app.installationId);
  requireString(observation, "commit_tree_sha", 40, SHA1);
  requireString(observation, "provider_tree_walk_sha256", 71, DIGEST);
  assertPinnedServiceVersion(requireString(observation, "worker_version_id", 128), expected.pin);
  const bundle = parseControllerActionBundle(
    observation.controller_action_bundle,
    expected.commitSha,
  );
  const bundleSha256 = requireString(observation, "controller_action_bundle_sha256", 71, DIGEST);
  assert(
    bundleSha256 === (await controllerActionBundleSha256(bundle)),
    "CONTROLLER_ACTION_BUNDLE_DIGEST_MISMATCH",
    503,
  );
  const observationSha256 = requireString(observation, "provider_observation_sha256", 71, DIGEST);
  const unsigned = { ...observation };
  delete unsigned.provider_observation_sha256;
  assert(
    observationSha256 === (await digestObject(unsigned)),
    "CONTROLLER_ACTION_OBSERVATION_DIGEST_MISMATCH",
    503,
  );
  return { bundle, bundleSha256, observation, observationSha256 };
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "CONTROLLER_ACTION_OBSERVATION_MISMATCH",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "CONTROLLER_ACTION_OBSERVATION_MISMATCH",
    503,
  );
}

export function controllerActionBundleAppPin(controllerRunReaderApp: JsonObject): GitHubAppPin {
  return {
    appId: requireString(controllerRunReaderApp, "app_id", 32, POSITIVE_ID),
    appSlug: requireString(controllerRunReaderApp, "app_slug", 128, SAFE_NAME),
    installationId: requireString(controllerRunReaderApp, "installation_id", 32, POSITIVE_ID),
  };
}
