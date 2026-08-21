import { canonicalJson } from "../canonical";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { assertAllowedB2ExactKey } from "../b2-key";
import { BrokerError, errorResponse } from "../errors";
import type { JsonObject } from "../types";
import { exactObject, parseJsonObject, requireInteger, requireString } from "../validation";
import { B2NativeVersionObserver, type B2NativeConfig } from "./b2-native";

interface WormObserverEnv {
  readonly B2_APPLICATION_KEY?: string;
  readonly B2_BUCKET_ID?: string;
  readonly B2_BUCKET_NAME?: string;
  readonly B2_KEY_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly OPERATING_MODE: string;
}

/** Private, route-less Service Binding Worker for exact B2 version inspection. */
export default {
  async fetch(request: Request, env: WormObserverEnv): Promise<Response> {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    try {
      const url = new URL(request.url);
      if (
        request.method !== "POST" ||
        url.pathname !== "/rpc/v1/object-versions" ||
        url.search !== ""
      ) {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      const config = requireConfig(env);
      const body = exactObject(await parseJsonObject(request), ["key", "schema", "schema_version"]);
      requireLiteral(body, "schema", "dpone.release-b2-version-inventory-request.v1");
      requireExactInteger(body, "schema_version", 1);
      const key = requireString(body, "key", 512);
      assertAllowedB2ExactKey(key);
      const inventory = await new B2NativeVersionObserver(config).inspectExactKey(key);
      return canonicalResponse({
        bucket: {
          default_retention_days: inventory.bucket.defaultRetentionDays,
          encryption: inventory.bucket.encryption,
          object_lock_enabled: inventory.bucket.objectLockEnabled,
          type: inventory.bucket.type,
        },
        digest: inventory.digest,
        key: inventory.key,
        schema: "dpone.release-b2-version-inventory.v1",
        schema_version: 1,
        versions: inventory.versions.map((version) => ({
          content_sha1: version.contentSha1,
          delete_marker: version.deleteMarker,
          digest: version.digest,
          is_latest: version.isLatest,
          retention_mode: version.retentionMode,
          retention_until: version.retentionUntil,
          size: version.size,
          version_id: version.versionId,
        })),
        worker_version_id: requireVersionId(env),
      });
    } catch (error) {
      return errorResponse(error, requestId);
    }
  },
} satisfies ExportedHandler<WormObserverEnv>;

function requireConfig(env: WormObserverEnv): B2NativeConfig {
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

function requireVersionId(env: WormObserverEnv): string {
  const value = env.CF_VERSION_METADATA?.id;
  if (value === undefined || !CLOUDFLARE_UUID.test(value)) {
    throw new BrokerError("PRIVATE_SERVICE_VERSION_UNAVAILABLE", 503, false);
  }
  return value;
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

function canonicalResponse(value: JsonObject): Response {
  return new Response(canonicalJson(value), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  if (requireString(object, key, expected.length) !== expected) {
    throw new BrokerError("PRIVATE_REQUEST_INVALID", 400, false);
  }
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  if (requireInteger(object, key, expected, expected) !== expected) {
    throw new BrokerError("PRIVATE_REQUEST_INVALID", 400, false);
  }
}
