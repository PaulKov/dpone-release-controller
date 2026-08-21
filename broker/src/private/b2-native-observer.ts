import type { B2ObservedVersion, B2VersionInventory, B2VersionObserver } from "../b2";
import { inventoryDigestPayload } from "../b2";
import { INTERNAL_RESPONSE_READ_POLICY, readBoundedBytes } from "../bounded";
import { canonicalBytes, sha256Hex } from "../canonical";
import { LIMITS } from "../config";
import { BrokerError } from "../errors";
import { digestDomain } from "../identity";
import type { JsonObject } from "../types";
import {
  PROVIDER_JSON_LIMIT,
  type B2NativeConfig,
  type B2Session,
  type ProviderFetch,
  arrayField,
  authorizedPost,
  authorizedValue,
  booleanField,
  integerField,
  objectField,
  patternString,
  providerJson,
  providerJsonCapture,
  providerObject,
  requireExactSseB2,
  requireLiteral,
  requireLiteralHeader,
  requireProviderOk,
  safeFetch,
  sha1Hex,
  stringField,
  validateObjectKey,
} from "./b2-native-provider";
import { B2SessionProvider } from "./b2-native-session";

const VERSION_LIMIT = 16;
const OBSERVER_CAPABILITIES = [
  "listBuckets",
  "listFiles",
  "readBucketEncryption",
  "readBucketReplications",
  "readBucketRetentions",
  "readFileRetentions",
  "readFiles",
] as const;

export class B2NativeVersionObserver implements B2VersionObserver {
  private readonly sessions: B2SessionProvider;

  public constructor(
    private readonly config: B2NativeConfig,
    private readonly providerFetch: ProviderFetch = fetch,
  ) {
    this.sessions = new B2SessionProvider(config, OBSERVER_CAPABILITIES, providerFetch);
  }

  public async inspectExactKey(key: string): Promise<B2VersionInventory> {
    validateObjectKey(key, this.config.prefix);
    const session = await this.sessions.authorize();
    const bucket = (await this.inspectBucketEvidence(session)).bucket;
    const rawVersions = await this.listExactVersions(session, key);
    const observed = await Promise.all(
      rawVersions.map((version, index) => this.inspectVersion(session, key, version, index === 0)),
    );
    const versions = [...observed].sort((left, right) =>
      left.versionId < right.versionId ? -1 : left.versionId > right.versionId ? 1 : 0,
    );
    const unsigned: B2VersionInventory = {
      bucket,
      digest: "sha256:" + "0".repeat(64),
      key,
      versions,
    };
    return {
      ...unsigned,
      digest: `sha256:${await sha256Hex(canonicalBytes(inventoryDigestPayload(unsigned)))}`,
    };
  }

  /** Closed A0 projection of observer key scope plus live bucket configuration. */
  public async observeConfiguration(): Promise<JsonObject> {
    const session = await this.sessions.authorize();
    const observed = await this.inspectBucketEvidence(session);
    return {
      authorization: session.authorizationEvidence,
      bucket: {
        default_retention_days: observed.bucket.defaultRetentionDays,
        encryption: observed.bucket.encryption,
        object_lock_enabled: observed.bucket.objectLockEnabled,
        projection_sha256: observed.projectionSha256,
        raw_provider_response_retained: false,
        type: observed.bucket.type,
      },
    };
  }

  private async inspectBucketEvidence(session: B2Session): Promise<{
    readonly bucket: B2VersionInventory["bucket"];
    readonly projectionSha256: string;
  }> {
    const response = await authorizedPost(this.providerFetch, session, "b2_list_buckets", {
      accountId: session.accountId,
      bucketId: this.config.bucketId,
    });
    const captured = await providerJsonCapture(response, 32_768, "B2_BUCKET_RESPONSE_INVALID");
    const result = captured.value;
    const buckets = arrayField(result, "buckets", "B2_BUCKET_RESPONSE_INVALID");
    if (buckets.length !== 1) {
      throw new BrokerError("B2_BUCKET_RESPONSE_INVALID", 503, false);
    }
    const bucket = providerObject(buckets[0], "B2_BUCKET_RESPONSE_INVALID");
    requireLiteral(bucket, "accountId", session.accountId, "B2_BUCKET_RESPONSE_INVALID");
    requireLiteral(bucket, "bucketId", this.config.bucketId, "B2_BUCKET_RESPONSE_INVALID");
    requireLiteral(bucket, "bucketName", this.config.bucketName, "B2_BUCKET_RESPONSE_INVALID");
    requireLiteral(bucket, "bucketType", "allPrivate", "B2_BUCKET_CONFIGURATION_INVALID");
    if (arrayField(bucket, "lifecycleRules", "B2_BUCKET_RESPONSE_INVALID").length !== 0) {
      throw new BrokerError("B2_BUCKET_CONFIGURATION_INVALID", 503, false);
    }
    const replication = authorizedValue(
      bucket,
      "replicationConfiguration",
      "B2_BUCKET_RESPONSE_INVALID",
    );
    if (replication.asReplicationDestination !== null || replication.asReplicationSource !== null) {
      throw new BrokerError("B2_BUCKET_CONFIGURATION_INVALID", 503, false);
    }
    const lock = authorizedValue(bucket, "fileLockConfiguration", "B2_BUCKET_RESPONSE_INVALID");
    if (!booleanField(lock, "isFileLockEnabled")) {
      throw new BrokerError("B2_BUCKET_CONFIGURATION_INVALID", 503, false);
    }
    const retention = objectField(lock, "defaultRetention", "B2_BUCKET_RESPONSE_INVALID");
    requireLiteral(retention, "mode", "compliance", "B2_BUCKET_CONFIGURATION_INVALID");
    const period = objectField(retention, "period", "B2_BUCKET_RESPONSE_INVALID");
    if (integerField(period, "duration") !== 2557 || stringField(period, "unit", 16) !== "days") {
      throw new BrokerError("B2_BUCKET_CONFIGURATION_INVALID", 503, false);
    }
    const encryption = authorizedValue(
      bucket,
      "defaultServerSideEncryption",
      "B2_BUCKET_RESPONSE_INVALID",
    );
    requireLiteral(encryption, "mode", "SSE-B2", "B2_BUCKET_CONFIGURATION_INVALID");
    requireLiteral(encryption, "algorithm", "AES256", "B2_BUCKET_CONFIGURATION_INVALID");
    const normalizedBucket: B2VersionInventory["bucket"] = {
      defaultRetentionDays: 2557,
      encryption: "SSE-B2",
      objectLockEnabled: true,
      type: "allPrivate",
    };
    return {
      bucket: normalizedBucket,
      projectionSha256: await digestDomain("dpone.release-b2-bucket-configuration-observation.v1", {
        account_id: session.accountId,
        bucket_id: this.config.bucketId,
        bucket_name: this.config.bucketName,
        default_retention_days: normalizedBucket.defaultRetentionDays,
        encryption: normalizedBucket.encryption,
        lifecycle_rules: [],
        object_lock_enabled: normalizedBucket.objectLockEnabled,
        replication_configuration: {
          as_replication_destination: null,
          as_replication_source: null,
        },
        type: normalizedBucket.type,
      }),
    };
  }

  private async listExactVersions(session: B2Session, key: string): Promise<JsonObject[]> {
    const response = await authorizedPost(this.providerFetch, session, "b2_list_file_versions", {
      bucketId: this.config.bucketId,
      maxFileCount: VERSION_LIMIT + 1,
      prefix: key,
      startFileName: key,
    });
    const result = await providerJson(response, PROVIDER_JSON_LIMIT, "B2_LIST_RESPONSE_INVALID");
    const files = arrayField(result, "files", "B2_LIST_RESPONSE_INVALID").map((value) =>
      providerObject(value, "B2_LIST_RESPONSE_INVALID"),
    );
    if (
      files.length > VERSION_LIMIT ||
      result.nextFileName !== null ||
      result.nextFileId !== null ||
      files.some(
        (file) =>
          stringField(file, "accountId", 64) !== session.accountId ||
          stringField(file, "bucketId", 64) !== this.config.bucketId ||
          stringField(file, "fileName", 1024) !== key,
      )
    ) {
      throw new BrokerError("B2_VERSION_INVENTORY_INVALID", 503, false);
    }
    return files;
  }

  private async inspectVersion(
    session: B2Session,
    key: string,
    listed: JsonObject,
    isLatest: boolean,
  ): Promise<B2ObservedVersion> {
    const action = stringField(listed, "action", 32);
    const versionId = stringField(listed, "fileId", 512);
    if (action === "hide") {
      return {
        contentSha1: null,
        deleteMarker: true,
        digest: null,
        isLatest,
        retentionMode: null,
        retentionUntil: null,
        size: 0,
        versionId,
      };
    }
    if (action !== "upload") {
      throw new BrokerError("B2_VERSION_INVENTORY_INVALID", 503, false);
    }
    const response = await authorizedPost(this.providerFetch, session, "b2_get_file_info", {
      fileId: versionId,
    });
    const info = await providerJson(response, 32_768, "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "accountId", session.accountId, "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "bucketId", this.config.bucketId, "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "fileId", versionId, "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "fileName", key, "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "action", "upload", "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(info, "contentType", "application/json", "B2_FILE_INFO_RESPONSE_INVALID");
    const size = integerField(info, "contentLength");
    if (size < 1 || size > LIMITS.bodyBytes) {
      throw new BrokerError("B2_FILE_INFO_RESPONSE_INVALID", 503, false);
    }
    const contentSha1 = patternString(info, "contentSha1", /^[0-9a-f]{40}$/u, 40);
    const fileInfo = objectField(info, "fileInfo", "B2_FILE_INFO_RESPONSE_INVALID");
    const digest = patternString(fileInfo, "dpone-sha256", /^sha256:[0-9a-f]{64}$/u, 71);
    requireExactSseB2(info, "B2_FILE_ENCRYPTION_INVALID");
    const retention = authorizedValue(info, "fileRetention", "B2_FILE_INFO_RESPONSE_INVALID");
    requireLiteral(retention, "mode", "compliance", "B2_FILE_RETENTION_INVALID");
    const retainUntilTimestamp = integerField(retention, "retainUntilTimestamp");
    const uploadTimestamp = integerField(info, "uploadTimestamp");
    const retentionUntil = new Date(retainUntilTimestamp).toISOString();
    const bytes = await this.downloadVersion(session, {
      contentSha1,
      digest,
      expectedSize: size,
      key,
      retainUntilTimestamp,
      uploadTimestamp,
      versionId,
    });
    if ((await sha1Hex(bytes)) !== contentSha1 || `sha256:${await sha256Hex(bytes)}` !== digest) {
      throw new BrokerError("B2_VERSION_BODY_DIGEST_MISMATCH", 503, false);
    }
    return {
      contentSha1,
      deleteMarker: false,
      digest,
      isLatest,
      retentionMode: "COMPLIANCE",
      retentionUntil,
      size,
      versionId,
    };
  }

  private async downloadVersion(
    session: B2Session,
    expected: {
      readonly contentSha1: string;
      readonly digest: string;
      readonly expectedSize: number;
      readonly key: string;
      readonly retainUntilTimestamp: number;
      readonly uploadTimestamp: number;
      readonly versionId: string;
    },
  ): Promise<Uint8Array> {
    const url = new URL("/b2api/v4/b2_download_file_by_id", session.downloadUrl);
    url.searchParams.set("fileId", expected.versionId);
    const response = await safeFetch(
      this.providerFetch,
      url,
      {
        headers: { authorization: session.authorizationToken },
        method: "GET",
        redirect: "error",
      },
      "B2_DOWNLOAD_UNAVAILABLE",
    );
    await requireProviderOk(response, "B2_DOWNLOAD_FAILED");
    try {
      requireLiteralHeader(response.headers, "content-length", String(expected.expectedSize));
      requireLiteralHeader(response.headers, "content-type", "application/json");
      requireLiteralHeader(response.headers, "x-bz-content-sha1", expected.contentSha1);
      requireLiteralHeader(response.headers, "x-bz-file-id", expected.versionId);
      requireLiteralHeader(response.headers, "x-bz-file-name", encodeURIComponent(expected.key));
      requireLiteralHeader(response.headers, "x-bz-file-retention-mode", "compliance");
      requireLiteralHeader(
        response.headers,
        "x-bz-file-retention-retain-until-timestamp",
        String(expected.retainUntilTimestamp),
      );
      requireLiteralHeader(
        response.headers,
        "x-bz-info-dpone-sha256",
        encodeURIComponent(expected.digest),
      );
      requireLiteralHeader(response.headers, "x-bz-server-side-encryption", "AES256");
      requireLiteralHeader(
        response.headers,
        "x-bz-upload-timestamp",
        String(expected.uploadTimestamp),
      );
      for (const forbidden of [
        "content-encoding",
        "content-range",
        "location",
        "set-cookie",
        "transfer-encoding",
      ]) {
        if (response.headers.has(forbidden)) {
          throw new BrokerError("B2_DOWNLOAD_HEADERS_INVALID", 503, false);
        }
      }
    } catch (error) {
      await response.body?.cancel("B2_DOWNLOAD_HEADERS_INVALID").catch(() => undefined);
      throw error;
    }
    const bytes = await readBoundedBytes(
      response,
      LIMITS.bodyBytes,
      "B2_DOWNLOAD_TOO_LARGE",
      INTERNAL_RESPONSE_READ_POLICY,
    );
    if (bytes.byteLength !== expected.expectedSize) {
      throw new BrokerError("B2_DOWNLOAD_SIZE_MISMATCH", 503, false);
    }
    return bytes;
  }
}
