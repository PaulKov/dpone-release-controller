import { expect } from "vitest";

import type { B2NativeConfig } from "../src/private/b2-native";

export const CONFIG: B2NativeConfig = {
  applicationKey: "application-key-0000000001",
  bucketId: "aabbccddeeff001122334455",
  bucketName: "dpone-release-receipts",
  keyId: "writerkey00000001",
  prefix: "receipts/v1/",
};
export const KEY =
  `receipts/v1/activation/00000000-0000-0000-0000-000000000001/` + `0-${"a".repeat(64)}.json`;
export const ACCOUNT_ID = "account-id-000000000001";
export const VERSION_ID = "4_z-version-id-0000000001";
export const UPLOAD_TIMESTAMP = Date.parse("2026-08-15T12:00:00Z");
export const RETENTION_UNTIL = Date.parse("2026-08-15T12:00:00Z") + 2557 * 86_400_000;

export interface FakeProvider {
  readonly fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  readonly operations: string[];
  readonly uploadHeaders: Headers;
}

export function writerProvider(
  bytes: Uint8Array,
  digest: string,
  contentSha1: string,
  capabilities: readonly string[] = ["writeFiles"],
  keyExpiration: number | null | "missing" = null,
  rootAuthorizationToken = true,
): FakeProvider {
  const operations: string[] = [];
  let uploadHeaders = new Headers();
  return {
    async fetch(input, init) {
      const url = requestUrl(input);
      if (url.pathname.endsWith("/b2_authorize_account")) {
        operations.push("authorize");
        return json(authorize(capabilities, undefined, keyExpiration, rootAuthorizationToken));
      }
      if (url.pathname.endsWith("/b2_get_upload_url")) {
        operations.push("b2_get_upload_url");
        return json({
          authorizationToken: "upload-token-00000001",
          bucketId: CONFIG.bucketId,
          uploadUrl:
            `https://pod-000-2006.backblaze.com/b2api/v4/b2_upload_file` +
            `?cvt=upload-capability-00000001&bucket=${CONFIG.bucketId}`,
        });
      }
      if (url.pathname === "/b2api/v4/b2_upload_file") {
        operations.push("upload");
        uploadHeaders = new Headers(init?.headers);
        expect(new Uint8Array(init?.body as ArrayBuffer)).toEqual(bytes);
        return json({
          accountId: ACCOUNT_ID,
          action: "upload",
          bucketId: CONFIG.bucketId,
          contentLength: bytes.byteLength,
          contentSha1,
          contentType: "application/json",
          fileId: VERSION_ID,
          fileInfo: { "dpone-sha256": digest },
          fileName: KEY,
          serverSideEncryption: { algorithm: "AES256", mode: "SSE-B2" },
        });
      }
      throw new Error(`unexpected provider URL: ${url.toString()}`);
    },
    operations,
    get uploadHeaders() {
      return uploadHeaders;
    },
  };
}

export interface ObserverOptions {
  readonly apiUrl?: string;
  readonly capabilities?: readonly string[];
  readonly downloadBytes?: Uint8Array;
  readonly extraBucket?: boolean;
  readonly hide?: boolean;
  readonly lockAuthorized?: boolean;
  readonly keyExpiration?: number | null | "missing";
  readonly rootAuthorizationToken?: boolean;
}

export function observerProvider(
  bytes: Uint8Array,
  digest: string,
  contentSha1: string,
  options: ObserverOptions = {},
): FakeProvider {
  const operations: string[] = [];
  const capabilities = options.capabilities ?? [
    "listBuckets",
    "listFiles",
    "readBucketEncryption",
    "readBucketReplications",
    "readBucketRetentions",
    "readFileRetentions",
    "readFiles",
  ];
  return {
    async fetch(input, init) {
      const url = requestUrl(input);
      if (url.pathname.endsWith("/b2_authorize_account")) {
        operations.push("authorize");
        return json(
          authorize(
            capabilities,
            options.apiUrl,
            options.keyExpiration ?? null,
            options.rootAuthorizationToken ?? true,
          ),
        );
      }
      if (url.pathname.endsWith("/b2_list_buckets")) {
        operations.push("b2_list_buckets");
        expect(JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer))).toEqual({
          accountId: "account-id-000000000001",
          bucketId: CONFIG.bucketId,
        });
        const bucket = {
          accountId: ACCOUNT_ID,
          bucketId: CONFIG.bucketId,
          bucketName: CONFIG.bucketName,
          bucketType: "allPrivate",
          defaultServerSideEncryption: authorized({ algorithm: "AES256", mode: "SSE-B2" }),
          fileLockConfiguration:
            options.lockAuthorized === false
              ? { isClientAuthorizedToRead: false, value: null }
              : authorized({
                  defaultRetention: {
                    mode: "compliance",
                    period: { duration: 2557, unit: "days" },
                  },
                  isFileLockEnabled: true,
                }),
          lifecycleRules: [],
          replicationConfiguration: authorized({
            asReplicationDestination: null,
            asReplicationSource: null,
          }),
        };
        return json({
          buckets: options.extraBucket === true ? [bucket, { ...bucket }] : [bucket],
        });
      }
      if (url.pathname.endsWith("/b2_list_file_versions")) {
        operations.push("b2_list_file_versions");
        return json({
          files: [
            {
              accountId: ACCOUNT_ID,
              action: options.hide === true ? "hide" : "upload",
              bucketId: CONFIG.bucketId,
              fileId: VERSION_ID,
              fileName: KEY,
            },
          ],
          nextFileId: null,
          nextFileName: null,
        });
      }
      if (url.pathname.endsWith("/b2_get_file_info")) {
        operations.push("b2_get_file_info");
        return json({
          accountId: ACCOUNT_ID,
          action: "upload",
          bucketId: CONFIG.bucketId,
          contentLength: bytes.byteLength,
          contentSha1,
          contentType: "application/json",
          fileId: VERSION_ID,
          fileInfo: { "dpone-sha256": digest },
          fileName: KEY,
          fileRetention: authorized({
            mode: "compliance",
            retainUntilTimestamp: RETENTION_UNTIL,
          }),
          serverSideEncryption: { algorithm: "AES256", mode: "SSE-B2" },
          uploadTimestamp: UPLOAD_TIMESTAMP,
        });
      }
      if (url.pathname.endsWith("/b2_download_file_by_id")) {
        operations.push("download");
        const downloadBytes = options.downloadBytes ?? bytes;
        return new Response(Uint8Array.from(downloadBytes).buffer, {
          headers: {
            "content-length": String(downloadBytes.byteLength),
            "content-type": "application/json",
            "x-bz-content-sha1": contentSha1,
            "x-bz-file-id": VERSION_ID,
            "x-bz-file-name": encodeURIComponent(KEY),
            "x-bz-file-retention-mode": "compliance",
            "x-bz-file-retention-retain-until-timestamp": String(RETENTION_UNTIL),
            "x-bz-info-dpone-sha256": encodeURIComponent(digest),
            "x-bz-server-side-encryption": "AES256",
            "x-bz-upload-timestamp": String(UPLOAD_TIMESTAMP),
          },
          status: 200,
        });
      }
      throw new Error(`unexpected provider URL: ${url.toString()}`);
    },
    operations,
    uploadHeaders: new Headers(),
  };
}

function authorize(
  capabilities: readonly string[],
  apiUrl?: string,
  keyExpiration: number | null | "missing" = null,
  rootAuthorizationToken = true,
): Record<string, unknown> {
  const response: Record<string, unknown> = {
    accountId: ACCOUNT_ID,
    apiInfo: {
      storageApi: {
        allowed: {
          buckets: [{ id: CONFIG.bucketId, name: CONFIG.bucketName }],
          capabilities,
          namePrefix: CONFIG.prefix,
        },
        apiUrl: apiUrl ?? "https://api000.backblazeb2.com",
        downloadUrl: "https://f000.backblazeb2.com",
      },
    },
  };
  if (rootAuthorizationToken) {
    response.authorizationToken = "account-token-00000001";
  } else {
    const apiInfo = response.apiInfo as Record<string, unknown>;
    const storageApi = apiInfo.storageApi as Record<string, unknown>;
    storageApi.authorizationToken = "account-token-00000001";
  }
  if (keyExpiration !== "missing") {
    response.applicationKeyExpirationTimestamp = keyExpiration;
  }
  return response;
}

function authorized(value: Record<string, unknown>): Record<string, unknown> {
  return { isClientAuthorizedToRead: true, value };
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

export async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}
