import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CLOUDFLARE_UUID, CLOUDFLARE_UUID_SOURCE } from "./cloudflare-ids.mjs";

export const PROJECT_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
export const DRY_CONFIGS = new Map([
  ["ingress", "wrangler.jsonc"],
  ["observer", "wrangler.worm-version-observer.jsonc"],
  ["cloudflareObserver", "wrangler.cloudflare-deployment-observer.jsonc"],
  ["worm", "wrangler.worm-mirror.jsonc"],
]);
export const LIVE_CONFIGS = new Map([
  ["ingress", "wrangler.live.jsonc"],
  ["observer", "wrangler.worm-version-observer.live.jsonc"],
  ["cloudflareObserver", "wrangler.cloudflare-deployment-observer.live.jsonc"],
  ["worm", "wrangler.worm-mirror.live.jsonc"],
]);
export const SERVICE_NAMES = Object.freeze({
  cloudflareObserver: "dpone-release-cloudflare-deployment-observer",
  ingress: "dpone-release-authority-broker",
  observer: "dpone-release-worm-version-observer",
  worm: "dpone-release-worm-mirror",
});
export const ROLE_ORDER = Object.freeze(["ingress", "observer", "cloudflareObserver", "worm"]);
export const CAPABILITIES = Object.freeze({
  observer: Object.freeze([
    "listBuckets",
    "listFiles",
    "readBucketEncryption",
    "readBucketReplications",
    "readBucketRetentions",
    "readFileRetentions",
    "readFiles",
  ]),
  writer: Object.freeze(["writeFiles"]),
});
export const UPLOAD_VERSION = new RegExp(
  `Worker Version ID:\\s*(${CLOUDFLARE_UUID_SOURCE})(?:\\s|$)`,
  "gu",
);
export const VERSION = CLOUDFLARE_UUID;
export const ACCOUNT_ID = /^[0-9a-f]{32}$/u;
export const BUCKET_ID = /^[0-9a-f]{24}$/u;
export const BUCKET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$/u;
export const B2_SECRET_DOCUMENT =
  /^\{"application_key":"([A-Za-z0-9]{16,256})","key_id":"([A-Za-z0-9]{16,64})"\}\n$/u;
export const MAX_INPUT_BYTES = 1_048_576;
export const MAX_PROVIDER_BYTES = 1_048_576;
export const B2_PREFIX = "receipts/v1/";
