import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CLOUDFLARE_UUID } from "./cloudflare-ids.mjs";

export const PROJECT_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
export const WRANGLER = fileURLToPath(
  new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
);
export const BOOTSTRAP_PRIVATE_SOURCE = resolve(PROJECT_ROOT, "src/bootstrap-private.ts");
export const BOOTSTRAP_WORM_SOURCE = resolve(PROJECT_ROOT, "src/bootstrap-worm.ts");
export const BOOTSTRAP_INGRESS_SOURCE = resolve(PROJECT_ROOT, "src/bootstrap-ingress.ts");
export const FINAL_INGRESS_SOURCE = resolve(PROJECT_ROOT, "src/index.ts");
export const FINAL_WORM_SOURCE = resolve(PROJECT_ROOT, "src/private/worm-mirror-worker.ts");
export const PRIVATE_CONFIGS = Object.freeze([
  "wrangler.attestation-mutator.live.jsonc",
  "wrangler.candidate-reader.live.jsonc",
  "wrangler.closed-projector.live.jsonc",
  "wrangler.cloudflare-deployment-observer.live.jsonc",
  "wrangler.controller-run-reader.live.jsonc",
  "wrangler.governance-reader.live.jsonc",
  "wrangler.pypi-deployment-gate.live.jsonc",
  "wrangler.pypi-reader.live.jsonc",
  "wrangler.release-mutator.live.jsonc",
  "wrangler.runtime-deployment-gate.live.jsonc",
  "wrangler.tenant-scanner.live.jsonc",
  "wrangler.worm-mirror.live.jsonc",
  "wrangler.worm-version-observer.live.jsonc",
]);
export const INGRESS_CONFIG = "wrangler.live.jsonc";
export const VERSION_ID = CLOUDFLARE_UUID;
export const EXPECTED_DURABLE_EXPORTS = Object.freeze([
  "ActivationRegistry",
  "AuthReplayLedger",
  "GlobalActivatedAuthorityHead",
  "ReleaseLedger",
]);
export const EXPECTED_WORM_DURABLE_EXPORTS = Object.freeze([
  "CloudflareEvidenceBatch",
  "WormExactObjectEffect",
]);
export const MAX_PROVIDER_BYTES = 1_048_576;
export const MAX_SMOKE_BYTES = 65_536;

export function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
