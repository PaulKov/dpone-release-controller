import { assert } from "./errors";

const EXACT_KEYS = Object.freeze([
  /^receipts\/v1\/[0-9]+\/v[0-9]+\.[0-9]+\.[0-9]+\/[0-9a-f]{64}\/[0-9]{12}-[0-9a-f]{64}\.json$/u,
  /^receipts\/v1\/activation\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[01]-[0-9a-f]{64}\.json$/u,
  /^receipts\/v1\/activation-evidence\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[a-z][a-z0-9_]{2,63}\/[0-9a-f]{64}\.json$/u,
  /^receipts\/v1\/activation-head\/generations\/[0-9]{20}-[0-9a-f]{64}\.json$/u,
  /^receipts\/v1\/cloudflare-observations\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/(?:cloudflare_network_surface|cloudflare_service_deployments)\/[0-9a-f]{64}\.json$/u,
  /^receipts\/v1\/cloudflare-observations-v2\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/[0-9a-f]{64}\/(?:cloudflare_network_surface|cloudflare_service_deployments)\/[0-9a-f]{64}\.json$/u,
]);

export function isAllowedB2ExactKey(key: string): boolean {
  return key.length <= 512 && EXACT_KEYS.some((pattern) => pattern.test(key));
}

export function assertAllowedB2ExactKey(key: string): void {
  assert(isAllowedB2ExactKey(key), "B2_OBSERVER_KEY_INVALID", 500);
}
