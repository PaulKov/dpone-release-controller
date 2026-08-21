import { BrokerError } from "./errors";

/**
 * Cloudflare Worker version and deployment identifiers are canonical lowercase
 * UUID-shaped values. Cloudflare does not promise an RFC version/variant, so
 * this validator deliberately checks only the provider's stable 8-4-4-4-12
 * lowercase hexadecimal wire shape.
 */
export const CLOUDFLARE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

export function requireCloudflareUuid(
  value: string | undefined,
  code = "CLOUDFLARE_UUID_INVALID",
  status = 500,
): string {
  if (value === undefined || !CLOUDFLARE_UUID.test(value)) {
    throw new BrokerError(code, status, false);
  }
  return value;
}
