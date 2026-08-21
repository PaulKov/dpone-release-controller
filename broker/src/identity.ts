import { digestObject, isBoundedAscii } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

/** Hashes the exact cross-language `{domain,payload}` identity preimage. */
export function digestDomain(domain: string, payload: JsonObject): Promise<string> {
  if (!isBoundedAscii(domain, 128)) {
    throw new BrokerError("IDENTITY_DOMAIN_INVALID", 400, false);
  }
  return digestObject({ domain, payload });
}
