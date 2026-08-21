import { BrokerError } from "./errors";

const FORBIDDEN_HEADERS = Object.freeze([
  "content-encoding",
  "content-range",
  "location",
  "set-cookie",
  "transfer-encoding",
]);

/**
 * Validate the authority-bearing portion of a private JSON response.
 * Cloudflare transport metadata such as Date, Server and CF-Ray is tolerated,
 * while redirect, transformation and cookie semantics are always rejected.
 */
export async function requireExactInternalJsonResponse(
  response: Response,
  expectedStatus: number,
  code: string,
): Promise<void> {
  const invalid =
    response.status !== expectedStatus ||
    response.headers.get("content-type") !== "application/json; charset=utf-8" ||
    response.headers.get("cache-control") !== "no-store" ||
    response.headers.get("x-content-type-options") !== "nosniff" ||
    FORBIDDEN_HEADERS.some((name) => response.headers.has(name));
  if (!invalid) return;

  await response.body?.cancel(code).catch(() => undefined);
  throw new BrokerError(code, 503, response.status === 429 || response.status >= 500);
}
