import { assert } from "./errors";
import type { PrivateServicePin } from "./types";

const OVERRIDE_HEADER = "Cloudflare-Workers-Version-Overrides";
const FORBIDDEN_FORWARD_HEADERS = new Set([
  OVERRIDE_HEADER.toLowerCase(),
  "authorization",
  "cf-access-jwt-assertion",
  "cookie",
]);

export interface PinnedServiceRequest {
  readonly body?: BodyInit;
  readonly headers?: Readonly<Record<string, string>>;
  readonly method: "GET" | "POST";
  readonly path: `/${string}`;
  readonly signal?: AbortSignal;
}

/**
 * Calls one private Worker at the immutable version pinned by activation A0.
 *
 * A new Request and Headers instance are always created. Ingress headers are
 * intentionally impossible to pass through this interface, which prevents an
 * untrusted caller from choosing a different private Worker version.
 */
export function callPinnedService(
  service: Fetcher,
  pin: PrivateServicePin,
  input: PinnedServiceRequest,
): Promise<Response> {
  assert(input.path.startsWith("/"), "SERVICE_PATH_INVALID", 500);
  const headers = new Headers();
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    assert(!FORBIDDEN_FORWARD_HEADERS.has(name.toLowerCase()), "SERVICE_HEADER_FORBIDDEN", 500);
    headers.set(name, value);
  }
  headers.set(OVERRIDE_HEADER, `${pin.serviceName}="${pin.versionId}"`);
  const request = new Request(`https://${pin.serviceName}.internal${input.path}`, {
    body: input.body ?? null,
    headers,
    method: input.method,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  return service.fetch(request);
}

export function assertPinnedServiceVersion(
  observedVersionId: string,
  pin: PrivateServicePin,
): void {
  assert(observedVersionId === pin.versionId, "SERVICE_VERSION_MISMATCH", 503);
}
