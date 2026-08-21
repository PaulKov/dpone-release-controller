import { readBoundedBytes } from "./bounded";
import { canonicalJson } from "./canonical";
import { assert, BrokerError } from "./errors";
import { assertPinnedServiceVersion, callPinnedService } from "./service-version";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

const MAX_WEBHOOK_BYTES = 65_536;

/** Forwards only GitHub's signed deployment-rule bytes to the pinned gate. */
export class PypiDeploymentGateClient {
  public constructor(
    private readonly service: Fetcher,
    private readonly pin: PrivateServicePin,
  ) {}

  public async handle(request: Request): Promise<JsonObject> {
    requireWebhookContentLength(request);
    const event = requiredHeader(request, "x-github-event", 64);
    assert(event === "deployment_protection_rule", "PYPI_GATE_EVENT_INVALID", 400);
    const delivery = requiredHeader(request, "x-github-delivery", 64);
    assert(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(delivery),
      "PYPI_GATE_DELIVERY_ID_INVALID",
    );
    const signature = requiredHeader(request, "x-hub-signature-256", 71);
    assert(/^sha256=[0-9a-f]{64}$/u.test(signature), "PYPI_GATE_SIGNATURE_INVALID", 401);
    const hookId = requiredHeader(request, "x-github-hook-id", 32);
    assert(/^[1-9][0-9]{0,31}$/u.test(hookId), "PYPI_GATE_HOOK_ID_INVALID");
    const userAgent = requiredHeader(request, "user-agent", 128);
    assert(/^GitHub-Hookshot\/[0-9a-f]+$/u.test(userAgent), "PYPI_GATE_USER_AGENT_INVALID");
    const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    assert(contentType === "application/json", "CONTENT_TYPE_REQUIRED", 415);
    const body = await readBoundedBytes(request, MAX_WEBHOOK_BYTES, "PYPI_GATE_WEBHOOK_TOO_LARGE");
    assert(body.byteLength > 0, "PYPI_GATE_WEBHOOK_EMPTY");
    const response = await callPinnedService(this.service, this.pin, {
      body: Uint8Array.from(body).buffer,
      headers: {
        "content-length": String(body.byteLength),
        "content-type": "application/json",
        "user-agent": userAgent,
        "x-github-delivery": delivery,
        "x-github-event": event,
        "x-github-hook-id": hookId,
        "x-hub-signature-256": signature,
      },
      method: "POST",
      path: "/rpc/v1/deployment-protection-rule",
    });
    if (!response.ok) {
      throw new BrokerError(
        "PYPI_GATE_PRIVATE_SERVICE_FAILED",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    return parseResult(response, delivery.toLowerCase(), this.pin);
  }
}

async function parseResult(
  response: Response,
  expectedDelivery: string,
  pin: PrivateServicePin,
): Promise<JsonObject> {
  const bytes = await readBoundedBytes(response, 4096, "PYPI_GATE_RESPONSE_TOO_LARGE");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("PYPI_GATE_RESPONSE_INVALID", 503, false);
  }
  const result = exactObject(decoded, [
    "delivery_id",
    "outcome",
    "receipt_id",
    "schema",
    "schema_version",
    "worker_version_id",
  ]);
  assert(text === canonicalJson(result), "PYPI_GATE_RESPONSE_NONCANONICAL", 503);
  requireLiteral(result, "schema", "dpone.release-pypi-deployment-gate-result.v1");
  requireExactInteger(result, "schema_version", 1);
  requireLiteral(result, "delivery_id", expectedDelivery);
  const outcome = requireString(result, "outcome", 16);
  assert(outcome === "approved" || outcome === "rejected", "PYPI_GATE_RESPONSE_INVALID", 503);
  requireString(result, "receipt_id", 71, /^sha256:[0-9a-f]{64}$/u);
  assertPinnedServiceVersion(requireString(result, "worker_version_id", 128), pin);
  return result;
}

function requireWebhookContentLength(request: Request): void {
  const value = request.headers.get("content-length");
  if (value === null) {
    return;
  }
  assert(/^(?:0|[1-9][0-9]{0,9})$/u.test(value), "CONTENT_LENGTH_INVALID");
  const parsed = Number(value);
  assert(
    Number.isSafeInteger(parsed) && parsed <= MAX_WEBHOOK_BYTES,
    "PYPI_GATE_WEBHOOK_TOO_LARGE",
    413,
  );
}

function requiredHeader(request: Request, name: string, maxLength: number): string {
  const value = request.headers.get(name);
  assert(
    value !== null && value.length > 0 && value.length <= maxLength,
    "PYPI_GATE_HEADER_INVALID",
  );
  return value;
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "PYPI_GATE_RESPONSE_INVALID",
    503,
  );
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "PYPI_GATE_RESPONSE_INVALID",
    503,
  );
}
