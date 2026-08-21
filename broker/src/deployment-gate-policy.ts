import { canonicalBytes } from "./canonical";
import { assert } from "./errors";
import type { JsonObject } from "./types";

const CALLBACK_PREFIX = "/repos/PaulKov/dpone-release-controller/actions/runs/";
const CALLBACK_SUFFIX = "/deployment_protection_rule";

export function parseDeploymentCallbackUrl(value: string): string {
  assert(value.length <= 512, "PYPI_GATE_CALLBACK_URL_INVALID");
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    assert(false, "PYPI_GATE_CALLBACK_URL_INVALID");
  }
  assert(
    url.protocol === "https:" &&
      url.hostname === "api.github.com" &&
      url.port === "" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      url.pathname.startsWith(CALLBACK_PREFIX) &&
      url.pathname.endsWith(CALLBACK_SUFFIX),
    "PYPI_GATE_CALLBACK_URL_INVALID",
  );
  const runId = url.pathname.slice(CALLBACK_PREFIX.length, -CALLBACK_SUFFIX.length);
  assert(/^[1-9][0-9]{0,15}$/u.test(runId), "PYPI_GATE_RUN_ID_INVALID");
  return runId;
}

export function deploymentReviewUrl(runId: string): string {
  assert(/^[1-9][0-9]{0,15}$/u.test(runId), "PYPI_GATE_RUN_ID_INVALID");
  return `https://api.github.com${CALLBACK_PREFIX}${runId}${CALLBACK_SUFFIX}`;
}

export function deploymentReviewBody(
  state: "approved" | "rejected",
  receiptReference: string,
): Uint8Array {
  assert(/^sha256:[0-9a-f]{64}$/u.test(receiptReference), "PYPI_GATE_RECEIPT_REFERENCE_INVALID");
  const body: JsonObject = {
    comment: `dpone release authority receipt ${receiptReference}`,
    environment_name: "pypi",
    state,
  };
  return canonicalBytes(body);
}

export async function verifyGitHubWebhookHmac(
  rawBody: Uint8Array,
  signatureHeader: string,
  secret: Uint8Array,
): Promise<void> {
  assert(rawBody.byteLength > 0 && rawBody.byteLength <= 65_536, "PYPI_GATE_WEBHOOK_SIZE_INVALID");
  assert(
    secret.byteLength >= 32 && secret.byteLength <= 256,
    "PYPI_GATE_WEBHOOK_SECRET_INVALID",
    500,
  );
  const match = /^sha256=([0-9a-f]{64})$/u.exec(signatureHeader);
  assert(match !== null, "PYPI_GATE_WEBHOOK_SIGNATURE_INVALID", 401);
  const key = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(secret).buffer,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  const computed = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, Uint8Array.from(rawBody).buffer),
  );
  const supplied = hexBytes(match[1] ?? "");
  let difference = computed.length ^ supplied.length;
  for (let index = 0; index < Math.max(computed.length, supplied.length); index += 1) {
    difference |= (computed[index] ?? 0) ^ (supplied[index] ?? 0);
  }
  assert(difference === 0, "PYPI_GATE_WEBHOOK_SIGNATURE_INVALID", 401);
}

export function validateGitHubDeliveryId(value: string): string {
  assert(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value),
    "PYPI_GATE_DELIVERY_ID_INVALID",
  );
  return value.toLowerCase();
}

function hexBytes(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}
