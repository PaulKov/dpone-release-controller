import { TextDecoder } from "node:util";

import { MAX_SMOKE_BYTES } from "./bootstrap-live-workers-common.mjs";

export async function smokeBootstrap(hostname, versionId, fetchImpl) {
  const checks = [
    ["GET", "/readyz"],
    ["POST", "/v1/admin/activation/provision"],
    ["POST", "/v1/providers/github/candidate"],
    ["POST", "/v1/receipts/append"],
    ["POST", "/v1/runtime/closure"],
    ["POST", "/v1/webhooks/github/deployment-protection-rule"],
  ];
  const liveness = await fetchImpl(`https://${hostname}/livez`, {
    headers: { "x-request-id": "bootstrap-smoke-liveness-0001" },
    redirect: "error",
  });
  const liveBody = await boundedJsonResponse(liveness, MAX_SMOKE_BYTES);
  if (
    liveness.status !== 200 ||
    JSON.stringify(liveBody) !==
      JSON.stringify({
        schema: "dpone.release-broker-bootstrap-liveness.v1",
        status: "bootstrap-deny",
        worker_version_id: versionId,
      })
  ) {
    throw new Error("bootstrap liveness smoke did not reach the exact deployed version");
  }
  for (const [method, path] of checks) {
    const response = await fetchImpl(`https://${hostname}${path}`, {
      headers: { "x-request-id": "bootstrap-smoke-deny-0001" },
      method,
      redirect: "error",
    });
    const body = await boundedJsonResponse(response, MAX_SMOKE_BYTES);
    if (
      response.status !== 503 ||
      body?.error?.code !== "BROKER_BOOTSTRAP_DENY" ||
      body?.error?.request_id !== "bootstrap-smoke-deny-0001" ||
      body?.error?.retryable !== false
    ) {
      throw new Error(`bootstrap deny smoke failed for ${path}`);
    }
  }
  return {
    authority_paths_denied: checks.map(([, path]) => path),
    hostname,
    liveness_version_id: versionId,
  };
}

export async function boundedJsonResponse(response, limit, policy = {}) {
  const contentType = response.headers.get("content-type");
  const declared = response.headers.get("content-length");
  if (
    contentType !== "application/json; charset=utf-8" ||
    response.headers.has("content-encoding") ||
    response.headers.has("content-range") ||
    response.headers.has("location") ||
    response.headers.has("set-cookie") ||
    response.headers.has("transfer-encoding")
  ) {
    await response.body?.cancel("bootstrap smoke headers invalid").catch(() => undefined);
    throw new Error("bootstrap smoke response headers invalid");
  }
  let declaredLength = null;
  if (declared !== null) {
    if (!/^(?:0|[1-9][0-9]{0,15})$/u.test(declared)) {
      await response.body?.cancel("bootstrap smoke Content-Length invalid").catch(() => undefined);
      throw new Error("bootstrap smoke Content-Length invalid");
    }
    declaredLength = Number(declared);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > limit) {
      await response.body?.cancel("bootstrap smoke response oversized").catch(() => undefined);
      throw new Error("bootstrap smoke response size invalid");
    }
  }
  if (response.body === null) throw new Error("bootstrap smoke response body missing");
  const idleTimeoutMs = boundedTimeout(policy.idleTimeoutMs ?? 5_000);
  const totalTimeoutMs = boundedTimeout(policy.totalTimeoutMs ?? 15_000);
  const maximumChunks = policy.maximumChunks ?? 1_024;
  if (!Number.isSafeInteger(maximumChunks) || maximumChunks <= 0 || maximumChunks > 16_384) {
    throw new Error("bootstrap smoke chunk limit invalid");
  }
  const reader = response.body.getReader();
  const chunks = [];
  const startedAt = Date.now();
  let total = 0;
  try {
    for (let count = 0; ; count += 1) {
      const remaining = totalTimeoutMs - (Date.now() - startedAt);
      if (remaining <= 0) throw new Error("bootstrap smoke response timed out");
      const item = await readBeforeTimeout(reader, Math.min(idleTimeoutMs, remaining));
      if (item.done) break;
      if (item.value.byteLength === 0 || count >= maximumChunks) {
        throw new Error("bootstrap smoke response stream shape invalid");
      }
      total += item.value.byteLength;
      if (total > limit) throw new Error("bootstrap smoke response size invalid");
      chunks.push(item.value);
    }
    if (declaredLength !== null && total !== declaredLength) {
      throw new Error("bootstrap smoke Content-Length mismatch");
    }
  } catch (error) {
    await reader.cancel("bootstrap smoke bounded read failed").catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (bytes.byteLength === 0) throw new Error("bootstrap smoke response size invalid");
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("bootstrap smoke response is not exact UTF-8 JSON");
  }
}

function boundedTimeout(value) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 60_000) {
    throw new Error("bootstrap smoke timeout invalid");
  }
  return value;
}

async function readBeforeTimeout(reader, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      reader.read(),
      new Promise((_, reject) => {
        timer = globalThis.setTimeout(
          () => reject(new Error("bootstrap smoke response stalled")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    globalThis.clearTimeout(timer);
  }
}
