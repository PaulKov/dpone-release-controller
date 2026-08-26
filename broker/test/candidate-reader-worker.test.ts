import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import { BrokerError } from "../src/errors";
import {
  CANDIDATE_MEDIA_TYPE,
  CANDIDATE_OBSERVATION_DIGEST_HEADER,
  CANDIDATE_OBSERVATION_HEADER,
  CANDIDATE_RPC_PATH,
  CANDIDATE_SERVICE_IDENTITY_HEADER,
  buildCandidateReaderRpcRequest,
  decodeCandidateObservation,
} from "../src/private/candidate-rpc";
import productionHandler, {
  createCandidateReaderHandler,
  type CandidateReaderWorkerEnv,
} from "../src/private/candidate-reader-worker";
import {
  CANDIDATE_NOW,
  CANDIDATE_ZIP,
  candidateHarness,
} from "./support/candidate-provider-fixture";
import { CANDIDATE_READER_PIN } from "./support/candidate-reader-service-fixture";

describe("credential-isolated candidate reader Worker", () => {
  it("accepts one closed RPC and never returns the App token or signed URL", async () => {
    const harness = await candidateHarness();
    const result = await harness.reader.authorize(harness.input, harness.authority);
    let calls = 0;
    const handler = createCandidateReaderHandler(() => ({
      authorizer: {
        authorize(input, authority) {
          calls += 1;
          expect(input).toEqual(harness.input);
          expect(authority).toEqual(harness.authority);
          return Promise.resolve(result);
        },
      },
      serviceIdentity: CANDIDATE_READER_PIN.serviceIdentity,
      workerVersionId: CANDIDATE_READER_PIN.versionId,
    }));

    const response = await handler.fetch(
      rpcRequest(
        harness.input.requestId,
        buildCandidateReaderRpcRequest(harness.input, harness.authority),
      ),
      testEnv(),
    );
    expect(response.status).toBe(200);
    expect(calls).toBe(1);
    expect(response.headers.get("cache-control")).toBe("private, no-store, max-age=0");
    expect(response.headers.get(CANDIDATE_SERVICE_IDENTITY_HEADER)).toBe(
      CANDIDATE_READER_PIN.serviceIdentity,
    );
    expect(response.headers.has("location")).toBe(false);
    expect(response.headers.has("set-cookie")).toBe(false);
    const encoded = response.headers.get(CANDIDATE_OBSERVATION_HEADER);
    const digest = response.headers.get(CANDIDATE_OBSERVATION_DIGEST_HEADER);
    expect(encoded).not.toBeNull();
    expect(digest).not.toBeNull();
    const decoded = await decodeCandidateObservation(
      encoded ?? "",
      digest ?? "",
      { authority: harness.authority, input: harness.input },
      {
        identity: CANDIDATE_READER_PIN.serviceIdentity,
        versionId: CANDIDATE_READER_PIN.versionId,
      },
      CANDIDATE_NOW,
    );
    expect(decoded.observation.candidate_reader_service_identity).toBe(
      CANDIDATE_READER_PIN.serviceIdentity,
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(CANDIDATE_ZIP);
    expect(JSON.stringify(Object.fromEntries(response.headers))).not.toContain("ghs_");
    expect(JSON.stringify(Object.fromEntries(response.headers))).not.toContain(
      "blob.core.windows.net",
    );
  });

  it("rejects route, credential, authority and canonical-body drift before provider access", async () => {
    const harness = await candidateHarness();
    let calls = 0;
    const handler = createCandidateReaderHandler(() => ({
      authorizer: {
        authorize() {
          calls += 1;
          throw new Error("provider must not be reached");
        },
      },
      serviceIdentity: CANDIDATE_READER_PIN.serviceIdentity,
      workerVersionId: CANDIDATE_READER_PIN.versionId,
    }));
    const body = buildCandidateReaderRpcRequest(harness.input, harness.authority);
    const requests = [
      rpcRequest(harness.input.requestId, body, { path: "/rpc/v1/candidate/other" }),
      rpcRequest(harness.input.requestId, body, { query: "?selector=all" }),
      rpcRequest(harness.input.requestId, body, { method: "GET" }),
      rpcRequest(harness.input.requestId, body, {
        extraHeaders: { authorization: "Bearer stolen" },
      }),
      rpcRequest(harness.input.requestId, body, { extraHeaders: { cookie: "session=stolen" } }),
      rpcRequest(harness.input.requestId, body, { serviceIdentity: "cloudflare-worker:attacker" }),
      rpcRequest(harness.input.requestId, { ...body, app_id: 101 }),
      rpcRequest(harness.input.requestId, body, {
        bodyText: canonicalJson(body).replace("{", "{ "),
      }),
    ];
    for (const request of requests) {
      const response = await handler.fetch(request, testEnv());
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.status).toBeLessThanOrEqual(503);
    }
    expect(calls).toBe(0);
  });

  it("keeps production configuration fail-closed without live secrets", async () => {
    const harness = await candidateHarness();
    const response = await productionHandler.fetch(
      rpcRequest(
        harness.input.requestId,
        buildCandidateReaderRpcRequest(harness.input, harness.authority),
      ),
      testEnv(),
    );
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).toContain("PRIVATE_SERVICE_PROVISIONING");
    expect(text).not.toContain("GITHUB_APP_PRIVATE_KEY");
  });

  it("returns a closed error when the provider adapter fails", async () => {
    const harness = await candidateHarness();
    const handler = createCandidateReaderHandler(() => ({
      authorizer: {
        authorize() {
          throw new BrokerError("CANDIDATE_PROVIDER_REQUEST_FAILED", 503, true);
        },
      },
      serviceIdentity: CANDIDATE_READER_PIN.serviceIdentity,
      workerVersionId: CANDIDATE_READER_PIN.versionId,
    }));
    const response = await handler.fetch(
      rpcRequest(
        harness.input.requestId,
        buildCandidateReaderRpcRequest(harness.input, harness.authority),
      ),
      testEnv(),
    );
    expect(response.status).toBe(503);
    expect(await response.text()).toBe(
      canonicalJson({
        error: {
          code: "CANDIDATE_PROVIDER_REQUEST_FAILED",
          request_id: harness.input.requestId,
          retryable: true,
        },
      }),
    );
  });
});

interface RpcRequestOptions {
  readonly bodyText?: string;
  readonly extraHeaders?: Readonly<Record<string, string>>;
  readonly method?: string;
  readonly path?: string;
  readonly query?: string;
  readonly serviceIdentity?: string;
}

function rpcRequest(requestId: string, body: object, options: RpcRequestOptions = {}): Request {
  const bodyText = options.bodyText ?? canonicalJson(body);
  const method = options.method ?? "POST";
  const init: RequestInit = {
    headers: {
      accept: CANDIDATE_MEDIA_TYPE,
      "content-type": "application/json",
      [CANDIDATE_SERVICE_IDENTITY_HEADER]:
        options.serviceIdentity ?? CANDIDATE_READER_PIN.serviceIdentity,
      "x-request-id": requestId,
      ...options.extraHeaders,
    },
    method,
  };
  if (method !== "GET") init.body = bodyText;
  return new Request(
    `https://candidate-reader.internal${options.path ?? CANDIDATE_RPC_PATH}${options.query ?? ""}`,
    init,
  );
}

function testEnv(): CandidateReaderWorkerEnv {
  return { OPERATING_MODE: "provisioning" };
}
