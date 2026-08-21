import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/canonical";
import { CandidateReaderClient, candidateReaderRequestBody } from "../src/candidate-reader-client";
import { CANDIDATE_SERVICE_VERSION_HEADER } from "../src/private/candidate-rpc";
import { CANDIDATE_NOW, CANDIDATE_ZIP } from "./support/candidate-provider-fixture";
import {
  CANDIDATE_READER_PIN,
  candidateServiceFixture,
  candidateServiceNow,
  candidateServiceResponse,
} from "./support/candidate-reader-service-fixture";

describe("version-pinned candidate reader client", () => {
  it("sends a closed authority request and returns only the bound ZIP stream", async () => {
    const fixture = await candidateServiceFixture();
    let observed: Request | undefined;
    const service = fetcher(async (request) => {
      observed = request;
      return candidateServiceResponse(fixture);
    });

    const stream = await new CandidateReaderClient(
      service,
      CANDIDATE_READER_PIN,
      candidateServiceNow,
    ).open(fixture.input, fixture.authority);

    expect(new Uint8Array(await new Response(stream.body).arrayBuffer())).toEqual(CANDIDATE_ZIP);
    expect(stream.length).toBe(CANDIDATE_ZIP.byteLength);
    expect(stream.observation).toEqual(fixture.observation);
    expect(JSON.stringify(stream.observation)).not.toContain("blob.core.windows.net");
    expect(observed?.url).toBe(
      "https://candidate-reader-private.internal/rpc/v1/candidate/archive",
    );
    expect(observed?.headers.get("cloudflare-workers-version-overrides")).toBe(
      'candidate-reader-private="candidate-reader-version-0001"',
    );
    expect(observed?.headers.get("authorization")).toBeNull();
    expect(observed?.headers.get("cookie")).toBeNull();
    expect(await observed?.text()).toBe(
      canonicalJson(candidateReaderRequestBody(fixture.input, fixture.authority)),
    );
  });

  it("rejects all response metadata drift before exposing provider bytes", async () => {
    const mutations: readonly ((response: Response) => void)[] = [
      (response) => response.headers.set("cache-control", "public, max-age=3600"),
      (response) => response.headers.set("content-type", "application/octet-stream"),
      (response) => response.headers.set("content-length", "5"),
      (response) => response.headers.set("content-length", "9007199254740992"),
      (response) => response.headers.set("content-encoding", "gzip"),
      (response) => response.headers.set("content-range", "bytes 0-3/4"),
      (response) => response.headers.set("location", "https://evil.invalid/capability"),
      (response) => response.headers.set("set-cookie", "token=provider-secret"),
      (response) => response.headers.set("transfer-encoding", "chunked"),
      (response) => response.headers.set("x-content-type-options", ""),
      (response) => response.headers.set("x-dpone-request-id", "request-attacker-0001"),
      (response) =>
        response.headers.set(CANDIDATE_SERVICE_VERSION_HEADER, "candidate-reader-version-0002"),
      (response) => response.headers.set("x-dpone-response-schema", "candidate.alias.v0"),
      (response) => response.headers.set("x-dpone-provider-observation-sha256", tagged("0")),
      (response) => response.headers.set("x-unexpected-provider-header", "forbidden"),
    ];
    for (const mutate of mutations) {
      const fixture = await candidateServiceFixture();
      const response = candidateServiceResponse(fixture);
      mutate(response);
      await expect(
        new CandidateReaderClient(
          fetcher(async () => response),
          CANDIDATE_READER_PIN,
          candidateServiceNow,
        ).open(fixture.input, fixture.authority),
      ).rejects.toThrow();
    }
  });

  it("rejects provider errors and an unused observation after its short TTL", async () => {
    const unavailable = await candidateServiceFixture();
    await expect(
      new CandidateReaderClient(
        fetcher(async () => candidateServiceResponse(unavailable, { status: 503 })),
        CANDIDATE_READER_PIN,
        candidateServiceNow,
      ).open(unavailable.input, unavailable.authority),
    ).rejects.toThrow("CANDIDATE_READER_FAILED");

    const expired = await candidateServiceFixture();
    await expect(
      new CandidateReaderClient(
        fetcher(async () => candidateServiceResponse(expired)),
        CANDIDATE_READER_PIN,
        () => CANDIDATE_NOW + 46_000,
      ).open(expired.input, expired.authority),
    ).rejects.toThrow("CANDIDATE_OBSERVATION_EXPIRY_INVALID");
  });
});

function fetcher(callback: (request: Request) => Promise<Response>): Fetcher {
  return { fetch: callback } as unknown as Fetcher;
}

function tagged(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
