import { describe, expect, it } from "vitest";

import {
  createValidatedCandidateSource,
  type ValidatedCandidateSource,
} from "../src/private/candidate-source";
import type { ProviderFetch } from "../src/private/github-provider";

const NOW = Date.parse("2026-08-15T12:00:00Z");
const BODY = Uint8Array.from([0x50, 0x4b, 0x03, 0x04]);

describe("private candidate byte source", () => {
  it("keeps the signed bearer private and streams one exact no-cache body", async () => {
    const calls: { headers: Headers; redirect: RequestRedirect; url: string }[] = [];
    const source = await candidateSource(async (target, init) => {
      calls.push({
        headers: new Headers(init?.headers),
        redirect: init?.redirect ?? "follow",
        url: targetUrl(target),
      });
      return zipResponse(BODY, BODY.byteLength);
    });

    expect(JSON.stringify(source)).not.toContain("blob.core.windows.net");
    expect(Object.getOwnPropertyNames(source)).toEqual(["expiresAt", "urlSha256"]);
    const response = await source.open();
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(BODY);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.has("content-encoding")).toBe(false);
    expect(response.headers.has("content-range")).toBe(false);
    expect(response.headers.has("transfer-encoding")).toBe(false);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.has("authorization")).toBe(false);
    expect(calls[0]?.headers.get("accept")).toBe("application/zip");
    expect(calls[0]?.redirect).toBe("error");
    expect(calls[0]?.url).toBe(signedUrl());
    await expect(source.open()).rejects.toThrow("CANDIDATE_SOURCE_ALREADY_OPENED");
  });

  it("rejects signed URL host, transport, path, query, replay and expiry drift", async () => {
    const mutations = [
      (url: URL) => {
        url.protocol = "http:";
      },
      (url: URL) => {
        url.hostname = "evil.invalid";
      },
      (url: URL) => {
        url.port = "444";
      },
      (url: URL) => {
        url.username = "attacker";
      },
      (url: URL) => {
        url.hash = "fragment";
      },
      (url: URL) => {
        url.pathname = "/other/object.zip";
      },
      (url: URL) => {
        url.pathname = "/actions-results/a//b.zip";
      },
      (url: URL) => {
        url.searchParams.append("sp", "r");
      },
      (url: URL) => {
        url.searchParams.set("sp", "rw");
      },
      (url: URL) => {
        url.searchParams.set("spr", "http");
      },
      (url: URL) => {
        url.searchParams.set("redirect", "https://evil.invalid");
      },
      (url: URL) => {
        url.searchParams.set("sig", "not valid signature");
      },
      (url: URL) => {
        url.searchParams.set("se", "2026-08-15T12:01:01Z");
      },
      (url: URL) => {
        url.searchParams.set("se", "2026-08-15T11:59:59Z");
      },
    ];
    for (const mutate of mutations) {
      const url = new URL(signedUrl());
      mutate(url);
      await expect(
        createValidatedCandidateSource(url.toString(), BODY.byteLength, unreachable(), () => NOW),
      ).rejects.toThrow(/CANDIDATE_SOURCE_(?:URL|QUERY|EXPIRY)_INVALID/u);
    }
  });

  it("rejects malformed lengths, encoding and error responses before exposing bytes", async () => {
    const responses = [
      new Response(BODY, { headers: { "content-type": "application/zip" } }),
      zipResponse(BODY, BODY.byteLength + 1),
      zipResponse(BODY, "1e3"),
      zipResponse(BODY, BODY.byteLength, { "content-encoding": "gzip" }),
      zipResponse(BODY, BODY.byteLength, { "content-range": "bytes 0-3/4" }),
      new Response(BODY, {
        headers: {
          "content-length": String(BODY.byteLength),
          "content-range": "bytes 0-3/4",
          "content-type": "application/zip",
        },
        status: 206,
      }),
      new Response(BODY, {
        headers: {
          "content-length": String(BODY.byteLength),
          "content-type": "text/html",
        },
      }),
      new Response("unavailable", { status: 503 }),
    ];
    for (const providerResponse of responses) {
      const source = await candidateSource(async () => providerResponse);
      await expect(source.open()).rejects.toThrow(/CANDIDATE_SOURCE_/u);
    }
  });

  it("detects truncated and overflow bodies while consuming the bounded stream", async () => {
    const truncated = await candidateSource(async () =>
      zipResponse(Uint8Array.from([1, 2, 3]), BODY.byteLength),
    );
    await expect((await truncated.open()).arrayBuffer()).rejects.toThrow();

    const overflow = await candidateSource(async () =>
      zipResponse(Uint8Array.from([1, 2, 3, 4, 5]), BODY.byteLength),
    );
    await expect((await overflow.open()).arrayBuffer()).rejects.toThrow();

    const aborted = await candidateSource(async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.error(new Error("upstream aborted"));
        },
      });
      return new Response(body, {
        headers: {
          "content-length": String(BODY.byteLength),
          "content-type": "application/zip",
        },
      });
    });
    await expect((await aborted.open()).arrayBuffer()).rejects.toThrow("upstream aborted");
  });

  it("uses the injected clock for open-time expiry", async () => {
    let current = NOW;
    const source = await createValidatedCandidateSource(
      signedUrl(),
      BODY.byteLength,
      unreachable(),
      () => current,
    );
    current += 46_000;
    await expect(source.open()).rejects.toThrow("CANDIDATE_SOURCE_EXPIRED");
  });
});

async function candidateSource(providerFetch: ProviderFetch): Promise<ValidatedCandidateSource> {
  return createValidatedCandidateSource(signedUrl(), BODY.byteLength, providerFetch, () => NOW);
}

function signedUrl(): string {
  const url = new URL(
    "https://productionresultssa0.blob.core.windows.net/actions-results/run/artifact.zip",
  );
  url.searchParams.set("se", "2026-08-15T12:00:45Z");
  url.searchParams.set("sig", "A".repeat(32));
  url.searchParams.set("sp", "r");
  url.searchParams.set("spr", "https");
  url.searchParams.set("sr", "b");
  url.searchParams.set("st", "2026-08-15T11:59:55Z");
  url.searchParams.set("sv", "2025-11-05");
  url.searchParams.set("rscd", "attachment; filename=release-candidates.zip");
  url.searchParams.set("rsct", "application/zip");
  return url.toString();
}

function zipResponse(body: BodyInit, length: number | string, extra: HeadersInit = {}): Response {
  return new Response(body, {
    headers: {
      "content-length": String(length),
      "content-type": "application/zip",
      ...Object.fromEntries(new Headers(extra)),
    },
  });
}

function unreachable(): ProviderFetch {
  return async () => {
    throw new Error("provider must not be called");
  };
}

function targetUrl(target: RequestInfo | URL): string {
  if (typeof target === "string") return target;
  return target instanceof URL ? target.toString() : target.url;
}
