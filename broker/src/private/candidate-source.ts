import { sha256Hex } from "../canonical";
import { boundedFixedLengthStream } from "../bounded";
import { BrokerError } from "../errors";
import { CANDIDATE_STREAM_PIPE_POLICY, MAX_RAW_CANDIDATE_BYTES } from "./candidate-contract";
import type { ProviderFetch } from "./github-provider";

const SIGNED_URL_TTL_MS = 60_000;
const MIN_SIGNED_URL_REMAINING_MS = 10_000;
const PROVIDER_TIMEOUT_MS = 15_000;
const SIGNED_HOST = /^productionresultssa[0-9]*\.blob\.core\.windows\.net$/u;
const SIGNED_QUERY_KEYS = new Set([
  "se",
  "sig",
  "ske",
  "skoid",
  "sks",
  "skt",
  "sktid",
  "skv",
  "sp",
  "spr",
  "sr",
  "rscc",
  "rscd",
  "rsce",
  "rscl",
  "rsct",
  "st",
  "sv",
]);

/**
 * A validated provider capability whose bearer URL is never serialised. Its
 * body is opened at most once and streamed without buffering candidate bytes.
 */
export class ValidatedCandidateSource {
  #opened = false;
  readonly #expectedBytes: number;
  readonly #now: () => number;
  readonly #providerFetch: ProviderFetch;
  readonly #signedUrl: string;

  public constructor(
    signedUrl: string,
    public readonly expiresAt: string,
    public readonly urlSha256: string,
    expectedBytes: number,
    providerFetch: ProviderFetch,
    now: () => number,
  ) {
    this.#signedUrl = signedUrl;
    this.#expectedBytes = expectedBytes;
    this.#providerFetch = providerFetch;
    this.#now = now;
  }

  public async open(): Promise<Response> {
    if (this.#opened) {
      throw new BrokerError("CANDIDATE_SOURCE_ALREADY_OPENED", 409, false);
    }
    this.#opened = true;
    if (Date.parse(this.expiresAt) <= this.#now()) {
      throw new BrokerError("CANDIDATE_SOURCE_EXPIRED", 409, false);
    }
    const response = await signedFetch(this.#providerFetch, this.#signedUrl);
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new BrokerError(
        "CANDIDATE_SOURCE_UNAVAILABLE",
        503,
        response.status === 429 || response.status >= 500,
      );
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/zip" && contentType !== "application/octet-stream") {
      await response.body?.cancel();
      throw new BrokerError("CANDIDATE_SOURCE_CONTENT_TYPE_INVALID", 503, false);
    }
    const contentLength = response.headers.get("content-length");
    if (
      response.headers.has("content-encoding") ||
      response.headers.has("content-range") ||
      response.redirected
    ) {
      await response.body?.cancel();
      throw new BrokerError("CANDIDATE_SOURCE_ENCODING_INVALID", 503, false);
    }
    if (contentLength === null || !/^[1-9][0-9]{0,15}$/u.test(contentLength)) {
      await response.body?.cancel();
      throw new BrokerError("CANDIDATE_SOURCE_LENGTH_INVALID", 503, false);
    }
    const length = Number(contentLength);
    if (
      !Number.isSafeInteger(length) ||
      length !== this.#expectedBytes ||
      length > MAX_RAW_CANDIDATE_BYTES ||
      response.body === null
    ) {
      await response.body?.cancel();
      throw new BrokerError("CANDIDATE_SOURCE_LENGTH_INVALID", 503, false);
    }
    const body = boundedFixedLengthStream(
      response.body,
      length,
      "CANDIDATE_PROVIDER_BODY",
      CANDIDATE_STREAM_PIPE_POLICY,
    );
    return new Response(body, {
      headers: {
        "cache-control": "no-store, no-cache, must-revalidate, private",
        "content-type": "application/zip",
        expires: "0",
        pragma: "no-cache",
        "x-content-type-options": "nosniff",
      },
      status: 200,
    });
  }
}

export async function createValidatedCandidateSource(
  value: string,
  expectedBytes: number,
  providerFetch: ProviderFetch,
  now: () => number,
): Promise<ValidatedCandidateSource> {
  const nowMs = now();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new BrokerError("CANDIDATE_SOURCE_URL_INVALID", 503, false);
  }
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(url.pathname);
  } catch {
    throw new BrokerError("CANDIDATE_SOURCE_URL_INVALID", 503, false);
  }
  if (
    url.protocol !== "https:" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    !SIGNED_HOST.test(url.hostname) ||
    !decodedPath.startsWith("/actions-results/") ||
    decodedPath.includes("//") ||
    decodedPath.split("/").some((segment) => segment === "." || segment === "..") ||
    hasUnsafePathScalar(decodedPath)
  ) {
    throw new BrokerError("CANDIDATE_SOURCE_URL_INVALID", 503, false);
  }
  const keys = [...url.searchParams.keys()];
  if (new Set(keys).size !== keys.length || keys.some((key) => !SIGNED_QUERY_KEYS.has(key))) {
    throw new BrokerError("CANDIDATE_SOURCE_QUERY_INVALID", 503, false);
  }
  if (
    url.searchParams.get("sp") !== "r" ||
    url.searchParams.get("spr") !== "https" ||
    url.searchParams.get("sr") !== "b" ||
    !/^\d{4}-\d{2}-\d{2}$/u.test(url.searchParams.get("sv") ?? "") ||
    !/^[A-Za-z0-9+/_=-]{16,512}$/u.test(url.searchParams.get("sig") ?? "")
  ) {
    throw new BrokerError("CANDIDATE_SOURCE_QUERY_INVALID", 503, false);
  }
  const expiryMs = Date.parse(url.searchParams.get("se") ?? "");
  const start = url.searchParams.get("st");
  const startMs = start === null ? nowMs : Date.parse(start);
  if (
    !Number.isSafeInteger(expectedBytes) ||
    expectedBytes <= 0 ||
    expectedBytes > MAX_RAW_CANDIDATE_BYTES ||
    !Number.isFinite(expiryMs) ||
    !Number.isFinite(startMs) ||
    expiryMs <= nowMs ||
    expiryMs > nowMs + SIGNED_URL_TTL_MS ||
    startMs > nowMs + 30_000 ||
    startMs >= expiryMs
  ) {
    throw new BrokerError("CANDIDATE_SOURCE_EXPIRY_INVALID", 503, false);
  }
  if (expiryMs <= nowMs + MIN_SIGNED_URL_REMAINING_MS) {
    throw new BrokerError("CANDIDATE_SOURCE_REFRESH_REQUIRED", 503, false);
  }
  return new ValidatedCandidateSource(
    value,
    canonicalUtcSeconds(expiryMs),
    `sha256:${await sha256Hex(value)}`,
    expectedBytes,
    providerFetch,
    now,
  );
}

function hasUnsafePathScalar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x5c || code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function canonicalUtcSeconds(value: number): string {
  return new Date(Math.floor(value / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

async function signedFetch(providerFetch: ProviderFetch, url: string): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await providerFetch(url, {
      headers: {
        accept: "application/zip",
        "user-agent": "dpone-release-authority-broker/1",
      },
      method: "GET",
      redirect: "error",
      signal: controller.signal,
    });
  } catch {
    throw new BrokerError("CANDIDATE_SOURCE_UNAVAILABLE", 503, true);
  } finally {
    clearTimeout(timeout);
  }
}
