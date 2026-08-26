import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

const TOKEN_DOCUMENT = /^\{"api_token":"([A-Za-z0-9._~-]{20,512})"\}\n$/u;
const ACCOUNT_ID = /^[0-9a-f]{32}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

/**
 * Validate the observer token and its independently produced provider policy
 * observation. This command intentionally performs no Cloudflare mutation:
 * the sole token-bearing Worker version is uploaded by the four-role paired
 * authority ceremony, which also installs both separated RPC keys.
 */
export function main() {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  return options.verify
    ? runCloudflareObserverTokenVerification(options)
    : runCloudflareObserverTokenDryValidation(options);
}

/** Quarantined durable verification report boundary. */
export function runCloudflareObserverTokenVerification(options) {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  return executeCloudflareObserverTokenVerification(options);
}

function runCloudflareObserverTokenDryValidation(options) {
  if (options.verify) throw new Error("dry token validation rejects verify options");
  return executeCloudflareObserverTokenVerification(options);
}

function executeCloudflareObserverTokenVerification(options) {
  const credential = readTokenDocument(options.credential);
  try {
    const tokenFingerprintSha256 = taggedSha256(Buffer.from(credential.token, "utf8"));
    const restriction = readRestrictionEvidence(
      options.restrictionEvidence,
      tokenFingerprintSha256,
    );
    const providerPolicyEvidence =
      options.providerPolicyEvidence === null
        ? null
        : readProviderPolicyEvidence(
            options.providerPolicyEvidence,
            restriction,
            tokenFingerprintSha256,
            Date.now(),
          );
    const report = {
      provider_mutation_performed: false,
      provider_policy_evidence: providerPolicyEvidence,
      restriction_evidence: restriction,
      schema: "dpone.cloudflare-deployment-observer-token-verification.v1",
      schema_version: 1,
      status: options.verify ? "READY_FOR_PAIRED_CEREMONY" : "DRY_RUN_VALIDATED",
      token_fingerprint_sha256: tokenFingerprintSha256,
    };
    if (options.verify) {
      if (providerPolicyEvidence === null || options.result === null) {
        throw new Error("verified token policy requires provider evidence and a result path");
      }
      assertPrivateResultTarget(options.result);
      writeFileSync(options.result, canonicalBytes(report), { flag: "wx", mode: 0o600 });
    }
    const output = `${JSON.stringify({ ...report, result: options.result })}\n`;
    process.stdout.write(output);
    return output;
  } finally {
    credential.bytes.fill(0);
  }
}

export function parseArguments(arguments_) {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  const values = new Map();
  let verify = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--verify") {
      if (verify) throw new Error(usage());
      verify = true;
      continue;
    }
    if (
      ![
        "--credential",
        "--provider-policy-evidence",
        "--restriction-evidence",
        "--result",
      ].includes(argument)
    ) {
      throw new Error(usage());
    }
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(argument)) {
      throw new Error(usage());
    }
    values.set(argument, value);
    index += 1;
  }
  const credential = values.get("--credential");
  const restrictionEvidence = values.get("--restriction-evidence");
  const providerPolicyEvidence = values.get("--provider-policy-evidence");
  const result = values.get("--result");
  if (
    credential === undefined ||
    restrictionEvidence === undefined ||
    (verify && (providerPolicyEvidence === undefined || result === undefined)) ||
    (!verify && (providerPolicyEvidence !== undefined || result !== undefined))
  ) {
    throw new Error(usage());
  }
  return {
    credential: resolve(credential),
    providerPolicyEvidence:
      providerPolicyEvidence === undefined ? null : resolve(providerPolicyEvidence),
    restrictionEvidence: resolve(restrictionEvidence),
    result: result === undefined ? null : resolve(result),
    verify,
  };
}

export function readTokenDocument(path) {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  const bytes = readPrivateFile(path, 35, 544);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    bytes.fill(0);
    throw new Error("Cloudflare observer token document is not canonical UTF-8");
  }
  const match = TOKEN_DOCUMENT.exec(text);
  if (match?.[1] === undefined) {
    bytes.fill(0);
    throw new Error("Cloudflare observer token document is not canonical");
  }
  return { bytes, token: match[1] };
}

export function readRestrictionEvidence(path, tokenFingerprintSha256) {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  const bytes = readPrivateFile(path, 64, 4096);
  const value = parseCanonicalJson(bytes, "Cloudflare token restriction evidence");
  if (
    JSON.stringify(Object.keys(value)) !==
      JSON.stringify([
        "account_id",
        "grants",
        "schema",
        "schema_version",
        "token_fingerprint_sha256",
        "zone_id",
      ]) ||
    typeof value.account_id !== "string" ||
    !ACCOUNT_ID.test(value.account_id) ||
    typeof value.zone_id !== "string" ||
    !ACCOUNT_ID.test(value.zone_id) ||
    JSON.stringify(value.grants) !==
      JSON.stringify([
        {
          permission: "Workers Scripts Read",
          resource_scope: `account:${value.account_id}`,
        },
        {
          permission: "Workers Routes Read",
          resource_scope: `zone:${value.zone_id}`,
        },
      ]) ||
    value.schema !== "dpone.cloudflare-deployment-observer-token-restriction-evidence.v1" ||
    value.schema_version !== 1 ||
    value.token_fingerprint_sha256 !== tokenFingerprintSha256
  ) {
    throw new Error("Cloudflare token restriction evidence contract mismatch");
  }
  return {
    account_id: value.account_id,
    evidence_sha256: taggedSha256(bytes),
    grants: value.grants,
    token_fingerprint_sha256: value.token_fingerprint_sha256,
    zone_id: value.zone_id,
  };
}

export function readProviderPolicyEvidence(
  path,
  restriction,
  tokenFingerprintSha256,
  acceptedAtMs,
) {
  assertProviderMutationReleased("cloudflare-observer-token-verify");
  const bytes = readPrivateFile(path, 64, 8192);
  const value = parseCanonicalJson(bytes, "Cloudflare token provider policy evidence");
  const observedAtMs = Date.parse(value.observed_at);
  if (
    JSON.stringify(Object.keys(value)) !==
      JSON.stringify([
        "account_id",
        "grants",
        "observed_at",
        "provider_observation_sha256",
        "schema",
        "schema_version",
        "token_fingerprint_sha256",
        "zone_id",
      ]) ||
    value.schema !== "dpone.cloudflare-api-token-policy-observation.v1" ||
    value.schema_version !== 1 ||
    value.account_id !== restriction.account_id ||
    value.zone_id !== restriction.zone_id ||
    value.token_fingerprint_sha256 !== tokenFingerprintSha256 ||
    JSON.stringify(value.grants) !== JSON.stringify(restriction.grants) ||
    typeof value.observed_at !== "string" ||
    !Number.isFinite(observedAtMs) ||
    new Date(observedAtMs).toISOString() !== value.observed_at ||
    !Number.isSafeInteger(acceptedAtMs) ||
    observedAtMs > acceptedAtMs ||
    acceptedAtMs - observedAtMs > 60_000 ||
    typeof value.provider_observation_sha256 !== "string" ||
    !DIGEST.test(value.provider_observation_sha256)
  ) {
    throw new Error("Cloudflare token provider policy evidence contract mismatch");
  }
  return {
    account_id: value.account_id,
    evidence_sha256: taggedSha256(bytes),
    grants: value.grants,
    observed_at: value.observed_at,
    provider_observation_sha256: value.provider_observation_sha256,
    token_fingerprint_sha256: value.token_fingerprint_sha256,
    zone_id: value.zone_id,
  };
}

function parseCanonicalJson(bytes, label) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${label} is not canonical UTF-8 JSON`);
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    `${JSON.stringify(value)}\n` !== bytes.toString("utf8")
  ) {
    throw new Error(`${label} is not canonical UTF-8 JSON`);
  }
  return value;
}

function readPrivateFile(path, minimumBytes, maximumBytes) {
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o077) !== 0 ||
    stat.size < minimumBytes ||
    stat.size > maximumBytes
  ) {
    throw new Error("Cloudflare observer input must be an exact mode-0600 regular file");
  }
  const bytes = readFileSync(path);
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== stat.size) {
    throw new Error("Cloudflare observer input read is not byte-exact");
  }
  return bytes;
}

function assertPrivateResultTarget(path) {
  if (existsSync(path)) throw new Error("Cloudflare token verification result is one-use");
  const parent = lstatSync(dirname(path));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o022) !== 0) {
    throw new Error("Cloudflare token verification result parent is not private");
  }
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

function usage() {
  return (
    "usage: pnpm cloudflare-observer-token:verify -- --credential <canonical-0600-json> " +
    "--restriction-evidence <canonical-0600-json> " +
    "[--provider-policy-evidence <canonical-0600-json> --result <canonical-0600-json> --verify]"
  );
}
