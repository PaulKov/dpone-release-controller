import { assert, BrokerError } from "./errors";
import {
  DIGEST,
  SERVICE_IDENTITY,
  SERVICE_KEYS,
  SHA1,
  TIMESTAMP,
  VERSION,
} from "./runtime-closure-contract";
import type { TargetLineageAuthority } from "./target-lineage";
import type { JsonObject, PrivateServicePin } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";

export function targetLineageAuthority(activation: JsonObject): TargetLineageAuthority {
  return {
    baselineCommitSha: requireString(activation, "target_policy_commit_sha", 40, SHA1),
    branchRulesetEvidenceSha256: requireString(
      activation,
      "target_branch_ruleset_evidence_sha256",
      71,
      DIGEST,
    ),
    branchRulesetId: requireString(
      activation,
      "target_branch_ruleset_id",
      32,
      /^[1-9][0-9]{0,31}$/u,
    ),
    branchRulesetProjectionSha256: requireString(
      activation,
      "target_branch_ruleset_projection_sha256",
      71,
      DIGEST,
    ),
    defaultBranchRef: requireString(activation, "target_default_branch_ref", 64),
  };
}

export function service(
  observation: JsonObject,
  key: "controller_run_reader" | "governance_reader",
) {
  return serviceObject(
    exactObject(observation.services, ["controller_run_reader", "governance_reader"]),
    key,
  );
}

export function serviceObject(
  services: JsonObject,
  key: "controller_run_reader" | "governance_reader",
): JsonObject {
  return exactObject(services[key], SERVICE_KEYS);
}

export function validateService(value: JsonObject): void {
  const identity = requireString(value, "service_identity", 512, SERVICE_IDENTITY);
  const version = requireString(value, "service_version_id", 128, VERSION);
  assert(identity.endsWith(`@${version}`), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
}

export function validateServicePin(value: JsonObject, pin: PrivateServicePin): void {
  validateService(value);
  requireLiteral(value, "service_identity", pin.serviceIdentity);
  requireLiteral(value, "service_version_id", pin.versionId);
}

export function requireTimestamp(object: JsonObject, key: string): string {
  const value = requireString(object, key, 32, TIMESTAMP);
  assert(Number.isFinite(Date.parse(value)), "RUNTIME_CLOSURE_OBSERVATION_INVALID", 503);
  return value;
}

export function requireLiteral(object: JsonObject, key: string, expected: string): void {
  assert(
    requireString(object, key, Math.max(1, expected.length)) === expected,
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
}

export function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  assert(
    requireInteger(object, key, expected, expected) === expected,
    "RUNTIME_CLOSURE_OBSERVATION_INVALID",
    503,
  );
}

export function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64url(value: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(
      value
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="),
    );
  } catch {
    throw new BrokerError("RUNTIME_CLOSURE_OBSERVATION_HEADER_INVALID", 503, false);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  assert(encodeBase64url(bytes) === value, "RUNTIME_CLOSURE_OBSERVATION_HEADER_INVALID", 503);
  return bytes;
}
