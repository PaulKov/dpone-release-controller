import { canonicalBytes, canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import { parseStrictJsonObject } from "./strict-json";
import type { ActivationWorm, JsonObject } from "./types";
import { exactObject, requireInteger, requireString } from "./validation";
import {
  canonicalEffectTimestamp,
  type ConfirmedWormExactObjectEffect,
  type PreparedWormExactObjectEffect,
  type WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

export const WORM_EXACT_OBJECT_EFFECT_RESULT_SCHEMA = "dpone.worm-exact-object-effect-result.v1";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const VERSION = /^[A-Za-z0-9._=-]{1,512}$/u;
const MAX_RESULT_BYTES = 65_536;
const MINIMUM_RETENTION_MS = 2_557 * 86_400_000;

/** Canonical private RPC result; body bytes remain in the sealed journal, not in this envelope. */
export function buildWormExactObjectEffectResult(
  confirmed: ConfirmedWormExactObjectEffect,
): Uint8Array {
  return canonicalBytes(resultProjection(confirmed));
}

/** Parse one exact result and bind it to the prepared immutable effect. */
export function parseWormExactObjectEffectResult(
  bytes: Uint8Array,
  expected: PreparedWormExactObjectEffect,
): ConfirmedWormExactObjectEffect {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_RESULT_BYTES) resultFail();
  const owned = Uint8Array.from(bytes);
  const result = exactObject(
    parseStrictJsonObject(owned, "WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID"),
    [
      "absence_inventory_sha256",
      "committed_at",
      "digest",
      "effect_id",
      "key",
      "pins",
      "schema",
      "schema_version",
      "status",
      "worm",
    ],
  );
  const text = new TextDecoder("utf-8", { fatal: true }).decode(owned);
  if (text !== canonicalJson(result)) resultFail();
  requireLiteral(result, "schema", WORM_EXACT_OBJECT_EFFECT_RESULT_SCHEMA);
  requireExactInteger(result, "schema_version", 1);
  requireLiteral(result, "status", "CONFIRMED");
  const pins = parsePins(result.pins);
  const committedAt = canonicalEffectTimestamp(requireString(result, "committed_at", 24));
  const worm = parseWorm(result.worm, expected.digest, expected.key, committedAt);
  const absenceInventoryDigest = requireString(result, "absence_inventory_sha256", 71, DIGEST);
  if (
    result.effect_id !== expected.effectId ||
    result.digest !== expected.digest ||
    result.key !== expected.key ||
    committedAt !== expected.committedAt ||
    canonicalJson(pins) !== canonicalJson(expected.pins)
  ) {
    resultFail("WORM_EXACT_OBJECT_EFFECT_RESULT_BINDING_INVALID");
  }
  return {
    absenceInventoryDigest,
    committedAt,
    digest: expected.digest,
    effectId: expected.effectId,
    key: expected.key,
    pins: expected.pins,
    status: "CONFIRMED",
    worm,
  };
}

function resultProjection(confirmed: ConfirmedWormExactObjectEffect): JsonObject {
  return {
    absence_inventory_sha256: confirmed.absenceInventoryDigest,
    committed_at: confirmed.committedAt,
    digest: confirmed.digest,
    effect_id: confirmed.effectId,
    key: confirmed.key,
    pins: pinsProjection(confirmed.pins),
    schema: WORM_EXACT_OBJECT_EFFECT_RESULT_SCHEMA,
    schema_version: 1,
    status: confirmed.status,
    worm: {
      digest: confirmed.worm.digest,
      key: confirmed.worm.key,
      retention_until: confirmed.worm.retentionUntil,
      version_id: confirmed.worm.versionId,
    },
  };
}

function parsePins(value: unknown): WormExactObjectEffectPins {
  const pins = exactObject(value, [
    "executor_service_identity",
    "executor_version_id",
    "observer_service_identity",
    "observer_version_id",
  ]);
  return {
    executorServiceIdentity: requireString(pins, "executor_service_identity", 512),
    executorVersionId: requireString(pins, "executor_version_id", 36),
    observerServiceIdentity: requireString(pins, "observer_service_identity", 512),
    observerVersionId: requireString(pins, "observer_version_id", 36),
  };
}

function pinsProjection(pins: WormExactObjectEffectPins): JsonObject {
  return {
    executor_service_identity: pins.executorServiceIdentity,
    executor_version_id: pins.executorVersionId,
    observer_service_identity: pins.observerServiceIdentity,
    observer_version_id: pins.observerVersionId,
  };
}

function parseWorm(
  value: unknown,
  expectedDigest: string,
  expectedKey: string,
  committedAt: string,
): ActivationWorm {
  const worm = exactObject(value, ["digest", "key", "retention_until", "version_id"]);
  const retentionUntil = canonicalEffectTimestamp(requireString(worm, "retention_until", 24));
  if (
    worm.digest !== expectedDigest ||
    worm.key !== expectedKey ||
    Date.parse(retentionUntil) < Date.parse(committedAt) + MINIMUM_RETENTION_MS
  ) {
    resultFail();
  }
  return {
    digest: expectedDigest,
    key: expectedKey,
    retentionUntil,
    versionId: requireString(worm, "version_id", 512, VERSION),
  };
}

function requireLiteral(object: JsonObject, key: string, expected: string): void {
  if (requireString(object, key, expected.length) !== expected) resultFail();
}

function requireExactInteger(object: JsonObject, key: string, expected: number): void {
  if (requireInteger(object, key, expected, expected) !== expected) resultFail();
}

function resultFail(code = "WORM_EXACT_OBJECT_EFFECT_RESULT_INVALID"): never {
  throw new BrokerError(code, 409, false);
}
