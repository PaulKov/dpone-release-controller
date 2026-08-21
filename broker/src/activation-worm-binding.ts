import { CLOUDFLARE_UUID } from "./cloudflare-ids";
import { BrokerError } from "./errors";
import type { ActivationWorm, JsonObject } from "./types";
import { requireInteger, requireObject, requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const VERSION_ID = /^[A-Za-z0-9._=-]{1,512}$/u;
const RETENTION_MILLISECONDS = 2557 * 86_400_000;

/** Derive the sole deterministic activation-record object key. */
export function expectedActivationWormKey(
  envelope: JsonObject,
  digest: string,
  sequence: 0 | 1,
): string {
  if (!DIGEST.test(digest)) {
    throw new BrokerError("ACTIVATION_WORM_BINDING_INVALID", 500, false);
  }
  return [
    "receipts",
    "v1",
    "activation",
    activationIngressWorkerVersion(envelope, sequence),
    `${sequence}-${digest.slice("sha256:".length)}.json`,
  ].join("/");
}

/** Validate and normalize one WORM pointer before durable confirmation. */
export function validateActivationWorm(
  worm: ActivationWorm,
  envelope: JsonObject,
  digest: string,
  sequence: 0 | 1,
  committedAt: string,
): ActivationWorm {
  const committedAtMs = Date.parse(committedAt);
  const retentionMs = Date.parse(worm.retentionUntil);
  const canonicalRetention = Number.isFinite(retentionMs)
    ? new Date(retentionMs).toISOString()
    : "";
  if (
    worm.digest !== digest ||
    worm.key !== expectedActivationWormKey(envelope, digest, sequence) ||
    !VERSION_ID.test(worm.versionId) ||
    !Number.isFinite(committedAtMs) ||
    new Date(committedAtMs).toISOString() !== committedAt ||
    canonicalRetention !== worm.retentionUntil ||
    retentionMs < committedAtMs + RETENTION_MILLISECONDS
  ) {
    throw new BrokerError("ACTIVATION_WORM_BINDING_INVALID", 503, false);
  }
  return {
    digest,
    key: worm.key,
    retentionUntil: canonicalRetention,
    versionId: worm.versionId,
  };
}

function activationIngressWorkerVersion(envelope: JsonObject, sequence: 0 | 1): string {
  const envelopeSequence = requireInteger(envelope, "sequence", 0, 1);
  if (envelopeSequence !== sequence) {
    throw new BrokerError("ACTIVATION_WORM_BINDING_INVALID", 500, false);
  }
  if (sequence === 1) {
    const provisioned = requireObject(envelope.provisioned, "ACTIVATION_WORM_BINDING_INVALID");
    return requireString(provisioned, "worker_version_id", 36, CLOUDFLARE_UUID);
  }
  const evidence = requireObject(envelope.evidence, "ACTIVATION_WORM_BINDING_INVALID");
  const broker = requireObject(evidence.broker, "ACTIVATION_WORM_BINDING_INVALID");
  return requireString(broker, "worker_version_id", 36, CLOUDFLARE_UUID);
}
