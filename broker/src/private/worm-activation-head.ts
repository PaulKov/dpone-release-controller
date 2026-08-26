import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  parseActivatedAuthorityHead,
} from "../activated-authority-head";
import { B2VersionObserverClient } from "../b2-version-observer-client";
import { B2ExactObjectMirror } from "../b2";
import { canonicalJson } from "../canonical";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import { requireInteger, requireString } from "../validation";
import { B2NativeWriter } from "./b2-native";
import {
  TAGGED_DIGEST,
  TIMESTAMP,
  VERSION,
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  canonicalResponse,
  exactHeader,
  observerPinFromHeaders,
  requireConfig,
  requireVersionId,
} from "./worm-mirror-worker-helpers";

/** Independently reparses and mirrors one canonical global-head witness. */
export async function mirrorActivatedAuthorityHead(
  envelope: JsonObject,
  headers: Headers,
  env: WormMirrorEnv,
): Promise<Response> {
  const head = await parseActivatedAuthorityHead(envelope);
  const digest = await activatedAuthorityHeadRecordSha256(head);
  const key = await activatedAuthorityHeadKey(head);
  exactHeaderEquals(headers, "x-dpone-canonical-sha256", digest, TAGGED_DIGEST, 71);
  exactHeaderEquals(
    headers,
    "x-dpone-committed-at",
    requireString(head, "committed_at", 32, TIMESTAMP),
    TIMESTAMP,
    32,
  );
  exactHeaderEquals(
    headers,
    "x-dpone-generation",
    String(requireInteger(head, "generation", 1)),
    /^[1-9][0-9]{0,15}$/u,
    16,
  );
  exactHeaderEquals(
    headers,
    "x-dpone-ingress-worker-version",
    requireString(head, "ingress_worker_version_id", 36, VERSION),
    VERSION,
    36,
  );
  exactHeaderEquals(
    headers,
    "x-dpone-record-id",
    requireString(head, "record_id", 71, TAGGED_DIGEST),
    TAGGED_DIGEST,
    71,
  );
  const observer = env.WORM_VERSION_OBSERVER;
  if (observer === undefined || typeof observer.fetch !== "function") {
    throw new BrokerError("B2_OBSERVER_UNAVAILABLE", 503, true);
  }
  const observerPin = observerPinFromHeaders(headers);
  assertExpectedB2ObserverPin(observerPin, env);
  const result = await new B2ExactObjectMirror(
    new B2NativeWriter(requireConfig(env)),
    new B2VersionObserverClient(observer, observerPin),
  ).mirror({
    canonicalBytes: new TextEncoder().encode(canonicalJson(head)),
    committedAt: requireString(head, "committed_at", 32, TIMESTAMP),
    digest,
    key,
  });
  return canonicalResponse({
    digest: result.digest,
    key: result.key,
    kind: "activation_head",
    retention_until: result.retentionUntil,
    schema: "dpone.release-worm-mirror-result.v1",
    version_id: result.versionId,
    worker_version_id: requireVersionId(env),
  });
}

function exactHeaderEquals(
  headers: Headers,
  name: string,
  expected: string,
  pattern: RegExp,
  maximum: number,
): void {
  if (exactHeader(headers, name, pattern, maximum) !== expected) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_WORM_BINDING_INVALID", 400, false);
  }
}
