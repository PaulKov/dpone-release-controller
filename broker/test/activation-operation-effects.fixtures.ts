import { PROVISION_REQUEST_SCHEMA } from "../src/activation-contract";
import type { ActivationOperationIssuance } from "../src/activation-operation-contract";
import {
  ActivationOperationEffects,
  type ActivationCloudflareAnchor,
  type ActivationCloudflareBatchPins,
  type ActivationOperationExecutorPins,
} from "../src/activation-operation-effects";
import { activationOperationIdentity } from "../src/activation-operation-identity";
import { ActivationOperationStore } from "../src/activation-operation-store";
import { canonicalBytes } from "../src/canonical";
import { SERVICE_AUTHORITY_ROLES } from "../src/service-authority";
import type { ActivationWorm, JsonObject } from "../src/types";
import type { PreparedWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import { buildWormExactObjectEffectResult } from "../src/worm-exact-object-effect-result";
import {
  ACCOUNT_ID,
  OBSERVER_IDENTITY,
  OBSERVER_VERSION,
} from "./cloudflare-deployment-observer-provider.fixtures";

export const WORKER_VERSION = "11111111-1111-1111-1111-111111111111";
const EXECUTOR_VERSION = "22222222-2222-2222-2222-222222222222";
const DIRECT_OBSERVER_VERSION = "33333333-3333-3333-3333-333333333333";
const WORM_VERSION = "44444444-4444-4444-4444-444444444444";
const B2_OBSERVER_VERSION = "55555555-5555-5555-5555-555555555555";
const OBSERVED_AT = "2026-08-19T12:00:01.000Z";
const RETENTION_UNTIL = "2034-08-20T12:00:00.000Z";
const NOW = Date.parse("2026-08-19T12:00:00.000Z");

export const COMMITTED_AT = "2026-08-19T12:00:02.000Z";
export const DIRECT_SLOTS = ["CONTROLLER_OIDC", "TARGET_OIDC", "TARGET_RULESET"] as const;
export const PINS: ActivationOperationExecutorPins = {
  executorServiceIdentity: serviceIdentity("a", "effect-executor", EXECUTOR_VERSION),
  executorWorkerVersionId: EXECUTOR_VERSION,
  observerServiceIdentity: serviceIdentity("b", "effect-observer", DIRECT_OBSERVER_VERSION),
  observerWorkerVersionId: DIRECT_OBSERVER_VERSION,
};
export const DRIFTED_PINS: ActivationOperationExecutorPins = {
  ...PINS,
  observerServiceIdentity: serviceIdentity("c", "effect-observer", DIRECT_OBSERVER_VERSION),
};
export const CLOUDFLARE_PINS: ActivationCloudflareBatchPins = {
  b2ObserverServiceIdentity: serviceIdentity(
    ACCOUNT_ID,
    "worm-version-observer",
    B2_OBSERVER_VERSION,
  ),
  b2ObserverWorkerVersionId: B2_OBSERVER_VERSION,
  cloudflareObserverServiceIdentity: OBSERVER_IDENTITY,
  cloudflareObserverWorkerVersionId: OBSERVER_VERSION,
  wormServiceIdentity: serviceIdentity(ACCOUNT_ID, "worm-mirror", WORM_VERSION),
  wormWorkerVersionId: WORM_VERSION,
};

export async function operationJournal(
  storage: DurableObjectStorage,
  marker = 0,
): Promise<{
  readonly effects: ActivationOperationEffects;
  readonly issuance: ActivationOperationIssuance;
  readonly issuanceId: string;
  readonly store: ActivationOperationStore;
}> {
  const store = new ActivationOperationStore(storage, () => Date.parse(COMMITTED_AT));
  const identity = await activationOperationIdentity(provisionBody(marker), 0, WORKER_VERSION);
  const issuance = await store.reserve(identity, NOW);
  return {
    effects: new ActivationOperationEffects(storage, () => Date.parse(COMMITTED_AT)),
    issuance,
    issuanceId: issuance.issuanceId,
    store,
  };
}

export async function freeze(
  store: ActivationOperationStore,
  issuanceId: string,
  slotId: "CONTROLLER_ACTION" | (typeof DIRECT_SLOTS)[number],
  index: number,
) {
  await store.prepareRead(issuanceId, slotId, canonicalBytes({ request: index }));
  return store.freezeRead(issuanceId, slotId, canonicalBytes({ payload: index }), OBSERVED_AT);
}

export function anchorFixture(offset = 0): readonly ActivationCloudflareAnchor[] {
  return Array.from({ length: 15 }, (_, index) => {
    const recordId = digest(offset + index + 100);
    const recordSha256 = digest(offset + index + 200);
    return {
      authorityRole: SERVICE_AUTHORITY_ROLES[index] ?? null,
      recordId,
      recordSha256,
      worm: {
        digest: recordSha256,
        key:
          `receipts/v1/cloudflare-observations/${CLOUDFLARE_PINS.cloudflareObserverWorkerVersionId}/` +
          `${anchorKind(index)}/${recordId.slice("sha256:".length)}.json`,
        retentionUntil: RETENTION_UNTIL,
        versionId: `4_z-anchor-${String(offset + index).padStart(4, "0")}`,
      },
    };
  });
}

export function mutableAnchors() {
  return anchorFixture().map((anchor) => ({ ...anchor, worm: { ...anchor.worm } }));
}

export function worm(
  expectedDigest: string | null,
  slotId: (typeof DIRECT_SLOTS)[number],
  index: number,
): ActivationWorm {
  if (expectedDigest === null) throw new Error("frozen payload digest missing");
  return {
    digest: expectedDigest,
    key:
      `receipts/v1/activation-evidence/${WORKER_VERSION}/${evidenceKind(slotId)}/` +
      `${expectedDigest.slice("sha256:".length)}.json`,
    retentionUntil: RETENTION_UNTIL,
    versionId: `4_z-direct-${String(index).padStart(4, "0")}`,
  };
}

export function confirmedDirectResult(
  effect: PreparedWormExactObjectEffect,
  slotId: (typeof DIRECT_SLOTS)[number],
  index: number,
  wormOverride?: ActivationWorm,
): Uint8Array {
  return buildWormExactObjectEffectResult({
    absenceInventoryDigest: digest(index + 700),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: effect.pins,
    status: "CONFIRMED",
    worm: wormOverride ?? worm(effect.digest, slotId, index),
  });
}

export function digest(index: number): string {
  return `sha256:${index.toString(16).padStart(64, "0")}`;
}

function provisionBody(marker: number): JsonObject {
  return {
    evidence: { marker, reviewed: true },
    observed_at: "2026-08-19T12:00:00.000Z",
    request_id: "request-provision-effects-0001",
    schema: PROVISION_REQUEST_SCHEMA,
    schema_version: 1,
  };
}

function serviceIdentity(account: string, service: string, version: string): string {
  const accountId = account.length === 1 ? account.repeat(32) : account;
  return `cloudflare-worker:${accountId}/dpone-release-${service}@${version}`;
}

function anchorKind(index: number): string {
  return SERVICE_AUTHORITY_ROLES[index] === undefined
    ? "cloudflare_network_surface"
    : "cloudflare_service_deployments";
}

function evidenceKind(slotId: (typeof DIRECT_SLOTS)[number]): string {
  return slotId === "TARGET_RULESET"
    ? "github_branch_ruleset"
    : "github_oidc_subject_customization";
}
