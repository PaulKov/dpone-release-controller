import {
  buildActivationOperationCloudflareRequest,
  parseActivationOperationCloudflareRequest,
  type ActivationOperationCloudflareRequest,
} from "../src/activation-operation-cloudflare-request";
import { canonicalBytes } from "../src/canonical";
import {
  cloudflareEvidenceWormKeyV2,
  type CloudflareEvidenceBatchContext,
  type CloudflareEvidenceBatchSlot,
} from "../src/cloudflare-evidence-batch-contract";
import { buildCloudflareEvidenceBatchResultV2 } from "../src/cloudflare-evidence-batch-result-v2";
import {
  buildCloudflareEvidenceBatchRequestV2,
  prepareCloudflareEvidenceBatchV2,
} from "../src/cloudflare-evidence-batch-rpc";
import { CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA } from "../src/cloudflare-deployment-observation";
import type { ServiceAuthorityRole } from "../src/service-authority";
import type { JsonObject } from "../src/types";
import {
  CLOUDFLARE_PINS,
  COMMITTED_AT,
  DIRECT_SLOTS,
  PINS,
  WORKER_VERSION,
  confirmedDirectResult,
  freeze,
} from "./activation-operation-effects.fixtures";
import type { operationJournal } from "./activation-operation-effects.fixtures";
import { cloudflareEvidenceBatchFixture } from "./cloudflare-evidence-batch.fixtures";
import {
  NETWORK_SURFACE,
  NOW,
  authorityInventory,
} from "./cloudflare-deployment-observer-provider.fixtures";

export const CLOUDFLARE_DELEGATED_AT = COMMITTED_AT;
export const CLOUDFLARE_OBSERVED_AT = new Date(NOW + 3_000).toISOString();
export const CLOUDFLARE_BATCH_SEALED_AT = new Date(NOW + 4_000).toISOString();

type OperationJournal = Awaited<ReturnType<typeof operationJournal>>;

export interface ActivationOperationCloudflareFixture {
  readonly anchorKeys: readonly string[];
  readonly delegation: ActivationOperationCloudflareRequest;
  readonly innerRequest: JsonObject;
  readonly outerRequestBytes: Uint8Array;
  readonly resultBytes: Uint8Array;
  readonly resultDocument: JsonObject;
}

export type CloudflareResultMutation =
  | "DROP_RECORD"
  | "DUPLICATE_RECORD"
  | "PIN_DRIFT"
  | "RESULT_DRIFT"
  | "SWAP_RECORDS";

export async function activationOperationCloudflareFixture(
  journal: OperationJournal,
): Promise<ActivationOperationCloudflareFixture> {
  const phase = journal.issuance.sequence === 0 ? "A0_PRE" : "A1_PRECOMMIT";
  const evidence = await cloudflareEvidenceBatchFixture(phase, Date.parse(CLOUDFLARE_OBSERVED_AT));
  const observerRequest = await operationObserverRequest(
    journal.issuance.internalRequestId,
    evidence.expectedDeployments,
    evidence.binding.expectationSha256,
    phase,
  );
  const expectedIssuance = {
    ingressWorkerVersionId: WORKER_VERSION,
    internalRequestId: journal.issuance.internalRequestId,
    issuanceId: journal.issuance.issuanceId,
    issuedAt: journal.issuance.issuedAt,
    ordinal: journal.issuance.ordinal,
    sequence: journal.issuance.sequence,
    freshUntil: journal.issuance.freshUntil,
  };
  const outerRequestBytes = await buildActivationOperationCloudflareRequest({
    committedAt: CLOUDFLARE_DELEGATED_AT,
    issuance: expectedIssuance,
    observerRequest,
    pins: CLOUDFLARE_PINS,
  });
  const delegation = await parseActivationOperationCloudflareRequest(
    outerRequestBytes,
    expectedIssuance,
  );
  const innerRequest = buildCloudflareEvidenceBatchRequestV2(
    evidence.transientResult,
    delegation,
    CLOUDFLARE_BATCH_SEALED_AT,
  );
  const prepared = await prepareCloudflareEvidenceBatchV2(innerRequest);
  const context = batchContext(prepared, delegation);
  const slots = confirmedSlots(prepared.slots, delegation);
  const resultDocument = buildCloudflareEvidenceBatchResultV2(context, slots);
  return {
    anchorKeys: slots.map((slot) => {
      if (slot.worm === null) throw new Error("confirmed fixture WORM missing");
      return slot.worm.key;
    }),
    delegation,
    innerRequest,
    outerRequestBytes,
    resultBytes: canonicalBytes(resultDocument),
    resultDocument,
  };
}

export async function prepareCloudflarePredecessors(
  storage: DurableObjectStorage,
  journal: OperationJournal,
): Promise<void> {
  const controller = slotState(storage, journal.issuanceId, "CONTROLLER_ACTION");
  if (controller === "PREPARED") {
    await freeze(journal.store, journal.issuanceId, "CONTROLLER_ACTION", 790);
  }
  for (const [index, slotId] of DIRECT_SLOTS.entries()) {
    let state = slotState(storage, journal.issuanceId, slotId);
    if (state === "PREPARED") {
      await freeze(journal.store, journal.issuanceId, slotId, 800 + index);
      state = "FROZEN";
    }
    if (state === "CONFIRMED") continue;
    const delegated = await journal.effects.delegate(
      journal.issuanceId,
      slotId,
      COMMITTED_AT,
      PINS,
    );
    await journal.effects.confirmDirect(
      journal.issuanceId,
      slotId,
      confirmedDirectResult(delegated.effect, slotId, 900 + index),
    );
  }
}

export function mutatedCloudflareResultBytes(
  fixture: ActivationOperationCloudflareFixture,
  mutation: CloudflareResultMutation,
): Uint8Array {
  const document = structuredClone(fixture.resultDocument);
  const records = requireArray(document.records);
  if (mutation === "DROP_RECORD") records.pop();
  if (mutation === "DUPLICATE_RECORD") records[1] = structuredClone(requireObject(records[0]));
  if (mutation === "SWAP_RECORDS") {
    const first = requireObject(records[0]);
    const second = requireObject(records[1]);
    records[0] = second;
    records[1] = first;
  }
  if (mutation === "RESULT_DRIFT") {
    document.delegation_sha256 = `${fixture.delegation.delegationSha256.slice(0, -1)}0`;
  }
  if (mutation === "PIN_DRIFT") {
    const pins = requireObject(document.pins);
    const observer = requireObject(pins.cloudflare_observer);
    const version = "66666666-6666-6666-6666-666666666666";
    const accountId = CLOUDFLARE_PINS.cloudflareObserverServiceIdentity
      .split(":")[1]
      ?.split("/")[0];
    if (accountId === undefined) throw new Error("fixture Cloudflare account missing");
    observer.service_identity = `cloudflare-worker:${accountId}/dpone-release-cloudflare-deployment-observer@${version}`;
    observer.worker_version_id = version;
  }
  return canonicalBytes(document);
}

async function operationObserverRequest(
  requestId: string,
  expectedDeployments: Awaited<
    ReturnType<typeof cloudflareEvidenceBatchFixture>
  >["expectedDeployments"],
  expectationSha256: string,
  phase: "A0_PRE" | "A1_PRECOMMIT",
): Promise<JsonObject> {
  const inventory = (await authorityInventory()).map((row) => {
    const pin = authorityPin(row.authority_role);
    return pin === undefined
      ? { ...row }
      : { ...row, service_identity: pin.serviceIdentity, worker_version_id: pin.workerVersionId };
  });
  return {
    expected_deployments: expectedDeployments.map((deployment) => ({
      ...deployment,
      deployment_versions: deployment.deployment_versions.map((version) => ({ ...version })),
    })),
    expectation_sha256: expectationSha256,
    expected_network_surface: { ...NETWORK_SURFACE },
    phase,
    request_id: requestId,
    requested_at: CLOUDFLARE_DELEGATED_AT,
    schema: CLOUDFLARE_DEPLOYMENT_REQUEST_SCHEMA,
    schema_version: 1,
    service_authority_inventory: inventory,
  };
}

function authorityPin(
  role: ServiceAuthorityRole,
): { readonly serviceIdentity: string; readonly workerVersionId: string } | undefined {
  if (role === "cloudflare_deployment_observer") {
    return {
      serviceIdentity: CLOUDFLARE_PINS.cloudflareObserverServiceIdentity,
      workerVersionId: CLOUDFLARE_PINS.cloudflareObserverWorkerVersionId,
    };
  }
  if (role === "worm_mirror") {
    return {
      serviceIdentity: CLOUDFLARE_PINS.wormServiceIdentity,
      workerVersionId: CLOUDFLARE_PINS.wormWorkerVersionId,
    };
  }
  if (role === "worm_version_observer") {
    return {
      serviceIdentity: CLOUDFLARE_PINS.b2ObserverServiceIdentity,
      workerVersionId: CLOUDFLARE_PINS.b2ObserverWorkerVersionId,
    };
  }
  if (role === "release_authority_ingress") {
    const accountId = CLOUDFLARE_PINS.cloudflareObserverServiceIdentity
      .split(":")[1]
      ?.split("/")[0];
    if (accountId === undefined) throw new Error("fixture Cloudflare account missing");
    return {
      serviceIdentity: `cloudflare-worker:${accountId}/dpone-release-authority-broker@${WORKER_VERSION}`,
      workerVersionId: WORKER_VERSION,
    };
  }
  return undefined;
}

function batchContext(
  prepared: Awaited<ReturnType<typeof prepareCloudflareEvidenceBatchV2>>,
  delegation: ActivationOperationCloudflareRequest,
): CloudflareEvidenceBatchContext {
  const providerObservationSha256 = prepared.observation.provider_observation_sha256;
  if (typeof providerObservationSha256 !== "string") {
    throw new Error("provider observation digest missing");
  }
  return {
    binding: prepared.binding,
    committedAt: prepared.batchSealedAt,
    execution: {
      b2ObserverServiceIdentity: delegation.pins.b2ObserverServiceIdentity,
      b2ObserverWorkerVersionId: delegation.pins.b2ObserverWorkerVersionId,
      wormServiceIdentity: delegation.pins.wormServiceIdentity,
      wormWorkerVersionId: delegation.pins.wormWorkerVersionId,
    },
    observation: prepared.observation,
    observedAt: prepared.observedAt,
    operation: {
      authorityPins: { ...delegation.pins },
      committedAt: delegation.committedAt,
      delegationSha256: delegation.delegationSha256,
      freshUntil: delegation.freshUntil,
      issuedAt: delegation.issuance.issuedAt,
    },
    providerObservationSha256,
  };
}

function confirmedSlots(
  inputs: Awaited<ReturnType<typeof prepareCloudflareEvidenceBatchV2>>["slots"],
  delegation: ActivationOperationCloudflareRequest,
): readonly CloudflareEvidenceBatchSlot[] {
  return inputs.map((input) => {
    const key = cloudflareEvidenceWormKeyV2(
      delegation.binding.observerWorkerVersionId,
      delegation.binding.batchId,
      input.kind,
      input.sanitized.recordId,
    );
    return {
      ...input,
      committedAt: CLOUDFLARE_BATCH_SEALED_AT,
      expectedWormKey: key,
      status: "CONFIRMED",
      writerVersionId: null,
      worm: {
        digest: input.sanitized.recordSha256,
        key,
        retentionUntil: "2034-08-20T12:00:00.000Z",
        versionId: `4_z-v2-${String(input.slotIndex).padStart(4, "0")}`,
      },
    };
  });
}

function slotState(storage: DurableObjectStorage, issuanceId: string, slotId: string): string {
  return storage.sql
    .exec<{
      readonly state: string;
    }>(
      `SELECT state FROM activation_operation_slots WHERE issuance_id = ? AND slot_id = ?`,
      issuanceId,
      slotId,
    )
    .one().state;
}

function requireArray(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) throw new Error("fixture result records missing");
  value.forEach(requireObject);
  return value as JsonObject[];
}

function requireObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("fixture result object missing");
  }
  return value as JsonObject;
}
