import type { ActivationOperationRecordMaterializer } from "../src/activation-operation-record-lifecycle";
import type { ActivationOperationRecordSource } from "../src/activation-operation-record-source";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { JsonObject } from "../src/types";
import { buildWormExactObjectEffectResult } from "../src/worm-exact-object-effect-result";
import type { PreparedWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import {
  activationOperationCloudflareFixture,
  prepareCloudflarePredecessors,
} from "./activation-operation-cloudflare.fixtures";
import { operationJournal, WORKER_VERSION } from "./activation-operation-effects.fixtures";
import { privateServices } from "./activation-schema-topology.fixtures";

export async function readyRecordJournal(storage: DurableObjectStorage) {
  const journal = await operationJournal(storage);
  await prepareCloudflarePredecessors(storage, journal);
  const cloudflare = await activationOperationCloudflareFixture(journal);
  await journal.effects.delegateCloudflare(journal.issuanceId, cloudflare.outerRequestBytes);
  await journal.effects.confirmCloudflare(journal.issuanceId, cloudflare.resultBytes);
  if (!journal.effects.readyToAppend(journal.issuanceId)) {
    throw new Error("operation fixture did not become record-ready");
  }
  return journal;
}

export function recordMaterializer(
  onMaterialize?: (source: ActivationOperationRecordSource) => void,
) {
  let calls = 0;
  const materializer: ActivationOperationRecordMaterializer = {
    materialize: async (source) => {
      calls += 1;
      onMaterialize?.(source);
      return provisionedRecord(source);
    },
  };
  return { calls: () => calls, materializer };
}

export function confirmedRecordWormResult(effect: PreparedWormExactObjectEffect): Uint8Array {
  return buildWormExactObjectEffectResult({
    absenceInventoryDigest: tagged(901),
    committedAt: effect.committedAt,
    digest: effect.digest,
    effectId: effect.effectId,
    key: effect.key,
    pins: effect.pins,
    status: "CONFIRMED",
    worm: {
      digest: effect.digest,
      key: effect.key,
      retentionUntil: "2034-08-20T12:00:04.000Z",
      versionId: "4_z-activation-record-0001",
    },
  });
}

async function provisionedRecord(source: ActivationOperationRecordSource): Promise<JsonObject> {
  const committedAt = source.issuance.record_committed_at;
  if (committedAt === null) throw new Error("record committed_at fixture missing");
  const withoutId: JsonObject = {
    committed_at: committedAt,
    evidence: {
      broker: {
        cloudflare_account_id: "0".repeat(32),
        private_services: privateServices(),
        worker_version_id: WORKER_VERSION,
      },
      controller: {},
      github_apps: {},
      oidc: {},
      service_authorities: {},
      target_governance: {},
    },
    fencing_token: 1,
    observed_at: committedAt,
    previous: "GENESIS",
    request_id: source.issuance.internal_request_id,
    schema: "dpone.release-broker-provisioned.v1",
    schema_version: 1,
    sequence: 0,
  };
  return {
    ...withoutId,
    record_id: `sha256:${await sha256Hex(canonicalBytes(withoutId))}`,
  };
}

function tagged(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}
