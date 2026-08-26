import { assertActivationRecordDigest } from "./activation-schema";
import { ActivationRecordStore, type ActivationRow } from "./activation-record-store";
import {
  decodeCanonicalObject,
  digestBytes,
  requireObjectField,
} from "./activation-registry-codec";
import { requireLiveConfig } from "./config";
import { BrokerError } from "./errors";
import type { ActivationRecordView, JsonObject, LiveConfigEnv, PrivateServicePin } from "./types";
import { WormMirrorClient } from "./worm-client";

/** Append/confirm/read boundary for the two immutable activation records. */
export class ActivationRegistryRecords {
  private readonly store: ActivationRecordStore;

  public constructor(
    storage: DurableObjectStorage,
    private readonly env: LiveConfigEnv,
  ) {
    this.store = new ActivationRecordStore(storage);
  }

  public find(sequence: 0 | 1): ActivationRow | undefined {
    return this.store.find(sequence);
  }

  public append(
    sequence: 0 | 1,
    requestDigest: string,
    record: JsonObject,
    committedAt: string,
  ): Promise<ActivationRow> {
    return this.store.append(sequence, requestDigest, record, committedAt);
  }

  public requireConfirmed(sequence: 0 | 1): ActivationRow {
    return this.store.requireConfirmed(sequence);
  }

  public assertIdempotent(row: ActivationRow, requestDigest: string): void {
    this.store.assertIdempotent(row, requestDigest);
  }

  public async confirmMirror(
    row: ActivationRow,
    wormPin: PrivateServicePin,
    observerPin: PrivateServicePin,
  ): Promise<ActivationRecordView> {
    if (row.worm_version_id !== null) {
      return this.toConfirmedView(row);
    }
    const service = this.env.WORM_MIRROR;
    if (service === undefined) {
      throw new BrokerError("WORM_MIRROR_UNAVAILABLE", 503, true);
    }
    const bytes = bytesFromSql(row.canonical_bytes);
    const runtime = requireLiveConfig(this.env);
    const worm = await new WormMirrorClient(service, wormPin, observerPin, {
      key: runtime.wormRpcAuthKey,
      serviceIdentity: runtime.workerServiceIdentity,
      versionId: runtime.workerVersionId,
    }).mirrorActivation({
      bytes,
      committedAt: row.committed_at,
      digest: row.record_digest,
      recordId: row.record_id,
      sequence: asSequence(row.sequence),
    });
    this.store.confirm(asSequence(row.sequence), worm);
    return this.toConfirmedView(this.store.requireConfirmed(asSequence(row.sequence)));
  }

  public async toConfirmedView(row: ActivationRow): Promise<ActivationRecordView> {
    if (
      row.worm_key === null ||
      row.worm_version_id === null ||
      row.worm_retention_until === null
    ) {
      throw new BrokerError("ACTIVATION_WORM_PENDING", 503, true);
    }
    const bytes = bytesFromSql(row.canonical_bytes);
    const envelope = decodeCanonicalObject(bytes);
    await assertActivationRecordDigest(envelope, row.record_id);
    if ((await digestBytes(bytes)) !== row.record_digest) {
      throw new BrokerError("ACTIVATION_BYTES_DIGEST_MISMATCH", 503, false);
    }
    return {
      digest: row.record_digest,
      envelope,
      recordId: row.record_id,
      sequence: asSequence(row.sequence),
      worm: {
        digest: row.record_digest,
        key: row.worm_key,
        retentionUntil: row.worm_retention_until,
        versionId: row.worm_version_id,
      },
    };
  }

  public assertProvisionedPointer(supplied: JsonObject, provisioned: ActivationRow): void {
    if (
      supplied.record_id !== provisioned.record_id ||
      supplied.digest !== provisioned.record_digest ||
      supplied.worm_key !== provisioned.worm_key ||
      supplied.worm_version_id !== provisioned.worm_version_id
    ) {
      throw new BrokerError("ACTIVATION_PROVISIONED_POINTER_MISMATCH", 409, false);
    }
    const envelope = decodeCanonicalObject(bytesFromSql(provisioned.canonical_bytes));
    const evidence = requireObjectField(envelope, "evidence");
    const broker = requireObjectField(evidence, "broker");
    if (supplied.worker_version_id !== broker.worker_version_id) {
      throw new BrokerError("ACTIVATION_PROVISIONED_POINTER_MISMATCH", 409, false);
    }
  }
}

function bytesFromSql(value: ArrayBuffer): Uint8Array {
  return new Uint8Array(value);
}

function asSequence(value: number): 0 | 1 {
  if (value !== 0 && value !== 1) {
    throw new BrokerError("ACTIVATION_SEQUENCE_INVALID", 503, false);
  }
  return value;
}
