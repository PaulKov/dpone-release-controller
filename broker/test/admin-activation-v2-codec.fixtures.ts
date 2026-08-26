import {
  ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
  ADMIN_ACTIVATION_V2_FINALIZE_PATH,
  ADMIN_ACTIVATION_V2_PROVISION_PATH,
  type AdminActivationV2CodecContext,
} from "../src/admin-activation-v2-contract";
import { ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA } from "../src/activation-record-v2-contract";
import { canonicalBytes } from "../src/canonical";
import type { JsonObject } from "../src/types";
import { compactActivationRecordV2Fixture } from "./activation-record-v2.fixtures";

export interface AdminActivationV2CodecFixture {
  readonly beginBytes: Uint8Array;
  readonly finalizeBytes: Uint8Array;
  readonly finalizeContext: AdminActivationV2CodecContext;
  readonly provisionBytes: Uint8Array;
  readonly provisionContext: AdminActivationV2CodecContext;
  readonly reissueBytes: Uint8Array;
  readonly stageBytes: Uint8Array;
  readonly workerVersionId: string;
}

let cached: Promise<AdminActivationV2CodecFixture> | undefined;

/** Build all five ingress variants from the production-valid compact v2 fixture. */
export async function adminActivationV2CodecFixture(): Promise<AdminActivationV2CodecFixture> {
  cached ??= buildFixture();
  return snapshot(await cached);
}

export function decodeFixtureObject(bytes: Uint8Array): JsonObject {
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  return object(value);
}

async function buildFixture(): Promise<AdminActivationV2CodecFixture> {
  const compact = await compactActivationRecordV2Fixture();
  const provisioned = compact.provisioned.document;
  const activated = compact.activated.document;
  const workerVersionId = string(provisioned, "worker_version_id");
  const authority = object(provisioned.component_authority);
  const descriptor = object(authority.descriptor);
  const session = object(authority.session);
  const components = compact.rawComponentBodies.map((bytes) => {
    const envelope = decodeFixtureObject(bytes);
    return {
      component_kind: string(envelope, "component_kind"),
      payload_sha256: string(envelope, "payload_sha256"),
    };
  });
  return {
    beginBytes: canonicalBytes({
      action: "BEGIN",
      components,
      schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
      schema_version: 2,
    }),
    finalizeBytes: canonicalBytes({
      approvals: cloneJson(activated.approvals),
      promotion: cloneJson(activated.promotion),
      provisioned: cloneJson(activated.provisioned),
      schema: ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA,
      schema_version: 2,
      target: cloneJson(activated.target),
    }),
    finalizeContext: Object.freeze({
      expectedWorkerVersionId: workerVersionId,
      path: ADMIN_ACTIVATION_V2_FINALIZE_PATH,
    }),
    provisionBytes: canonicalBytes({
      action: "PROVISION",
      schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
      schema_version: 2,
      selected_session_id: string(session, "session_id"),
    }),
    provisionContext: Object.freeze({
      expectedWorkerVersionId: workerVersionId,
      path: ADMIN_ACTIVATION_V2_PROVISION_PATH,
    }),
    reissueBytes: canonicalBytes({
      action: "REISSUE",
      predecessor_descriptor_id: string(descriptor, "descriptor_id"),
      predecessor_descriptor_sha256: string(descriptor, "descriptor_sha256"),
      predecessor_session_id: string(session, "session_id"),
      schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
      schema_version: 2,
    }),
    stageBytes: Uint8Array.from(compact.rawComponentBodies[0] ?? new Uint8Array()),
    workerVersionId,
  };
}

function snapshot(value: AdminActivationV2CodecFixture): AdminActivationV2CodecFixture {
  return {
    ...value,
    beginBytes: Uint8Array.from(value.beginBytes),
    finalizeBytes: Uint8Array.from(value.finalizeBytes),
    provisionBytes: Uint8Array.from(value.provisionBytes),
    reissueBytes: Uint8Array.from(value.reissueBytes),
    stageBytes: Uint8Array.from(value.stageBytes),
  };
}

function cloneJson(value: unknown): JsonObject {
  return decodeFixtureObject(canonicalBytes(object(value)));
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("admin activation v2 fixture object missing");
  }
  return value as JsonObject;
}

function string(value: JsonObject, key: string): string {
  const selected = value[key];
  if (typeof selected !== "string") {
    throw new Error(`admin activation v2 fixture ${key} missing`);
  }
  return selected;
}
