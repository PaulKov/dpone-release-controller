import { FINALIZE_REQUEST_SCHEMA, PROVISION_REQUEST_SCHEMA } from "./activation-contract";
import {
  activationJsonBudget,
  activationLiteral,
  activationString,
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
  exactActivationObject,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
  ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
  ACTIVATION_COMPONENT_ENVELOPE_SCHEMA,
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
  ACTIVATION_COMPONENT_PROFILE,
  ACTIVATION_COMPONENT_SEQUENCE,
  type ActivationComponentDigestInput,
  type ActivationComponentKind,
} from "./activation-component-contract";
import { validateActivationRecordV2Finalize } from "./activation-record-v2-finalize";
import {
  activationRecordV2Budget,
  exactRecordV2Object,
  freezeRecordV2Json,
  recordV2Literal,
} from "./activation-record-v2-codec";
import { ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA } from "./activation-record-v2-contract";
import {
  ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES,
  ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
  ADMIN_ACTIVATION_V2_FINALIZE_PATH,
  ADMIN_ACTIVATION_V2_PROVISION_PATH,
  type AdminActivationV2Begin,
  type AdminActivationV2CodecContext,
  type AdminActivationV2Finalize,
  type AdminActivationV2Provision,
  type AdminActivationV2Reissue,
  type AdminActivationV2Stage,
  type UntrustedAdminActivationV2Ingress,
} from "./admin-activation-v2-contract";
import { decodeCanonicalAdminActivationV2Body } from "./admin-activation-v2-canonical";
import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

const COMMAND_BASE_FIELDS = ["action", "schema", "schema_version"] as const;
const BEGIN_FIELDS = [...COMMAND_BASE_FIELDS, "components"] as const;
const REISSUE_FIELDS = [
  ...COMMAND_BASE_FIELDS,
  "predecessor_descriptor_id",
  "predecessor_descriptor_sha256",
  "predecessor_session_id",
] as const;
const PROVISION_FIELDS = [...COMMAND_BASE_FIELDS, "selected_session_id"] as const;
const COMPONENT_DIGEST_FIELDS = ["component_kind", "payload_sha256"] as const;
const STAGE_FIELDS = [
  "activation_sequence",
  "component_id",
  "component_kind",
  "component_profile",
  "component_set_descriptor_id",
  "component_set_descriptor_sha256",
  "component_set_id",
  "payload",
  "payload_sha256",
  "schema",
  "schema_version",
  "worker_version_id",
] as const;
const FINALIZE_FIELDS = [
  "approvals",
  "promotion",
  "provisioned",
  "schema",
  "schema_version",
  "target",
] as const;
const LEGACY_SCHEMAS = new Set([PROVISION_REQUEST_SCHEMA, FINALIZE_REQUEST_SCHEMA]);

/**
 * Decode one canonical candidate v2 admin body under explicit route and Worker context.
 * Authentication, transport headers, replay, persistence, and provider effects are out of scope.
 */
export function parseAdminActivationV2Ingress(
  input: unknown,
  context: AdminActivationV2CodecContext,
): UntrustedAdminActivationV2Ingress {
  const trusted = snapshotContext(context);
  const decoded = decodeCanonicalAdminActivationV2Body(input);
  const schema = decoded.document.schema;
  if (typeof schema === "string" && LEGACY_SCHEMAS.has(schema)) {
    fail("ADMIN_ACTIVATION_V1_SCHEMA_FORBIDDEN");
  }
  if (schema === ADMIN_ACTIVATION_V2_COMMAND_SCHEMA) {
    requirePath(trusted.path, ADMIN_ACTIVATION_V2_PROVISION_PATH);
    return parseCommand(decoded.bytes, decoded.document);
  }
  if (schema === ACTIVATION_COMPONENT_ENVELOPE_SCHEMA) {
    requirePath(trusted.path, ADMIN_ACTIVATION_V2_PROVISION_PATH);
    return parseStage(decoded.bytes, decoded.document, trusted.expectedWorkerVersionId);
  }
  if (schema === ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA) {
    requirePath(trusted.path, ADMIN_ACTIVATION_V2_FINALIZE_PATH);
    return parseFinalize(decoded.bytes, decoded.document, trusted.expectedWorkerVersionId);
  }
  fail("ADMIN_ACTIVATION_V2_SCHEMA_INVALID");
}

function parseCommand(
  bytes: Uint8Array,
  document: JsonObject,
): AdminActivationV2Begin | AdminActivationV2Provision | AdminActivationV2Reissue {
  if (bytes.byteLength > ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES) {
    fail("ADMIN_ACTIVATION_V2_COMMAND_SIZE_INVALID", 413);
  }
  const action = document.action;
  if (action === "BEGIN") return parseBegin(bytes, document);
  if (action === "REISSUE") return parseReissue(bytes, document);
  if (action === "PROVISION") return parseProvision(bytes, document);
  fail("ADMIN_ACTIVATION_V2_ACTION_INVALID");
}

function parseBegin(bytes: Uint8Array, value: JsonObject): AdminActivationV2Begin {
  const document = commandObject(value, BEGIN_FIELDS);
  const candidates = document.components;
  if (!Array.isArray(candidates) || candidates.length !== ACTIVATION_COMPONENT_KINDS.length) {
    fail("ADMIN_ACTIVATION_V2_BEGIN_INVALID");
  }
  const components = candidates.map((candidate, index): ActivationComponentDigestInput => {
    const entry = exactObject(
      candidate,
      COMPONENT_DIGEST_FIELDS,
      "ADMIN_ACTIVATION_V2_BEGIN_INVALID",
    );
    const componentKind = ACTIVATION_COMPONENT_KINDS[index];
    if (componentKind === undefined || entry.component_kind !== componentKind) {
      fail("ADMIN_ACTIVATION_V2_BEGIN_INVALID");
    }
    return Object.freeze({
      componentKind,
      payloadSha256: stringField(
        entry,
        "payload_sha256",
        ACTIVATION_COMPONENT_DIGEST,
        "ADMIN_ACTIVATION_V2_BEGIN_INVALID",
      ),
    });
  });
  return parsed(bytes, {
    action: "BEGIN" as const,
    components: Object.freeze(components),
    schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
  });
}

function parseReissue(bytes: Uint8Array, value: JsonObject): AdminActivationV2Reissue {
  const document = commandObject(value, REISSUE_FIELDS);
  return parsed(bytes, {
    action: "REISSUE" as const,
    predecessorDescriptorId: digestField(document, "predecessor_descriptor_id"),
    predecessorDescriptorSha256: digestField(document, "predecessor_descriptor_sha256"),
    predecessorSessionId: digestField(document, "predecessor_session_id"),
    schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
  });
}

function parseProvision(bytes: Uint8Array, value: JsonObject): AdminActivationV2Provision {
  const document = commandObject(value, PROVISION_FIELDS);
  return parsed(bytes, {
    action: "PROVISION" as const,
    schema: ADMIN_ACTIVATION_V2_COMMAND_SCHEMA,
    selectedSessionId: digestField(document, "selected_session_id"),
  });
}

function parseStage(
  bytes: Uint8Array,
  value: JsonObject,
  expectedWorkerVersionId: string,
): AdminActivationV2Stage {
  activationJsonBudget(value, componentEnvelopeLimits(), "ADMIN_ACTIVATION_V2_STAGE_INVALID");
  const document = exactActivationObject(value, STAGE_FIELDS, "ADMIN_ACTIVATION_V2_STAGE_INVALID");
  activationLiteral(
    document,
    "schema",
    ACTIVATION_COMPONENT_ENVELOPE_SCHEMA,
    "ADMIN_ACTIVATION_V2_STAGE_INVALID",
  );
  activationLiteral(document, "schema_version", 2, "ADMIN_ACTIVATION_V2_STAGE_INVALID");
  activationLiteral(
    document,
    "activation_sequence",
    ACTIVATION_COMPONENT_SEQUENCE,
    "ADMIN_ACTIVATION_V2_STAGE_INVALID",
  );
  activationLiteral(
    document,
    "component_profile",
    ACTIVATION_COMPONENT_PROFILE,
    "ADMIN_ACTIVATION_V2_STAGE_INVALID",
  );
  const componentKind = document.component_kind;
  if (
    typeof componentKind !== "string" ||
    !ACTIVATION_COMPONENT_KINDS.includes(componentKind as ActivationComponentKind)
  ) {
    fail("ADMIN_ACTIVATION_V2_STAGE_INVALID");
  }
  const payload = document.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    fail("ADMIN_ACTIVATION_V2_STAGE_INVALID");
  }
  activationJsonBudget(payload, componentPayloadLimits(), "ADMIN_ACTIVATION_V2_STAGE_INVALID");
  const workerVersionId = activationString(
    document,
    "worker_version_id",
    ACTIVATION_COMPONENT_WORKER_VERSION,
    "ADMIN_ACTIVATION_V2_STAGE_INVALID",
  );
  if (workerVersionId !== expectedWorkerVersionId) {
    fail("ADMIN_ACTIVATION_V2_WORKER_VERSION_MISMATCH");
  }
  return parsed(bytes, {
    action: "STAGE" as const,
    componentKind: componentKind as ActivationComponentKind,
    descriptorId: activationString(
      document,
      "component_set_descriptor_id",
      ACTIVATION_COMPONENT_DIGEST,
      "ADMIN_ACTIVATION_V2_STAGE_INVALID",
    ),
    descriptorSha256: activationString(
      document,
      "component_set_descriptor_sha256",
      ACTIVATION_COMPONENT_DIGEST,
      "ADMIN_ACTIVATION_V2_STAGE_INVALID",
    ),
    schema: ACTIVATION_COMPONENT_ENVELOPE_SCHEMA,
    setId: activationString(
      document,
      "component_set_id",
      ACTIVATION_COMPONENT_DIGEST,
      "ADMIN_ACTIVATION_V2_STAGE_INVALID",
    ),
    workerVersionId,
  });
}

function parseFinalize(
  bytes: Uint8Array,
  value: JsonObject,
  expectedWorkerVersionId: string,
): AdminActivationV2Finalize {
  try {
    activationRecordV2Budget(value);
    const request = exactRecordV2Object(value, FINALIZE_FIELDS);
    recordV2Literal(request, "schema", ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA);
    recordV2Literal(request, "schema_version", 2);
    validateActivationRecordV2Finalize(request, expectedWorkerVersionId);
    return parsed(bytes, {
      action: "FINALIZE" as const,
      request: freezeRecordV2Json(request),
      schema: ACTIVATION_FINALIZE_REQUEST_V2_SCHEMA,
      workerVersionId: expectedWorkerVersionId,
    });
  } catch (error) {
    if (error instanceof BrokerError && error.code.startsWith("ADMIN_ACTIVATION_V2_")) throw error;
    fail(
      "ADMIN_ACTIVATION_V2_FINALIZE_INVALID",
      error instanceof BrokerError && error.status === 413 ? 413 : 409,
    );
  }
}

function commandObject(value: JsonObject, fields: readonly string[]): JsonObject {
  const document = exactObject(value, fields, "ADMIN_ACTIVATION_V2_COMMAND_INVALID");
  if (document.schema !== ADMIN_ACTIVATION_V2_COMMAND_SCHEMA || document.schema_version !== 2) {
    fail("ADMIN_ACTIVATION_V2_COMMAND_INVALID");
  }
  return document;
}

function exactObject(value: unknown, fields: readonly string[], code: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const document = value as JsonObject;
  const actual = Object.keys(document).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index]))
    fail(code);
  return document;
}

function stringField(document: JsonObject, key: string, pattern: RegExp, code: string): string {
  const value = document[key];
  pattern.lastIndex = 0;
  if (typeof value !== "string" || pattern.exec(value)?.[0] !== value) fail(code);
  return value;
}

function digestField(document: JsonObject, key: string): string {
  return stringField(
    document,
    key,
    ACTIVATION_COMPONENT_DIGEST,
    "ADMIN_ACTIVATION_V2_COMMAND_INVALID",
  );
}

function parsed<T extends object>(
  bytes: Uint8Array,
  fields: T,
): T & { readonly canonicalBytes: Uint8Array; readonly trust: "UNTRUSTED" } {
  const owned = Uint8Array.from(bytes);
  return Object.freeze({
    ...fields,
    get canonicalBytes(): Uint8Array {
      return Uint8Array.from(owned);
    },
    trust: "UNTRUSTED" as const,
  });
}

function snapshotContext(context: AdminActivationV2CodecContext): AdminActivationV2CodecContext {
  const expectedWorkerVersionId: unknown = context.expectedWorkerVersionId;
  const path: unknown = context.path;
  if (
    typeof expectedWorkerVersionId !== "string" ||
    !ACTIVATION_COMPONENT_WORKER_VERSION.test(expectedWorkerVersionId) ||
    (path !== ADMIN_ACTIVATION_V2_PROVISION_PATH && path !== ADMIN_ACTIVATION_V2_FINALIZE_PATH)
  ) {
    throw new BrokerError("ADMIN_ACTIVATION_V2_CONTEXT_INVALID", 500, false);
  }
  return Object.freeze({ expectedWorkerVersionId, path });
}

function requirePath(actual: string, expected: string): void {
  if (actual !== expected) fail("ADMIN_ACTIVATION_V2_ROUTE_SCHEMA_MISMATCH");
}

function componentEnvelopeLimits() {
  return {
    bytes: ACTIVATION_COMPONENT_ENVELOPE_MAX_BYTES,
    depth: ACTIVATION_COMPONENT_MAX_DEPTH,
    maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
    nodes: ACTIVATION_COMPONENT_ENVELOPE_MAX_NODES,
  };
}

function componentPayloadLimits() {
  return {
    bytes: ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
    depth: ACTIVATION_COMPONENT_MAX_DEPTH - 2,
    maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
    nodes: ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
  };
}

function fail(code: string, status = 409): never {
  throw new BrokerError(code, status, false);
}
