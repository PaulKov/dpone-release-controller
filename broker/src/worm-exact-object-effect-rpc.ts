import {
  assertActivationRecordDigest,
  parseActivatedEnvelope,
  parseProvisionedEnvelope,
} from "./activation-records";
import {
  exactActivatedEnvelope,
  exactProvisionedEnvelope,
} from "./activation-snapshot-reconstruction";
import { canonicalJson } from "./canonical";
import { BrokerError } from "./errors";
import { assertRetainableProviderEvidence } from "./provider-evidence";
import { parseStrictJsonObject } from "./strict-json";
import type { JsonObject } from "./types";
import { WORM_EXACT_OBJECT_MAX_BYTES } from "./worm-exact-object-effect-contract";

export const WORM_EXACT_OBJECT_EFFECT_RPC_PATH = "/rpc/v1/exact-object-effect" as const;
export const WORM_EXACT_OBJECT_EFFECT_REQUEST_ID = /^activation-[0-9a-f]{64}$/u;

const ACTIVATION_KEY = /^receipts\/v1\/activation\/([0-9a-f-]{36})\/([01])-([0-9a-f]{64})\.json$/u;
const EVIDENCE_KEY =
  /^receipts\/v1\/activation-evidence\/([0-9a-f-]{36})\/(github_branch_ruleset|github_oidc_subject_customization)\/([0-9a-f]{64})\.json$/u;

/** Parse exact canonical JSON bytes before they cross the WORM DO boundary. */
export function parseWormExactObjectEffectDocument(bytes: Uint8Array): JsonObject {
  if (bytes.byteLength < 1 || bytes.byteLength > WORM_EXACT_OBJECT_MAX_BYTES) {
    throw rpcError("WORM_EXACT_OBJECT_EFFECT_RPC_SIZE_INVALID", 413);
  }
  const document = parseStrictJsonObject(bytes, "WORM_EXACT_OBJECT_EFFECT_RPC_BODY_INVALID");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw rpcError("WORM_EXACT_OBJECT_EFFECT_RPC_BODY_INVALID");
  }
  if (text !== canonicalJson(document)) {
    throw rpcError("WORM_EXACT_OBJECT_EFFECT_RPC_BODY_NONCANONICAL");
  }
  return document;
}

/**
 * Restrict the generic journal to reviewed namespaces and closed record bytes.
 * This is a retention boundary, not standalone activation admission: the
 * registry still verifies the complete stored A0/A1 pair before advancing the
 * authority head.
 */
export async function assertWormExactObjectEffectKeyBinding(
  document: JsonObject,
  key: string,
  digest: string,
  ingressVersionId: string,
): Promise<void> {
  const digestHex = digest.startsWith("sha256:") ? digest.slice("sha256:".length) : "";
  const activation = ACTIVATION_KEY.exec(key);
  if (activation !== null) {
    const sequence = Number(activation[2]);
    if (
      activation[1] !== ingressVersionId ||
      activation[3] !== digestHex ||
      document.sequence !== sequence ||
      (sequence === 0
        ? document.schema !== "dpone.release-broker-provisioned.v1"
        : document.schema !== "dpone.release-broker-activated.v1")
    ) {
      throw rpcError("WORM_EXACT_OBJECT_EFFECT_RPC_KEY_INVALID");
    }
    const envelope =
      sequence === 0 ? exactProvisionedEnvelope(document) : exactActivatedEnvelope(document);
    const parsed =
      sequence === 0 ? parseProvisionedEnvelope(envelope) : parseActivatedEnvelope(envelope);
    await assertActivationRecordDigest(envelope, parsed.recordId);
    return;
  }
  const evidence = EVIDENCE_KEY.exec(key);
  if (
    evidence?.[1] !== ingressVersionId ||
    evidence[3] !== digestHex ||
    document.schema !== "dpone.release-broker-provider-evidence-entry.v1" ||
    document.evidence_kind !== evidence[2]
  ) {
    throw rpcError("WORM_EXACT_OBJECT_EFFECT_RPC_KEY_INVALID");
  }
  await assertRetainableProviderEvidence(
    document,
    evidence[2] as "github_branch_ruleset" | "github_oidc_subject_customization",
  );
}

function rpcError(code: string, status = 400): BrokerError {
  return new BrokerError(code, status, false);
}
