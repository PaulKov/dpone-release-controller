import { B2VersionObserverClient } from "../b2-version-observer-client";
import { B2ExactObjectMirror } from "../b2";
import { readBoundedBytes } from "../bounded";
import { canonicalJson, sha256Hex } from "../canonical";
import {
  CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH,
  CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES,
} from "../cloudflare-evidence-batch-rpc";
import {
  CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH,
  CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH,
  CLOUDFLARE_EVIDENCE_WORM_RPC_PATH,
} from "../cloudflare-evidence-worm-client";
import {
  CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2,
  MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES,
} from "../cloudflare-evidence-batch-resume-v2";
import { LIMITS } from "../config";
import { BrokerError, errorResponse } from "../errors";
import { assertRetainableProviderEvidence } from "../provider-evidence";
import { verifyWormRpcRequest } from "../worm-rpc-auth";
import { WORM_EXACT_OBJECT_EFFECT_RPC_PATH } from "../worm-exact-object-effect-rpc";
import { B2NativeWriter } from "./b2-native";
import { mirrorActivatedAuthorityHead } from "./worm-activation-head";
import { handleCloudflareEvidence } from "./worm-cloudflare-evidence";
import {
  handleCloudflareEvidenceBatch,
  handleCloudflareEvidenceBatchResume,
} from "./worm-cloudflare-evidence-batch";
export { CloudflareEvidenceBatch } from "./cloudflare-evidence-batch-do";
import { handleWormExactObjectEffect } from "./worm-exact-object-effect-handler";
export { WormExactObjectEffect } from "./worm-exact-object-effect-do";
import {
  TAGGED_DIGEST,
  type WormMirrorEnv,
  assertExpectedB2ObserverPin,
  assertExpectedCallee,
  canonicalResponse,
  decodeCanonicalEnvelope,
  exactHeader,
  parseActivationBinding,
  parseActivationEvidenceBinding,
  observerPinFromHeaders,
  requireConfig,
  requireVersionId,
} from "./worm-mirror-worker-helpers";

/**
 * Private, route-less WORM writer. It owns only a prefix-scoped writeFiles B2
 * key and delegates every read/list/retention check to the separately pinned
 * observer Worker.
 */
export default {
  async fetch(request: Request, env: WormMirrorEnv): Promise<Response> {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    try {
      const url = new URL(request.url);
      const activation = url.pathname === "/rpc/v1/activation";
      const activationHead = url.pathname === "/rpc/v1/activation-head";
      const activationEvidence = url.pathname === "/rpc/v1/activation-evidence";
      const cloudflareEvidence = url.pathname === CLOUDFLARE_EVIDENCE_WORM_RPC_PATH;
      const cloudflareEvidenceAbsence = url.pathname === CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH;
      const cloudflareEvidenceBatch = url.pathname === CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH;
      const cloudflareEvidenceBatchV2 = url.pathname === CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2;
      const cloudflareEvidenceBatchResumeV2 =
        url.pathname === CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2;
      const cloudflareEvidenceReconcile =
        url.pathname === CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH;
      const exactObjectEffect = url.pathname === WORM_EXACT_OBJECT_EFFECT_RPC_PATH;
      if (
        request.method !== "POST" ||
        (!activation &&
          !activationHead &&
          !activationEvidence &&
          !cloudflareEvidence &&
          !cloudflareEvidenceAbsence &&
          !cloudflareEvidenceBatch &&
          !cloudflareEvidenceBatchV2 &&
          !cloudflareEvidenceBatchResumeV2 &&
          !exactObjectEffect &&
          !cloudflareEvidenceReconcile) ||
        url.search !== ""
      ) {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      const rpcPath = activation
        ? "/rpc/v1/activation"
        : activationHead
          ? "/rpc/v1/activation-head"
          : cloudflareEvidence
            ? CLOUDFLARE_EVIDENCE_WORM_RPC_PATH
            : cloudflareEvidenceAbsence
              ? CLOUDFLARE_EVIDENCE_WORM_ABSENCE_RPC_PATH
              : cloudflareEvidenceBatch
                ? CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH
                : cloudflareEvidenceBatchV2
                  ? CLOUDFLARE_EVIDENCE_BATCH_RPC_PATH_V2
                  : cloudflareEvidenceBatchResumeV2
                    ? CLOUDFLARE_EVIDENCE_BATCH_RESUME_RPC_PATH_V2
                    : exactObjectEffect
                      ? WORM_EXACT_OBJECT_EFFECT_RPC_PATH
                      : cloudflareEvidenceReconcile
                        ? CLOUDFLARE_EVIDENCE_WORM_RECONCILE_RPC_PATH
                        : "/rpc/v1/activation-evidence";
      assertExpectedCallee(request.headers, env);
      await verifyWormRpcRequest(
        request.headers,
        rpcPath,
        cloudflareEvidence ||
          cloudflareEvidenceAbsence ||
          cloudflareEvidenceBatch ||
          cloudflareEvidenceBatchV2 ||
          cloudflareEvidenceBatchResumeV2 ||
          cloudflareEvidenceReconcile
          ? env.CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY
          : env.WORM_RPC_AUTH_KEY,
        cloudflareEvidence ||
          cloudflareEvidenceAbsence ||
          cloudflareEvidenceBatch ||
          cloudflareEvidenceBatchV2 ||
          cloudflareEvidenceBatchResumeV2 ||
          cloudflareEvidenceReconcile
          ? env.WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY
          : env.WORM_EXPECTED_CALLER_SERVICE_IDENTITY,
      );
      assertExpectedB2ObserverPin(observerPinFromHeaders(request.headers), env);
      const canonicalBytes = await readBoundedBytes(
        request,
        cloudflareEvidenceBatch || cloudflareEvidenceBatchV2
          ? MAX_CLOUDFLARE_EVIDENCE_BATCH_RPC_BYTES
          : cloudflareEvidenceBatchResumeV2
            ? MAX_CLOUDFLARE_EVIDENCE_BATCH_RESUME_BYTES
            : LIMITS.bodyBytes,
        "MIRROR_BODY_SIZE_INVALID",
      );
      const signedDigest = exactHeader(
        request.headers,
        "x-dpone-canonical-sha256",
        TAGGED_DIGEST,
        71,
      );
      if (`sha256:${await sha256Hex(canonicalBytes)}` !== signedDigest) {
        throw new BrokerError("WORM_RPC_BODY_DIGEST_MISMATCH", 400, false);
      }
      const envelope = decodeCanonicalEnvelope(canonicalBytes);
      if (cloudflareEvidenceBatch || cloudflareEvidenceBatchV2) {
        return await handleCloudflareEvidenceBatch(
          canonicalJson(envelope),
          request.headers,
          env,
          cloudflareEvidenceBatchV2 ? 2 : 1,
        );
      }
      if (cloudflareEvidenceBatchResumeV2) {
        return await handleCloudflareEvidenceBatchResume(
          canonicalJson(envelope),
          request.headers,
          env,
        );
      }
      if (exactObjectEffect) {
        return await handleWormExactObjectEffect(canonicalBytes, request.headers, env);
      }
      if (cloudflareEvidence || cloudflareEvidenceAbsence || cloudflareEvidenceReconcile) {
        return await handleCloudflareEvidence(
          cloudflareEvidence ? "mirror" : cloudflareEvidenceAbsence ? "absence" : "reconcile",
          envelope,
          request.headers,
          env,
        );
      }
      if (activationHead) {
        return await mirrorActivatedAuthorityHead(envelope, request.headers, env);
      }
      const binding = activationEvidence
        ? parseActivationEvidenceBinding(envelope, request.headers)
        : parseActivationBinding(envelope, request.headers);
      if ("evidenceKind" in binding) {
        await assertRetainableProviderEvidence(envelope, binding.evidenceKind);
      }
      const config = requireConfig(env);
      const observer = env.WORM_VERSION_OBSERVER;
      if (observer === undefined || typeof observer.fetch !== "function") {
        throw new BrokerError("B2_OBSERVER_UNAVAILABLE", 503, true);
      }
      const mirror = new B2ExactObjectMirror(
        new B2NativeWriter(config),
        new B2VersionObserverClient(observer, binding.observerPin),
      );
      if ("evidenceKind" in binding) {
        const evidenceResult = await mirror.mirror({
          canonicalBytes: new TextEncoder().encode(canonicalJson(envelope)),
          committedAt: binding.committedAt,
          digest: binding.digest,
          key: [
            "receipts",
            "v1",
            "activation-evidence",
            binding.ingressWorkerVersion,
            binding.evidenceKind,
            `${binding.digest.slice("sha256:".length)}.json`,
          ].join("/"),
        });
        return canonicalResponse({
          digest: evidenceResult.digest,
          key: evidenceResult.key,
          kind: "activation_evidence",
          retention_until: evidenceResult.retentionUntil,
          schema: "dpone.release-worm-mirror-result.v1",
          version_id: evidenceResult.versionId,
          worker_version_id: requireVersionId(env),
        });
      }
      const result = await mirror.mirror({
        canonicalBytes: new TextEncoder().encode(canonicalJson(envelope)),
        committedAt: binding.committedAt,
        digest: binding.digest,
        key: [
          "receipts",
          "v1",
          "activation",
          binding.ingressWorkerVersion,
          `${binding.sequence}-${binding.digest.slice("sha256:".length)}.json`,
        ].join("/"),
      });
      return canonicalResponse({
        digest: result.digest,
        key: result.key,
        kind: "activation",
        retention_until: result.retentionUntil,
        schema: "dpone.release-worm-mirror-result.v1",
        version_id: result.versionId,
        worker_version_id: requireVersionId(env),
      });
    } catch (error) {
      return errorResponse(error, requestId);
    }
  },
} satisfies ExportedHandler<WormMirrorEnv>;

/**
 * Rejects a Service Binding fallback before the request body is read or B2 is
 * touched. The caller must bind both the immutable version and its derived
 * Cloudflare service identity.
 */
