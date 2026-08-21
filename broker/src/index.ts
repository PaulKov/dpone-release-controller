import { ActivationRegistry } from "./activation-registry";
import { ActivatedAuthorityHeadClient } from "./activated-authority-head-client";
import { parseActivationSnapshotCanonical } from "./activation-rpc";
import { verifyActivationSnapshot } from "./activation-snapshot-verifier";
import {
  activationProofRecoveryClaimsDigest,
  activationProofIntentDigest,
  admissionClaimsDigest,
  buildActivationProof,
  buildActivationProofRecovery,
  parseActivationProofRequest,
} from "./activation-proof";
import { adminReplayKey, authenticateAdmin } from "./admin-auth";
import {
  ADMIN_REPLAY_LEDGER_NAME,
  AuthReplayLedger,
  replayRequestBody,
} from "./auth-replay-ledger";
import { controllerRouteTrust, requireLiveConfig } from "./config";
import { CANDIDATE_PUBLIC_PATH } from "./candidate-stream";
import { canonicalJson, sha256Hex } from "./canonical";
import { assert, BrokerError, canonicalTextResponse, errorResponse, jsonResponse } from "./errors";
import { ControllerRunClient } from "./controller-run-client";
import { GlobalActivatedAuthorityHead } from "./global-activated-authority-head";
import { authenticateGitHubOidc } from "./oidc";
import { ReleaseLedger } from "./release-ledger";
import { RUNTIME_CLOSURE_PUBLIC_PATH } from "./runtime-closure";
import type { Env, JsonObject, TrustedRuntimeConfig } from "./types";
import { parseJsonObject, requestId } from "./validation";

export { ActivationRegistry, AuthReplayLedger, GlobalActivatedAuthorityHead, ReleaseLedger };

const ADMIN_PROVISION_PATH = "/v1/admin/activation/provision";
const ADMIN_FINALIZE_PATH = "/v1/admin/activation/finalize";
const ACTIVATION_PROOF_PATH = "/v1/activation/proof";
const PYPI_GATE_WEBHOOK_PATH = "/v1/webhooks/github/deployment-protection-rule";
const PROTOCOL_GATED_PATHS = new Set([
  CANDIDATE_PUBLIC_PATH,
  PYPI_GATE_WEBHOOK_PATH,
  RUNTIME_CLOSURE_PUBLIC_PATH,
]);
const LIVENESS_PATH = "/livez";
const READINESS_PATH = "/readyz";
const RETIRED_HEALTH_PATH = "/healthz";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      const url = new URL(request.url);
      if (url.search !== "") {
        throw new BrokerError("ROUTE_NOT_FOUND", 404, false);
      }
      if (request.method === "GET" && url.pathname === LIVENESS_PATH) {
        return liveness(env);
      }
      if (request.method === "GET" && url.pathname === READINESS_PATH) {
        return await readiness(env, currentRequestId);
      }
      if (request.method === "GET" && url.pathname === RETIRED_HEALTH_PATH) {
        throw new BrokerError("ROUTE_NOT_FOUND", 404, false);
      }
      if (request.method === "POST" && PROTOCOL_GATED_PATHS.has(url.pathname)) {
        throw new BrokerError("BROKER_PROTOCOL_UNFROZEN", 503, false);
      }
      const config = requireLiveConfig(env);
      if (request.method === "POST" && url.pathname === ACTIVATION_PROOF_PATH) {
        return await handleActivationProof(request, env, config, currentRequestId);
      }
      if (
        request.method === "POST" &&
        (url.pathname === ADMIN_PROVISION_PATH || url.pathname === ADMIN_FINALIZE_PATH)
      ) {
        return await handleAdminActivation(request, env, config, currentRequestId, url.pathname);
      }
      throw new BrokerError("ROUTE_NOT_FOUND", 404, false);
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler<Env>;

async function handleAdminActivation(
  request: Request,
  env: Env,
  config: TrustedRuntimeConfig,
  currentRequestId: string,
  path: string,
): Promise<Response> {
  assert(request.headers.get("x-request-id") === currentRequestId, "REQUEST_ID_REQUIRED");
  const authentication = await authenticateAdmin(request, config);
  const body = await parseJsonObject(request);
  assert(body.request_id === currentRequestId, "REQUEST_ID_MISMATCH");
  const canonicalBody = canonicalJson(body);
  const replayKey = await adminReplayKey({
    authentication,
    canonicalBody,
    method: request.method,
    path,
    requestId: currentRequestId,
  });
  const replay = env.AUTH_REPLAY_LEDGER.getByName(ADMIN_REPLAY_LEDGER_NAME);
  await replay.consumeIdempotentExact(
    replayRequestBody(
      authentication.tokenSha256,
      authentication.expiresAt,
      currentRequestId,
      replayKey,
    ),
  );
  const registry = env.ACTIVATION_REGISTRY.getByName(`version:${config.workerVersionId}`);
  const result =
    path === ADMIN_PROVISION_PATH
      ? await registry.provision(canonicalBody)
      : await registry.finalize(canonicalBody);
  return canonicalTextResponse(result);
}

async function handleActivationProof(
  request: Request,
  env: Env,
  config: TrustedRuntimeConfig,
  currentRequestId: string,
): Promise<Response> {
  assert(request.headers.get("x-request-id") === currentRequestId, "REQUEST_ID_REQUIRED");
  const registry = env.ACTIVATION_REGISTRY.getByName(`version:${config.workerVersionId}`);
  const snapshotText = await registry.snapshotCanonical();
  if (snapshotText === null) {
    throw new BrokerError("BROKER_PROVISIONING", 503, true);
  }
  const snapshot = parseActivationSnapshotCanonical(snapshotText);
  assert(snapshot !== null, "BROKER_PROVISIONING", 503);
  const verified = await verifyActivationSnapshot(snapshot, config);
  const activation = verified.activation;
  const auth = await authenticateGitHubOidc(request, controllerRouteTrust(activation, "ledger"));
  const body = await parseJsonObject(request);
  parseActivationProofRequest(body);
  const service = env.CONTROLLER_RUN_READER;
  assert(service !== undefined, "CONTROLLER_RUN_READER_UNAVAILABLE", 503);
  const observation = await new ControllerRunClient(
    service,
    activation.privateServices.controllerRunReader,
    {
      app: activation.controllerRunReaderApp,
      defaultBranchWorkflowBlobSha: activation.controllerDefaultBranchWorkflowBlobSha,
      jobName: "admit",
      peeledCommitSha: activation.controllerWorkflowSha,
      ref: activation.controllerRef,
      tagObjectSha: activation.controllerTagObjectSha,
      workflowId: activation.controllerWorkflowId,
      workflowRef: activation.controllerWorkflowRef,
    },
  ).verify(auth, currentRequestId);
  const claimsDigest = await admissionClaimsDigest(auth, observation, currentRequestId);
  const intentSha256 = await activationProofIntentDigest(auth, observation, snapshot);
  const headClient = new ActivatedAuthorityHeadClient(env.GLOBAL_ACTIVATED_AUTHORITY_HEAD);
  const reserved = await headClient.reserveActivationProof(
    verified,
    intentSha256,
    {
      claimsSha256: claimsDigest,
      expiresAt: auth.expiresAt,
      jtiSha256: `sha256:${await sha256Hex(new TextEncoder().encode(auth.jti))}`,
    },
    currentRequestId,
    Date.now(),
  );
  if (reserved.status === "CONFIRMED") {
    assert(
      reserved.sealedResult !== null && reserved.sealedResultSha256 !== null,
      "ACTIVATED_AUTHORITY_EFFECT_RESULT_INVALID",
      503,
    );
    const nowMs = Date.now();
    const recovery = await buildActivationProofRecovery({
      currentHead: reserved.headProof,
      currentRequestId,
      nowMs,
      originalProof: reserved.sealedResult,
      originalRequestId: reserved.originalRequestId,
      reservationId: reserved.reservationId,
      sealedResultSha256: reserved.sealedResultSha256,
    });
    const recoveryClaimsDigest = await activationProofRecoveryClaimsDigest({
      admissionClaimsSha256: claimsDigest,
      currentHead: reserved.headProof,
      currentRequestId,
      originalRequestId: reserved.originalRequestId,
      reservationId: reserved.reservationId,
      sealedResultSha256: reserved.sealedResultSha256,
    });
    await env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1").consumeOnce(
      replayRequestBody(auth.jti, auth.expiresAt, currentRequestId, recoveryClaimsDigest),
    );
    return activationProofResponse(recovery, currentRequestId);
  }
  assert(reserved.status === "RESERVED", "ACTIVATED_AUTHORITY_EFFECT_STATUS_INVALID", 503);
  let proof: JsonObject;
  try {
    proof = await buildActivationProof({
      activation,
      activatedAuthorityHead: reserved.headProof,
      auth,
      nowMs: Date.now(),
      observation,
      requestId: currentRequestId,
      snapshot,
    });
  } catch (error) {
    await headClient.cancelActivationProof(reserved.reservationId, currentRequestId, Date.now());
    throw error;
  }
  assert(
    typeof proof.proof_sha256 === "string" && /^sha256:[0-9a-f]{64}$/u.test(proof.proof_sha256),
    "ACTIVATION_PROOF_DIGEST_INVALID",
    500,
  );
  const resultSha256 = await headClient.sealActivationProof(
    reserved.reservationId,
    currentRequestId,
    canonicalJson(proof),
    Date.now(),
  );
  await headClient.dispatchActivationProof(reserved.reservationId, currentRequestId, Date.now());
  await headClient.confirmActivationProof(
    reserved.reservationId,
    currentRequestId,
    resultSha256,
    Date.now(),
  );
  return activationProofResponse(proof, currentRequestId);
}

function activationProofResponse(body: JsonObject, requestIdValue: string): Response {
  const response = jsonResponse(body);
  response.headers.set("cache-control", "no-store");
  response.headers.set("pragma", "no-cache");
  response.headers.set("x-request-id", requestIdValue);
  return response;
}

function liveness(env: Env): Response {
  return jsonResponse({
    schema: "dpone.release-broker-liveness.v1",
    status: "live",
    worker_version_id: env.CF_VERSION_METADATA?.id ?? "unavailable",
  });
}

async function readiness(env: Env, currentRequestId: string): Promise<Response> {
  const config = requireLiveConfig(env);
  const registry = env.ACTIVATION_REGISTRY.getByName(`version:${config.workerVersionId}`);
  const snapshotText = await registry.snapshotCanonical();
  if (snapshotText === null) {
    throw new BrokerError("BROKER_PROVISIONING", 503, true);
  }
  const snapshot = parseActivationSnapshotCanonical(snapshotText);
  assert(snapshot !== null, "BROKER_PROVISIONING", 503);
  const verified = await verifyActivationSnapshot(snapshot, config);
  await new ActivatedAuthorityHeadClient(env.GLOBAL_ACTIVATED_AUTHORITY_HEAD).current(
    verified,
    currentRequestId,
    Date.now(),
  );

  // Provider re-observation must be a frozen, credential-free manifest before
  // this endpoint can signal authority readiness.
  throw new BrokerError("BROKER_PROVIDER_READINESS_UNFROZEN", 503, false);
}
