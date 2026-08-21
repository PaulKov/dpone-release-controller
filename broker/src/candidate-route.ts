import { admissionClaimsDigest } from "./activation-proof";
import { replayRequestBody } from "./auth-replay-ledger";
import { CandidateReaderClient, type CandidateReaderStream } from "./candidate-reader-client";
import {
  CANDIDATE_PUBLIC_PATH,
  buildCandidateStreamResponse,
  parseCandidateStreamRequest,
} from "./candidate-stream";
import { digestObject } from "./canonical";
import { controllerRouteTrust } from "./config";
import { ControllerRunClient, type ControllerJobObservation } from "./controller-run-client";
import { assert, BrokerError } from "./errors";
import { authenticateGitHubOidc } from "./oidc";
import type { ActivationTrust, AuthenticatedWorkflow, Env, PrivateServicePin } from "./types";
import { parseJsonObject } from "./validation";
import type {
  CandidateActivatedAuthority,
  CandidateProviderInput,
} from "./private/candidate-contract";
import { CANDIDATE_MEDIA_TYPE } from "./private/candidate-rpc";

export interface CandidateRouteDependencies {
  authenticate(request: Request): Promise<AuthenticatedWorkflow>;
  consumeReplay(
    auth: AuthenticatedWorkflow,
    requestId: string,
    claimsDigest: string,
  ): Promise<void>;
  observeController(
    auth: AuthenticatedWorkflow,
    requestId: string,
  ): Promise<ControllerJobObservation>;
  openCandidate(
    input: CandidateProviderInput,
    authority: CandidateActivatedAuthority,
  ): Promise<CandidateReaderStream>;
}

/**
 * Candidate archive admission orchestration. It intentionally contains no
 * credentials and accepts all provider access through narrow injected ports.
 */
export class CandidateStreamRoute {
  public constructor(
    private readonly dependencies: CandidateRouteDependencies,
    private readonly candidateReaderPin: PrivateServicePin,
    private readonly authority: CandidateActivatedAuthority,
  ) {}

  public async handle(request: Request, requestId: string): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== CANDIDATE_PUBLIC_PATH || url.search !== "") {
      throw new BrokerError("ROUTE_NOT_FOUND", 404, false);
    }
    assert(request.headers.get("x-request-id") === requestId, "REQUEST_ID_REQUIRED");
    assert(request.headers.get("accept") === CANDIDATE_MEDIA_TYPE, "ACCEPT_HEADER_INVALID", 406);

    const auth = await this.dependencies.authenticate(request);
    const body = await parseJsonObject(request);
    const input = parseCandidateStreamRequest(body, requestId);
    const controllerObservation = await this.dependencies.observeController(auth, requestId);
    const admissionDigest = await admissionClaimsDigest(auth, controllerObservation, requestId);
    const claimsDigest = await digestObject({
      admission_claims_sha256: admissionDigest,
      candidate_artifact_digest: input.artifactDigest,
      candidate_artifact_id: input.artifactId,
      candidate_run_attempt: input.runAttempt,
      candidate_run_id: input.runId,
      expected_peeled_commit_sha: input.peeledCommitSha,
      release: input.release,
      route: CANDIDATE_PUBLIC_PATH,
      target_policy_blob_sha: this.authority.policyBlobSha,
      target_policy_sha256: this.authority.policySha256,
    });
    await this.dependencies.consumeReplay(auth, requestId, claimsDigest);
    const stream = await this.dependencies.openCandidate(input, this.authority);
    return buildCandidateStreamResponse(stream, this.candidateReaderPin, requestId);
  }
}

/**
 * Constructs the production adapter graph. The ingress Worker receives only
 * private Service Bindings; GitHub App credentials remain in adapter Workers.
 * This factory is deliberately not wired into the public router until the
 * receipt and recovery contracts are frozen.
 */
export function productionCandidateStreamRoute(
  env: Env,
  activation: ActivationTrust,
): CandidateStreamRoute {
  const controllerService = env.CONTROLLER_RUN_READER;
  const candidateService = env.CANDIDATE_READER;
  assert(controllerService !== undefined, "CONTROLLER_RUN_READER_UNAVAILABLE", 503);
  assert(candidateService !== undefined, "CANDIDATE_READER_UNAVAILABLE", 503);
  const controllerClient = new ControllerRunClient(
    controllerService,
    activation.privateServices.controllerRunReader,
    {
      app: activation.controllerRunReaderApp,
      defaultBranchWorkflowBlobSha: activation.controllerDefaultBranchWorkflowBlobSha,
      jobName: "candidate-import",
      peeledCommitSha: activation.controllerWorkflowSha,
      ref: activation.controllerRef,
      tagObjectSha: activation.controllerTagObjectSha,
      workflowId: activation.controllerWorkflowId,
      workflowRef: activation.controllerWorkflowRef,
    },
  );
  const candidateClient = new CandidateReaderClient(
    candidateService,
    activation.privateServices.candidateReader,
  );
  return new CandidateStreamRoute(
    {
      authenticate: (request) =>
        authenticateGitHubOidc(request, controllerRouteTrust(activation, "candidate")),
      consumeReplay: async (auth, requestId, claimsDigest) => {
        await env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1").consume(
          replayRequestBody(auth.jti, auth.expiresAt, requestId, claimsDigest),
        );
      },
      observeController: (auth, requestId) => controllerClient.verify(auth, requestId),
      openCandidate: (input, authority) => candidateClient.open(input, authority),
    },
    activation.privateServices.candidateReader,
    {
      policyBlobSha: activation.targetPolicyBlobSha,
      policySha256: activation.targetPolicySha256,
    },
  );
}
