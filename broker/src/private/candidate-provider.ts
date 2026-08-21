import { digestObject } from "../canonical";
import { TRUST } from "../config";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import {
  CANDIDATE_API_REPOSITORY,
  CANDIDATE_ARTIFACT_NAME,
  CANDIDATE_POLICY_PATH,
  CANDIDATE_WORKFLOW_PATH,
  type CandidateActivatedAuthority,
  type CandidateProviderInput,
  type CandidateReaderConfig,
  validateCandidateAuthority,
  validateCandidateConfig,
  validateCandidateInput,
  verifyCandidateAnnotatedTag,
  verifyCandidateArtifact,
  verifyCandidateArtifactList,
  verifyCandidatePolicy,
  verifyCandidateRun,
  verifyCandidateTagReference,
} from "./candidate-contract";
import { createValidatedCandidateSource, type ValidatedCandidateSource } from "./candidate-source";
import type { InstallationTokenSource } from "./github-app";
import {
  githubJson,
  githubRedirectRequest,
  githubRequest,
  type ProviderFetch,
  providerInteger,
  providerString,
  requireGitHubOk,
} from "./github-provider";

const PROVIDER_JSON_LIMIT = 262_144;

export type {
  CandidateActivatedAuthority,
  CandidateProviderInput,
  CandidateReaderConfig,
} from "./candidate-contract";
export { ValidatedCandidateSource } from "./candidate-source";

export interface CandidateProviderResult {
  readonly observation: JsonObject;
  readonly source: ValidatedCandidateSource;
  readonly workerVersionId: string;
}

/**
 * Closed target Actions artifact reader. It verifies one completed candidate
 * run and keeps the provider bearer URL encapsulated in a one-use stream.
 */
export class CandidateProviderReader {
  public constructor(
    private readonly config: CandidateReaderConfig,
    private readonly tokens: InstallationTokenSource,
    private readonly providerFetch: ProviderFetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    validateCandidateConfig(config);
  }

  public async authorize(
    input: CandidateProviderInput,
    authority: CandidateActivatedAuthority,
  ): Promise<CandidateProviderResult> {
    validateCandidateInput(input);
    validateCandidateAuthority(authority);
    const token = await this.tokens.installationToken();
    const authorization = `Bearer ${token}`;
    const tagRef = `refs/tags/${input.release}`;
    const [run, artifact, artifactsResponse, reference, policy] = await Promise.all([
      this.get(authorization, `${CANDIDATE_API_REPOSITORY}/actions/runs/${input.runId}`),
      this.get(authorization, `${CANDIDATE_API_REPOSITORY}/actions/artifacts/${input.artifactId}`),
      this.getResponse(
        authorization,
        `${CANDIDATE_API_REPOSITORY}/actions/runs/${input.runId}/artifacts?name=${CANDIDATE_ARTIFACT_NAME}&per_page=100&page=1`,
      ),
      this.get(authorization, `${CANDIDATE_API_REPOSITORY}/git/ref/tags/${input.release}`),
      this.get(
        authorization,
        `${CANDIDATE_API_REPOSITORY}/contents/${CANDIDATE_POLICY_PATH}?ref=${input.peeledCommitSha}`,
      ),
    ]);
    if (artifactsResponse.headers.has("link")) {
      await artifactsResponse.body
        ?.cancel("CANDIDATE_ARTIFACT_SET_AMBIGUOUS")
        .catch(() => undefined);
      throw new BrokerError("CANDIDATE_ARTIFACT_SET_AMBIGUOUS", 503, false);
    }
    const artifacts = await githubJson(
      artifactsResponse,
      PROVIDER_JSON_LIMIT,
      "CANDIDATE_ARTIFACT_LIST_INVALID",
    );
    const nowMs = this.now();
    const runProjection = verifyCandidateRun(run, input);
    const artifactProjection = verifyCandidateArtifact(artifact, input, nowMs);
    const listProjection = verifyCandidateArtifactList(artifacts, input, artifactProjection, nowMs);
    const tagObjectSha = verifyCandidateTagReference(reference, tagRef, input.peeledCommitSha);
    const annotatedTag = await this.get(
      authorization,
      `${CANDIDATE_API_REPOSITORY}/git/tags/${tagObjectSha}`,
    );
    const tagProjection = verifyCandidateAnnotatedTag(annotatedTag, input, tagRef, tagObjectSha);
    const policyProjection = await verifyCandidatePolicy(policy, input, authority);
    const artifactSize = providerInteger(
      artifactProjection,
      "size_in_bytes",
      "CANDIDATE_ARTIFACT_INVALID",
    );
    const source = await this.authorizeArchive(authorization, input.artifactId, artifactSize);
    const policyBlobSha = providerString(
      policyProjection,
      "blob_sha",
      40,
      "CANDIDATE_POLICY_INVALID",
    );
    const providerResponseSha256 = await digestObject({
      artifact: artifactProjection,
      artifact_list: listProjection,
      policy: policyProjection,
      run: runProjection,
      source: {
        expires_at: source.expiresAt,
        url_sha256: source.urlSha256,
      },
      tag: tagProjection,
    });
    return {
      observation: {
        artifact_created_at: providerString(
          artifact,
          "created_at",
          32,
          "CANDIDATE_ARTIFACT_INVALID",
        ),
        artifact_digest: input.artifactDigest,
        artifact_expired: false,
        artifact_expires_at: providerString(
          artifact,
          "expires_at",
          32,
          "CANDIDATE_ARTIFACT_INVALID",
        ),
        artifact_id: input.artifactId,
        artifact_name: CANDIDATE_ARTIFACT_NAME,
        artifact_size_bytes: artifactSize,
        broker_request_id: input.requestId,
        conclusion: "success",
        event: "push",
        head_branch: input.release,
        head_sha: input.peeledCommitSha,
        policy_blob_sha: policyBlobSha,
        policy_path: CANDIDATE_POLICY_PATH,
        policy_sha256: authority.policySha256,
        policy_source_commit_sha: input.peeledCommitSha,
        provider_api_version: "2026-03-10",
        provider_response_sha256: providerResponseSha256,
        release: input.release,
        repository: TRUST.targetRepository,
        repository_id: TRUST.targetRepositoryId,
        run_attempt: input.runAttempt,
        run_id: input.runId,
        run_status: "completed",
        schema: "dpone.github-actions-artifact-observation.v1",
        schema_version: 1,
        source_url_expires_at: source.expiresAt,
        source_url_sha256: source.urlSha256,
        tag_object_sha: tagObjectSha,
        tag_object_type: "tag",
        tag_ref: tagRef,
        workflow_path: CANDIDATE_WORKFLOW_PATH,
      },
      source,
      workerVersionId: this.config.workerVersionId,
    };
  }

  private async authorizeArchive(
    authorization: string,
    artifactId: number,
    expectedBytes: number,
  ): Promise<ValidatedCandidateSource> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await githubRedirectRequest(this.providerFetch, {
        authorization,
        method: "GET",
        path: `${CANDIDATE_API_REPOSITORY}/actions/artifacts/${artifactId}/zip`,
      });
      if (response.status !== 302) {
        await response.body?.cancel();
        throw new BrokerError("CANDIDATE_SOURCE_REDIRECT_INVALID", 503, false);
      }
      const location = response.headers.get("location");
      if (location === null || location.length > 4096) {
        await response.body?.cancel();
        throw new BrokerError("CANDIDATE_SOURCE_REDIRECT_INVALID", 503, false);
      }
      await response.body?.cancel();
      try {
        return await createValidatedCandidateSource(
          location,
          expectedBytes,
          this.providerFetch,
          this.now,
        );
      } catch (error) {
        if (
          error instanceof BrokerError &&
          error.code === "CANDIDATE_SOURCE_REFRESH_REQUIRED" &&
          attempt === 0
        ) {
          continue;
        }
        throw error;
      }
    }
    throw new BrokerError("CANDIDATE_SOURCE_REFRESH_FAILED", 503, true);
  }

  private async get(authorization: string, path: `/${string}`): Promise<JsonObject> {
    const response = await this.getResponse(authorization, path);
    return githubJson(response, PROVIDER_JSON_LIMIT, "CANDIDATE_PROVIDER_RESPONSE_INVALID");
  }

  private async getResponse(authorization: string, path: `/${string}`): Promise<Response> {
    const response = await githubRequest(this.providerFetch, {
      authorization,
      method: "GET",
      path,
    });
    await requireGitHubOk(response, "CANDIDATE_PROVIDER_REQUEST_FAILED");
    return response;
  }
}
