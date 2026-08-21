import { CANDIDATE_READER_PERMISSIONS } from "../activation-contract";
import { TRUST } from "../config";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { assert, BrokerError, errorResponse } from "../errors";
import { parseJsonObject, requestId } from "../validation";
import { CandidateProviderReader, type CandidateProviderResult } from "./candidate-provider";
import { GitHubAppTokenProvider, type GitHubAppConfig } from "./github-app";
import {
  CANDIDATE_OBSERVATION_DIGEST_HEADER,
  CANDIDATE_OBSERVATION_HEADER,
  CANDIDATE_MEDIA_TYPE,
  CANDIDATE_RESPONSE_REQUEST_ID_HEADER,
  CANDIDATE_RESPONSE_SCHEMA,
  CANDIDATE_RESPONSE_SCHEMA_HEADER,
  CANDIDATE_RPC_PATH,
  CANDIDATE_SERVICE_IDENTITY_HEADER,
  CANDIDATE_SERVICE_VERSION_HEADER,
  encodeCandidateObservation,
  parseCandidateReaderRpcRequest,
} from "./candidate-rpc";

export interface CandidateReaderWorkerEnv {
  readonly CANDIDATE_READER_SERVICE_NAME?: string;
  readonly CF_ACCOUNT_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly GITHUB_APP_ID?: string;
  readonly GITHUB_APP_INSTALLATION_ID?: string;
  readonly GITHUB_APP_PRIVATE_KEY?: string;
  readonly OPERATING_MODE: string;
}

interface CandidateArchiveAuthorizer {
  authorize: CandidateProviderReader["authorize"];
}

interface CandidateReaderRuntime {
  readonly authorizer: CandidateArchiveAuthorizer;
  readonly serviceIdentity: string;
  readonly workerVersionId: string;
}

type RuntimeResolver = (env: CandidateReaderWorkerEnv) => CandidateReaderRuntime;

export interface CandidateReaderHandler {
  fetch(request: Request, env: CandidateReaderWorkerEnv): Promise<Response>;
}

/**
 * Builds the private Service Binding handler. Dependency injection keeps the
 * HTTP/stream boundary testable without adding any production test route.
 */
export function createCandidateReaderHandler(
  resolveRuntime: RuntimeResolver,
): CandidateReaderHandler {
  return {
    async fetch(request: Request, env: CandidateReaderWorkerEnv): Promise<Response> {
      let currentRequestId: string = crypto.randomUUID();
      try {
        currentRequestId = requestId(request);
        const url = new URL(request.url);
        if (request.method !== "POST" || url.pathname !== CANDIDATE_RPC_PATH || url.search !== "") {
          throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
        }
        assert(request.headers.get("x-request-id") === currentRequestId, "REQUEST_ID_REQUIRED");
        assert(
          request.headers.get("accept") === CANDIDATE_MEDIA_TYPE,
          "ACCEPT_HEADER_INVALID",
          406,
        );
        for (const name of ["authorization", "cf-access-jwt-assertion", "cookie"]) {
          assert(!request.headers.has(name), "PRIVATE_CREDENTIAL_HEADER_FORBIDDEN", 400);
        }
        const runtime = resolveRuntime(env);
        assert(
          request.headers.get(CANDIDATE_SERVICE_IDENTITY_HEADER) === runtime.serviceIdentity,
          "CANDIDATE_SERVICE_IDENTITY_MISMATCH",
          503,
        );
        const rpc = parseCandidateReaderRpcRequest(await parseJsonObject(request));
        assert(rpc.input.requestId === currentRequestId, "REQUEST_ID_MISMATCH");
        const result = await runtime.authorizer.authorize(rpc.input, rpc.authority);
        assert(
          result.workerVersionId === runtime.workerVersionId,
          "CANDIDATE_SERVICE_VERSION_MISMATCH",
          503,
        );
        return await buildArchiveResponse(result, runtime, currentRequestId);
      } catch (error) {
        return errorResponse(error, currentRequestId);
      }
    },
  };
}

const productionHandler = createCandidateReaderHandler(resolveProductionRuntime);

export default productionHandler;

async function buildArchiveResponse(
  result: CandidateProviderResult,
  runtime: CandidateReaderRuntime,
  requestIdValue: string,
): Promise<Response> {
  const observation = await encodeCandidateObservation({
    ...result.observation,
    candidate_reader_service_identity: runtime.serviceIdentity,
    candidate_reader_service_version_id: runtime.workerVersionId,
  });
  const response = await result.source.open();
  response.headers.set("cache-control", "private, no-store, max-age=0");
  response.headers.set("content-type", CANDIDATE_MEDIA_TYPE);
  response.headers.set(CANDIDATE_OBSERVATION_HEADER, observation.base64url);
  response.headers.set(CANDIDATE_OBSERVATION_DIGEST_HEADER, observation.digest);
  response.headers.set(CANDIDATE_SERVICE_IDENTITY_HEADER, runtime.serviceIdentity);
  response.headers.set(CANDIDATE_SERVICE_VERSION_HEADER, runtime.workerVersionId);
  response.headers.set(CANDIDATE_RESPONSE_REQUEST_ID_HEADER, requestIdValue);
  response.headers.set(CANDIDATE_RESPONSE_SCHEMA_HEADER, CANDIDATE_RESPONSE_SCHEMA);
  response.headers.delete("content-encoding");
  response.headers.delete("content-range");
  response.headers.delete("set-cookie");
  return response;
}

function resolveProductionRuntime(env: CandidateReaderWorkerEnv): CandidateReaderRuntime {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("PRIVATE_SERVICE_PROVISIONING", 503, true);
  }
  const workerVersionId = requiredPattern(
    env.CF_VERSION_METADATA?.id,
    CLOUDFLARE_UUID,
    "PRIVATE_SERVICE_VERSION_UNAVAILABLE",
  );
  const accountId = requiredPattern(
    env.CF_ACCOUNT_ID,
    /^[0-9a-f]{32}$/u,
    "PRIVATE_SERVICE_IDENTITY_INVALID",
  );
  const serviceName = requiredSafeName(
    env.CANDIDATE_READER_SERVICE_NAME,
    "PRIVATE_SERVICE_IDENTITY_INVALID",
  );
  const serviceIdentity = `cloudflare-worker:${accountId}/${serviceName}@${workerVersionId}`;
  const appConfig: GitHubAppConfig = {
    appId: positiveSafeId(env.GITHUB_APP_ID),
    installationId: positiveSafeId(env.GITHUB_APP_INSTALLATION_ID),
    permissions: CANDIDATE_READER_PERMISSIONS,
    privateKey: requirePrivateKey(env.GITHUB_APP_PRIVATE_KEY),
    repository: TRUST.targetRepository,
    repositoryId: TRUST.targetRepositoryId,
  };
  return {
    authorizer: new CandidateProviderReader(
      { workerVersionId },
      new GitHubAppTokenProvider(appConfig),
    ),
    serviceIdentity,
    workerVersionId,
  };
}

function positiveSafeId(value: string | undefined): string {
  const id = requiredPattern(value, /^[1-9][0-9]{0,15}$/u, "GITHUB_APP_CONFIGURATION_INVALID");
  if (!Number.isSafeInteger(Number(id))) {
    throw new BrokerError("GITHUB_APP_CONFIGURATION_INVALID", 503, false);
  }
  return id;
}

function requiredSafeName(value: string | undefined, code: string): string {
  return requiredPattern(value, /^[A-Za-z0-9][A-Za-z0-9._-]{15,127}$/u, code);
}

function requiredPattern(value: string | undefined, pattern: RegExp, code: string): string {
  if (value === undefined || !pattern.test(value)) {
    throw new BrokerError(code, 503, false);
  }
  return value;
}

function requirePrivateKey(value: string | undefined): string {
  if (
    value === undefined ||
    value.length < 512 ||
    value.length > 16_384 ||
    !value.startsWith("-----BEGIN PRIVATE KEY-----\n") ||
    !value.endsWith("\n-----END PRIVATE KEY-----")
  ) {
    throw new BrokerError("GITHUB_APP_KEY_UNAVAILABLE", 503, false);
  }
  return value;
}
