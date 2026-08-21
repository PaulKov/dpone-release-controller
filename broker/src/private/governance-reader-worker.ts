import { GOVERNANCE_READER_PERMISSIONS } from "../activation-contract";
import { TRUST } from "../config";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { assert, BrokerError, errorResponse, jsonResponse } from "../errors";
import { parseJsonObject, requestId } from "../validation";
import { GitHubAppTokenProvider, type GitHubAppConfig } from "./github-app";
import { GitHubOidcEvidenceReader, parseGitHubOidcEvidenceRequest } from "./github-oidc-evidence";
import {
  parseTargetLineageRpcRequest,
  TARGET_LINEAGE_RPC_PATH,
  TARGET_LINEAGE_RPC_RESPONSE_SCHEMA,
  TargetLineageReader,
} from "./target-lineage-reader";
import {
  parseTargetRulesetRequest,
  TARGET_RULESET_RPC_PATH,
  TargetRulesetReader,
} from "./target-ruleset-reader";

interface GovernanceReaderEnv {
  readonly CF_ACCOUNT_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly GITHUB_APP_ID?: string;
  readonly GITHUB_APP_INSTALLATION_ID?: string;
  readonly GITHUB_APP_PRIVATE_KEY?: string;
  readonly OPERATING_MODE: string;
  readonly SERVICE_NAME?: string;
}

/** Private target governance observer with no mutation-capable credentials. */
export default {
  async fetch(request: Request, env: GovernanceReaderEnv): Promise<Response> {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      const url = new URL(request.url);
      if (request.method !== "POST" || url.search !== "") {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      assert(request.headers.get("x-request-id") === currentRequestId, "REQUEST_ID_REQUIRED");
      const config = requireConfig(env);
      const appConfig: GitHubAppConfig = {
        appId: config.appId,
        installationId: config.installationId,
        permissions: GOVERNANCE_READER_PERMISSIONS,
        privateKey: config.privateKey,
        repository: TRUST.targetRepository,
        repositoryId: TRUST.targetRepositoryId,
      };
      const tokens = new GitHubAppTokenProvider(appConfig);
      if (url.pathname === TARGET_RULESET_RPC_PATH) {
        const input = parseTargetRulesetRequest(await parseJsonObject(request));
        if (input.requestId !== currentRequestId) {
          throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
        }
        const identity =
          `cloudflare-worker:${config.cloudflareAccountId}/${config.serviceName}` +
          `@${config.workerVersionId}`;
        const response = jsonResponse(
          await new TargetRulesetReader(tokens, identity, config.workerVersionId).observe(input),
        );
        response.headers.set("x-request-id", currentRequestId);
        return response;
      }
      if (url.pathname === TARGET_LINEAGE_RPC_PATH) {
        const input = parseTargetLineageRpcRequest(await parseJsonObject(request));
        if (input.requestId !== currentRequestId) {
          throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
        }
        const response = jsonResponse({
          governance_reader_service_identity:
            `cloudflare-worker:${config.cloudflareAccountId}/${config.serviceName}` +
            `@${config.workerVersionId}`,
          governance_reader_service_version_id: config.workerVersionId,
          request_id: currentRequestId,
          schema: TARGET_LINEAGE_RPC_RESPONSE_SCHEMA,
          schema_version: 1,
          target_lineage: await new TargetLineageReader(tokens).observe(input),
        });
        response.headers.set("x-request-id", currentRequestId);
        return response;
      }
      if (url.pathname !== "/rpc/v1/a0/oidc-subject-customization") {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      const bodyRequestId = parseGitHubOidcEvidenceRequest(await parseJsonObject(request));
      if (bodyRequestId !== currentRequestId) {
        throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
      }
      const result = await new GitHubOidcEvidenceReader(
        {
          cloudflareAccountId: config.cloudflareAccountId,
          observerRole: "governance_reader",
          repository: TRUST.targetRepository,
          repositoryId: TRUST.targetRepositoryId,
          serviceName: config.serviceName,
          workerVersionId: config.workerVersionId,
        },
        tokens,
      ).observe(currentRequestId);
      const response = jsonResponse(result);
      response.headers.set("x-request-id", currentRequestId);
      return response;
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler<GovernanceReaderEnv>;

function requireConfig(env: GovernanceReaderEnv): {
  readonly appId: string;
  readonly cloudflareAccountId: string;
  readonly installationId: string;
  readonly privateKey: string;
  readonly serviceName: string;
  readonly workerVersionId: string;
} {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("PRIVATE_SERVICE_PROVISIONING", 503, true);
  }
  return {
    appId: exact(env.GITHUB_APP_ID, /^[1-9][0-9]{0,31}$/u, 32),
    cloudflareAccountId: exact(env.CF_ACCOUNT_ID, /^[0-9a-f]{32}$/u, 32),
    installationId: exact(env.GITHUB_APP_INSTALLATION_ID, /^[1-9][0-9]{0,31}$/u, 32),
    privateKey: privateKey(env.GITHUB_APP_PRIVATE_KEY),
    serviceName: exact(env.SERVICE_NAME, /^[a-z0-9][a-z0-9-]{1,127}$/u, 128),
    workerVersionId: exact(env.CF_VERSION_METADATA?.id, CLOUDFLARE_UUID, 36),
  };
}

function exact(value: string | undefined, pattern: RegExp, maximum: number): string {
  const match = value === undefined ? null : pattern.exec(value);
  if (value === undefined || value.length > maximum || match?.[0] !== value) {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function privateKey(value: string | undefined): string {
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
