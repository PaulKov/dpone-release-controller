import { jsonResponse, BrokerError, errorResponse } from "../errors";
import { CONTROLLER_RUN_READER_PERMISSIONS } from "../activation-contract";
import { TRUST } from "../config";
import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { parseJsonObject, requestId } from "../validation";
import { GitHubAppTokenProvider, type GitHubAppConfig } from "./github-app";
import {
  ControllerRunReader,
  type ControllerRunReaderConfig,
  parseControllerRunRequest,
} from "./controller-run-reader";
import {
  ControllerActionBundleReader,
  parseControllerActionBundleObservationRequest,
} from "./controller-action-bundle-reader";
import { GitHubOidcEvidenceReader, parseGitHubOidcEvidenceRequest } from "./github-oidc-evidence";

interface ControllerRunReaderEnv {
  readonly CF_ACCOUNT_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly GITHUB_APP_ID?: string;
  readonly GITHUB_APP_INSTALLATION_ID?: string;
  readonly GITHUB_APP_PRIVATE_KEY?: string;
  readonly GITHUB_APP_SLUG?: string;
  readonly OPERATING_MODE: string;
  readonly SERVICE_NAME?: string;
}

interface PrivateConfig extends ControllerRunReaderConfig {
  readonly cloudflareAccountId: string;
  readonly serviceName: string;
}

/** Private, route-less Service Binding Worker for controller run admission. */
export default {
  async fetch(request: Request, env: ControllerRunReaderEnv): Promise<Response> {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      const url = new URL(request.url);
      if (request.method !== "POST" || url.search !== "") {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      const config = requireConfig(env);
      const appConfig: GitHubAppConfig = {
        appId: config.appId,
        installationId: config.installationId,
        permissions: CONTROLLER_RUN_READER_PERMISSIONS,
        privateKey: requirePrivateKey(env.GITHUB_APP_PRIVATE_KEY),
        repository: TRUST.controllerRepository,
        repositoryId: TRUST.controllerRepositoryId,
      };
      const tokens = new GitHubAppTokenProvider(appConfig);
      const body = await parseJsonObject(request);
      let result;
      if (url.pathname === "/rpc/v1/a0/controller-action-bundle") {
        const input = parseControllerActionBundleObservationRequest(body);
        if (input.requestId !== currentRequestId) {
          throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
        }
        result = await new ControllerActionBundleReader(config, tokens).observe(input);
      } else if (url.pathname === "/rpc/v1/verify-check-run") {
        const input = parseControllerRunRequest(body);
        if (input.requestId !== currentRequestId) {
          throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
        }
        result = await new ControllerRunReader(config, tokens).verify(input);
      } else if (url.pathname === "/rpc/v1/a0/oidc-subject-customization") {
        const evidenceRequestId = parseGitHubOidcEvidenceRequest(body);
        if (evidenceRequestId !== currentRequestId) {
          throw new BrokerError("REQUEST_ID_MISMATCH", 400, false);
        }
        result = await new GitHubOidcEvidenceReader(
          {
            cloudflareAccountId: config.cloudflareAccountId,
            observerRole: "controller_run_reader",
            repository: TRUST.controllerRepository,
            repositoryId: TRUST.controllerRepositoryId,
            serviceName: config.serviceName,
            workerVersionId: config.workerVersionId,
          },
          tokens,
        ).observe(currentRequestId);
      } else {
        throw new BrokerError("PRIVATE_ROUTE_NOT_FOUND", 404, false);
      }
      const response = jsonResponse(result);
      response.headers.set("x-request-id", currentRequestId);
      return response;
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler<ControllerRunReaderEnv>;

function requireConfig(env: ControllerRunReaderEnv): PrivateConfig {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("PRIVATE_SERVICE_PROVISIONING", 503, true);
  }
  const workerVersionId = env.CF_VERSION_METADATA?.id;
  if (workerVersionId === undefined || !CLOUDFLARE_UUID.test(workerVersionId)) {
    throw new BrokerError("PRIVATE_SERVICE_VERSION_UNAVAILABLE", 503, false);
  }
  return {
    appId: positiveId(env.GITHUB_APP_ID),
    appSlug: safeName(env.GITHUB_APP_SLUG),
    cloudflareAccountId: cloudflareAccountId(env.CF_ACCOUNT_ID),
    installationId: positiveId(env.GITHUB_APP_INSTALLATION_ID),
    serviceName: serviceName(env.SERVICE_NAME),
    workerVersionId,
  };
}

function cloudflareAccountId(value: string | undefined): string {
  if (value === undefined || !/^[0-9a-f]{32}$/u.test(value)) {
    throw new BrokerError("PRIVATE_SERVICE_IDENTITY_UNAVAILABLE", 503, false);
  }
  return value;
}

function serviceName(value: string | undefined): string {
  if (value === undefined || !/^[a-z0-9][a-z0-9-]{1,127}$/u.test(value)) {
    throw new BrokerError("PRIVATE_SERVICE_IDENTITY_UNAVAILABLE", 503, false);
  }
  return value;
}

function positiveId(value: string | undefined): string {
  if (value === undefined || !/^[1-9][0-9]{0,31}$/u.test(value)) {
    throw new BrokerError("GITHUB_APP_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function safeName(value: string | undefined): string {
  if (value === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/u.test(value)) {
    throw new BrokerError("GITHUB_APP_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function requirePrivateKey(value: string | undefined): string {
  if (value === undefined || value.length < 512 || value.length > 16_384) {
    throw new BrokerError("GITHUB_APP_KEY_UNAVAILABLE", 503, false);
  }
  return value;
}
