import { CLOUDFLARE_UUID } from "../cloudflare-ids";
import { BrokerError } from "../errors";
import type { WormRpcCallerAuth } from "../worm-rpc-auth";

const ACCOUNT_ID = /^[0-9a-f]{32}$/u;
const SERVICE_NAME = /^[a-z0-9][a-z0-9-]{1,127}$/u;

export interface CloudflareDeploymentObserverEnv {
  readonly APPROVED_INGRESS_HOSTNAME?: string;
  readonly APPROVED_INGRESS_ZONE_ID?: string;
  readonly CF_ACCOUNT_ID?: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly CLOUDFLARE_API_TOKEN?: string;
  readonly CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY?: string;
  readonly CLOUDFLARE_OBSERVER_RPC_AUTH_KEY?: string;
  readonly EXPECTED_INGRESS_SERVICE_IDENTITY?: string;
  readonly OPERATING_MODE: string;
  readonly SERVICE_NAME?: string;
  readonly WORM_MIRROR?: Fetcher;
}

export interface CloudflareDeploymentObserverConfig {
  readonly accountId: string;
  readonly approvedIngressHostname: string;
  readonly approvedIngressZoneId: string;
  readonly apiToken: string;
  readonly expectedIngressServiceIdentity: string;
  readonly observerRpcAuthKey: string;
  readonly serviceIdentity: string;
  readonly serviceName: string;
  readonly workerVersionId: string;
  readonly wormCallerAuth: WormRpcCallerAuth;
  readonly wormService: Fetcher;
}

export function requireCloudflareDeploymentObserverConfig(
  env: CloudflareDeploymentObserverEnv,
): CloudflareDeploymentObserverConfig {
  if (env.OPERATING_MODE !== "live") {
    throw new BrokerError("PRIVATE_SERVICE_PROVISIONING", 503, true);
  }
  const accountId = exact(env.CF_ACCOUNT_ID, ACCOUNT_ID, 32);
  const serviceName = exact(env.SERVICE_NAME, SERVICE_NAME, 128);
  if (serviceName !== "dpone-release-cloudflare-deployment-observer") {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  const workerVersionId = exact(env.CF_VERSION_METADATA?.id, CLOUDFLARE_UUID, 36);
  const serviceIdentity = `cloudflare-worker:${accountId}/${serviceName}@${workerVersionId}`;
  const expectedIngressServiceIdentity = exact(
    env.EXPECTED_INGRESS_SERVICE_IDENTITY,
    /^cloudflare-worker:[0-9a-f]{32}\/dpone-release-authority-broker@[0-9a-f-]{36}$/u,
    512,
  );
  if (!expectedIngressServiceIdentity.startsWith(`cloudflare-worker:${accountId}/`)) {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  const approvedIngressHostname = exact(
    env.APPROVED_INGRESS_HOSTNAME,
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u,
    253,
  );
  const approvedIngressZoneId = exact(env.APPROVED_INGRESS_ZONE_ID, ACCOUNT_ID, 32);
  if (approvedIngressHostname.endsWith(".invalid") || approvedIngressZoneId === "0".repeat(32)) {
    throw new BrokerError("CLOUDFLARE_NETWORK_SCOPE_UNRESOLVED", 503, false);
  }
  return {
    accountId,
    approvedIngressHostname,
    approvedIngressZoneId,
    apiToken: secret(env.CLOUDFLARE_API_TOKEN),
    expectedIngressServiceIdentity,
    observerRpcAuthKey: exactSecret(env.CLOUDFLARE_OBSERVER_RPC_AUTH_KEY, 43, 43),
    serviceIdentity,
    serviceName,
    workerVersionId,
    wormCallerAuth: {
      key: exactSecret(env.CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY, 43, 43),
      serviceIdentity,
      versionId: workerVersionId,
    },
    wormService: fetcher(env.WORM_MIRROR),
  };
}

function fetcher(value: Fetcher | undefined): Fetcher {
  if (value === undefined || typeof value.fetch !== "function") {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function exactSecret(value: string | undefined, minimum: number, maximum: number): string {
  if (
    value === undefined ||
    value.length < minimum ||
    value.length > maximum ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function exact(value: string | undefined, pattern: RegExp, maximum: number): string {
  pattern.lastIndex = 0;
  const match = value === undefined ? null : pattern.exec(value);
  if (value === undefined || value.length > maximum || match?.[0] !== value) {
    throw new BrokerError("PRIVATE_SERVICE_CONFIGURATION_INVALID", 503, false);
  }
  return value;
}

function secret(value: string | undefined): string {
  if (
    value === undefined ||
    value.length < 20 ||
    value.length > 512 ||
    !/^[\x21-\x7e]+$/u.test(value) ||
    /\s/u.test(value)
  ) {
    throw new BrokerError("CLOUDFLARE_API_TOKEN_UNAVAILABLE", 503, false);
  }
  return value;
}
