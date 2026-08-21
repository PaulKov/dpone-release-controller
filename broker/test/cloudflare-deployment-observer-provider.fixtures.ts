import { vi } from "vitest";

import { digestObject } from "../src/canonical";
import { projectCloudflareWorkerVersionResources } from "../src/cloudflare-worker-resources";
import {
  SERVICE_AUTHORITY_DEFINITIONS,
  SERVICE_AUTHORITY_ROLES,
  type DeploymentObservationPhase,
  type ExpectedServiceDeployment,
  type ServiceAuthorityInventoryRow,
  type ServiceAuthorityRole,
} from "../src/service-authority";
import type { JsonObject, PrivateServicePin } from "../src/types";
import {
  digest,
  hex,
  requireDefined,
  uuid,
} from "./cloudflare-deployment-observer-common.fixtures";

export { digest, uuid } from "./cloudflare-deployment-observer-common.fixtures";

export const ACCOUNT_ID = "a".repeat(32);
export const OBSERVER_VERSION = uuid(900);
export const INGRESS_VERSION = uuid(899);
export const OBSERVER_SERVICE = "dpone-release-cloudflare-deployment-observer";
export const OBSERVER_IDENTITY = `cloudflare-worker:${ACCOUNT_ID}/${OBSERVER_SERVICE}@${OBSERVER_VERSION}`;
export const REQUEST_ID = "cloudflare-deployment-observation-0001";
export const NOW = Date.parse("2026-08-19T12:00:00.000Z");
export const NETWORK_SURFACE = {
  cert_id: "00000000-0000-0000-0000-000000000901",
  domain_id: hex(901, 32),
  environment: null,
  hostname: "release.example.test",
  service: "dpone-release-authority-broker",
  zone_id: hex(902, 32),
  zone_name: "example.test",
} as const;
export const PIN: PrivateServicePin = {
  serviceIdentity: OBSERVER_IDENTITY,
  serviceName: OBSERVER_SERVICE,
  versionId: OBSERVER_VERSION,
};
export const OBSERVER_CALLER = {
  key: "A".repeat(43),
  serviceIdentity: `cloudflare-worker:${ACCOUNT_ID}/dpone-release-authority-broker@${INGRESS_VERSION}`,
  versionId: INGRESS_VERSION,
};

export async function authorityInventory(): Promise<readonly ServiceAuthorityInventoryRow[]> {
  return Promise.all(
    SERVICE_AUTHORITY_ROLES.map(async (role, index) => {
      const versionId = finalVersion(role);
      const projection = projectCloudflareWorkerVersionResources(
        versionResult(role, versionId).resources,
      );
      return {
        authority_role: role,
        binding: SERVICE_AUTHORITY_DEFINITIONS[role].binding,
        configuration_sha256: digest(index + 100),
        service: SERVICE_AUTHORITY_DEFINITIONS[role].service,
        service_identity: `cloudflare-worker:${ACCOUNT_ID}/${SERVICE_AUTHORITY_DEFINITIONS[role].service}@${versionId}`,
        source_commit_sha: hex(index + 200, 40),
        source_sha256: digest(index + 300),
        version_resource_projection_sha256: await digestObject(projection),
        worker_version_id: versionId,
      };
    }),
  );
}

export async function providerFixture(
  phase: DeploymentObservationPhase,
  options: { readonly driftGetDeployment?: boolean } = {},
): Promise<{
  readonly calls: {
    authorization: string;
    method: string;
    query: string;
    redirect: RequestRedirect | undefined;
  }[];
  readonly expectedDeployments: readonly ExpectedServiceDeployment[];
  readonly fetch: typeof fetch;
}> {
  const calls: {
    authorization: string;
    method: string;
    query: string;
    redirect: RequestRedirect | undefined;
  }[] = [];
  const expectedDeployments = (await Promise.all(
    SERVICE_AUTHORITY_ROLES.map(async (role, index) => {
      const final = await expectedVersion(role, finalVersion(role), "FINAL_AUTHORITY", index, 100);
      return {
        authority_role: role,
        deployment_id: uuid(100 + index),
        deployment_versions:
          phase === "A0_PRE" && role === "release_authority_ingress"
            ? [
                { ...final, percentage: 0 },
                await expectedVersion(role, uuid(999), "BOOTSTRAP_DENY", index + 1000, 100),
              ].sort((left, right) => left.worker_version_id.localeCompare(right.worker_version_id))
            : [final],
        service: SERVICE_AUTHORITY_DEFINITIONS[role].service,
      };
    }),
  )) satisfies readonly ExpectedServiceDeployment[];
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof Request ? input.url : input.href,
    );
    calls.push({
      authorization: new Headers(init?.headers).get("authorization") ?? "",
      method: init?.method ?? "",
      query: url.search,
      redirect: init?.redirect,
    });
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/domains`) {
      return domainListResponse();
    }
    if (
      url.pathname ===
      `/client/v4/accounts/${ACCOUNT_ID}/workers/domains/${NETWORK_SURFACE.domain_id}`
    ) {
      return providerResponse(domainResult(), `ray-${calls.length}`);
    }
    if (url.pathname === `/client/v4/zones/${NETWORK_SURFACE.zone_id}/workers/routes`) {
      return providerResponse([], `ray-${calls.length}`);
    }
    const parts = url.pathname.split("/");
    const scriptIndex = parts.indexOf("scripts");
    const service = parts[scriptIndex + 1];
    const role = roleForService(service);
    const expected = requireDefined(
      expectedDeployments[SERVICE_AUTHORITY_ROLES.indexOf(role)],
      `missing expected deployment for ${role}`,
    );
    const deployment = deploymentResult(role, expected);
    let result: JsonObject;
    if (parts[scriptIndex + 2] === "deployments" && parts.length === scriptIndex + 3) {
      result = { deployments: [deployment] };
    } else if (parts[scriptIndex + 2] === "deployments") {
      result = structuredClone(deployment);
      if (options.driftGetDeployment) result.source = "dash";
    } else if (parts[scriptIndex + 2] === "versions") {
      const versionId = parts[scriptIndex + 3];
      if (versionId === undefined) throw new Error("missing version path");
      result = versionResult(role, versionId);
    } else if (parts[scriptIndex + 2] === "script-settings") {
      result = scriptSettingsResult();
    } else if (parts[scriptIndex + 2] === "subdomain") {
      result = { enabled: false, previews_enabled: false };
    } else {
      throw new Error(`unexpected provider path ${url.pathname}`);
    }
    return providerResponse(result, `ray-${calls.length}`);
  });
  return { calls, expectedDeployments, fetch };
}

async function expectedVersion(
  role: ServiceAuthorityRole,
  workerVersionId: string,
  artifactKind: "BOOTSTRAP_DENY" | "FINAL_AUTHORITY",
  index: number,
  percentage: number,
) {
  const projection = projectCloudflareWorkerVersionResources(
    versionResult(role, workerVersionId).resources,
  );
  return {
    artifact_kind: artifactKind,
    configuration_sha256:
      artifactKind === "FINAL_AUTHORITY"
        ? digest(SERVICE_AUTHORITY_ROLES.indexOf(role) + 100)
        : digest(index + 100),
    percentage,
    provisioning_record_id: digest(index + 500),
    provisioning_record_sha256: digest(index + 600),
    script_etag: `provider-script-etag-${workerVersionId}`,
    source_sha256:
      artifactKind === "FINAL_AUTHORITY"
        ? digest(SERVICE_AUTHORITY_ROLES.indexOf(role) + 300)
        : digest(index + 300),
    version_resource_projection_sha256: await digestObject(projection),
    worker_version_id: workerVersionId,
  } as const;
}

function domainResult(): JsonObject {
  return {
    cert_id: NETWORK_SURFACE.cert_id,
    hostname: NETWORK_SURFACE.hostname,
    id: NETWORK_SURFACE.domain_id,
    service: NETWORK_SURFACE.service,
    zone_id: NETWORK_SURFACE.zone_id,
    zone_name: NETWORK_SURFACE.zone_name,
  };
}

function domainListResponse(): Response {
  return new Response(
    JSON.stringify({
      errors: [],
      messages: [],
      result: [domainResult()],
      result_info: { count: 1, page: 1, per_page: 20, total_count: 1, total_pages: 1 },
      success: true,
    }),
    {
      headers: { "cf-ray": "ray-domains", "content-type": "application/json" },
      status: 200,
    },
  );
}

function scriptSettingsResult(): JsonObject {
  return {
    logpush: false,
    observability: {
      enabled: false,
      head_sampling_rate: 0,
      logs: {
        destinations: [],
        enabled: false,
        head_sampling_rate: 0,
        invocation_logs: false,
        persist: false,
      },
      traces: {
        destinations: [],
        enabled: false,
        head_sampling_rate: 0,
        persist: false,
        propagation_policy: "authenticated",
      },
    },
    tags: [],
    tail_consumers: [],
  };
}

function deploymentResult(
  role: ServiceAuthorityRole,
  expected: ExpectedServiceDeployment,
): JsonObject {
  return {
    annotations: {
      "workers/message": "reviewed authority deployment",
      "workers/triggered_by": "versions deploy",
    },
    author_email: "operator+secret@example.invalid",
    created_on: "2026-08-19T11:59:00.000Z",
    id: uuid(100 + SERVICE_AUTHORITY_ROLES.indexOf(role)),
    source: "wrangler",
    strategy: "percentage",
    versions: expected.deployment_versions.map((member) => ({
      percentage: member.percentage,
      version_id: member.worker_version_id,
    })),
  };
}

function versionResult(role: ServiceAuthorityRole, versionId: string): JsonObject {
  const bindings: JsonObject[] = [
    { name: "CF_VERSION_METADATA", type: "version_metadata" },
    { name: "OPERATING_MODE", text: "live", type: "plain_text" },
    { name: "SERVICE_NAME", text: SERVICE_AUTHORITY_DEFINITIONS[role].service, type: "plain_text" },
  ];
  if (role === "cloudflare_deployment_observer") {
    bindings.push({ name: "CLOUDFLARE_API_TOKEN", type: "secret_text" });
  }
  const exports: JsonObject = {
    default: { state: "created", type: "worker" },
  };
  const namedHandlers: JsonObject[] = [];
  if (role === "release_authority_ingress") {
    const durableBindings = [
      "ACTIVATION_REGISTRY",
      "AUTH_REPLAY_LEDGER",
      "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
      "RELEASE_LEDGERS",
    ] as const;
    for (const [index, className] of [
      "ActivationRegistry",
      "AuthReplayLedger",
      "GlobalActivatedAuthorityHead",
      "ReleaseLedger",
    ].entries()) {
      exports[className] = { state: "created", storage: "sqlite", type: "durable-object" };
      namedHandlers.push({ handlers: [], name: className });
      bindings.push({
        class_name: className,
        name: requireDefined(durableBindings[index], `missing Durable Object binding ${className}`),
        namespace_id: hex(index + 1, 32),
        type: "durable_object_namespace",
      });
    }
  }
  return {
    id: versionId,
    metadata: {
      author_email: "operator+secret@example.invalid",
      author_id: "operator-secret-id",
      created_on: "2026-08-19T11:58:00.000Z",
      hasPreview: false,
      modified_on: "2026-08-19T11:58:00.000Z",
      source: "wrangler",
    },
    number: 1,
    resources: {
      bindings,
      script: {
        etag: `provider-script-etag-${versionId}`,
        handlers: ["fetch"],
        last_deployed_from: "wrangler",
        named_handlers: namedHandlers,
      },
      script_runtime: {
        compatibility_date: "2026-08-15",
        compatibility_flags: [],
        exports,
        limits: { cpu_ms: 30_000 },
        ...(role === "release_authority_ingress" ? { migration_tag: "v3" } : {}),
        usage_model: "standard",
      },
    },
  };
}

function providerResponse(result: unknown, requestId: string): Response {
  return new Response(JSON.stringify({ errors: [], messages: [], result, success: true }), {
    headers: { "cf-ray": requestId, "content-type": "application/json; charset=utf-8" },
    status: 200,
  });
}

function roleForService(value: string | undefined): ServiceAuthorityRole {
  const entry = Object.entries(SERVICE_AUTHORITY_DEFINITIONS).find(
    ([, definition]) => definition.service === value,
  );
  if (entry === undefined) throw new Error("unknown authority service");
  return entry[0] as ServiceAuthorityRole;
}

function finalVersion(role: ServiceAuthorityRole): string {
  return uuid(1 + SERVICE_AUTHORITY_ROLES.indexOf(role));
}
