import { describe, expect, it } from "vitest";

import { digestObject } from "../src/canonical";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  buildServiceAuthorityObservation,
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
  RECEIPT_ROLE_BINDINGS,
  SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
} from "../src/service-authority-activation";
import { SERVICE_AUTHORITY_DEFINITIONS, SERVICE_AUTHORITY_ROLES } from "../src/service-authority";
import type { JsonObject } from "../src/types";

const ACCOUNT_ID = "a".repeat(32);
const SOURCE_COMMIT = "b".repeat(40);

describe("service-authority activation contract", () => {
  it("cross-binds every reviewed authority row before a provider call", async () => {
    const fixture = await expectationFixture();
    const parsed = await parseServiceAuthorityExpectation(
      fixture.document,
      fixture.digest,
      ACCOUNT_ID,
      SOURCE_COMMIT,
    );
    expect(() =>
      assertServiceAuthorityExpectationMatchesBroker(parsed, brokerFixture(fixture.document)),
    ).not.toThrow();

    const drift = brokerFixture(fixture.document);
    const privateServices = drift.private_services as JsonObject;
    const observer = privateServices.cloudflare_deployment_observer as JsonObject;
    observer.worker_version_id = uuid(999);
    observer.service_identity = `cloudflare-worker:${ACCOUNT_ID}/${requiredString(observer, "service")}@${uuid(999)}`;
    expect(() => assertServiceAuthorityExpectationMatchesBroker(parsed, drift)).toThrow(
      "SERVICE_AUTHORITY_BROKER_CROSS_BIND_MISMATCH",
    );
  });

  it("materializes only the future ingress deployment id and preserves immutable provenance", async () => {
    const fixture = await expectationFixture();
    const parsed = await parseServiceAuthorityExpectation(
      fixture.document,
      fixture.digest,
      ACCOUNT_ID,
      SOURCE_COMMIT,
    );
    const deploymentId = uuid(800);
    const materialized = materializeA1PrecommitDeployments(
      parsed.a1PrecommitDeployments,
      deploymentId,
    );
    expect(
      materialized.find((row) => row.authority_role === "release_authority_ingress")?.deployment_id,
    ).toBe(deploymentId);
    expect(
      materialized
        .filter((row) => row.authority_role !== "release_authority_ingress")
        .every((row) => row.deployment_id !== deploymentId),
    ).toBe(true);
  });

  it("covers compact provider projections and every WORM pointer in the aggregate digest", async () => {
    const fixture = await expectationFixture();
    const accepted = acceptedObservation(fixture.digest);
    const first = await buildServiceAuthorityObservation(accepted, fixture.digest);
    const tampered = structuredClone(accepted);
    const firstEvidence = requireDefined(
      tampered.serviceEvidenceEntries[0],
      "missing first service evidence entry",
    );
    const firstWorm = firstEvidence.worm as JsonObject;
    firstWorm.key = `${requiredString(firstWorm, "key")}.tampered`;
    const second = await buildServiceAuthorityObservation(tampered, fixture.digest);

    expect(first.services).toHaveLength(14);
    expect(first.provider_observation_sha256).not.toBe(second.provider_observation_sha256);
    expect(JSON.stringify(first)).toContain("deployment_projection");
    expect(JSON.stringify(first)).toContain("version_resource_projection");
  });
});

async function expectationFixture(): Promise<{ document: JsonObject; digest: string }> {
  const authorities = SERVICE_AUTHORITY_ROLES.map((authorityRole, index) => {
    const definition = SERVICE_AUTHORITY_DEFINITIONS[authorityRole];
    const workerVersionId = uuid(index + 10);
    return {
      authority_role: authorityRole,
      binding: definition.binding,
      configuration_sha256: digest(index + 10),
      service: definition.service,
      service_identity: `cloudflare-worker:${ACCOUNT_ID}/${definition.service}@${workerVersionId}`,
      source_commit_sha: SOURCE_COMMIT,
      source_sha256: digest(index + 30),
      version_resource_projection_sha256: digest(index + 50),
      worker_version_id: workerVersionId,
    };
  });
  const a0 = authorities.map((authority, index) => ({
    authority_role: authority.authority_role,
    deployment_id: uuid(index + 100),
    deployment_versions:
      authority.authority_role === "release_authority_ingress"
        ? [
            deploymentMember("BOOTSTRAP_DENY", uuid(1), 100, index + 200),
            deploymentMember(
              "FINAL_AUTHORITY",
              authority.worker_version_id,
              0,
              index + 300,
              authority,
            ),
          ].sort((left, right) => left.worker_version_id.localeCompare(right.worker_version_id))
        : [
            deploymentMember(
              "FINAL_AUTHORITY",
              authority.worker_version_id,
              100,
              index + 300,
              authority,
            ),
          ],
    service: authority.service,
  }));
  const a1 = authorities.map((authority, index) => ({
    authority_role: authority.authority_role,
    deployment_id:
      authority.authority_role === "release_authority_ingress" ? null : uuid(index + 100),
    deployment_versions: [
      deploymentMember("FINAL_AUTHORITY", authority.worker_version_id, 100, index + 300, authority),
    ],
    service: authority.service,
  }));
  const document: JsonObject = {
    authorities,
    broker_source_commit_sha: SOURCE_COMMIT,
    cloudflare_account_id: ACCOUNT_ID,
    deployment_expectations: { a0_pre: a0, a1_precommit: a1 },
    network_surface: {
      cert_id: uuid(700),
      domain_id: hex(701, 32),
      environment: "production",
      hostname: "release.example.test",
      service: SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service,
      zone_id: hex(702, 32),
      zone_name: "example.test",
    },
    receipt_role_bindings: RECEIPT_ROLE_BINDINGS.map((row) => ({ ...row })),
    schema: SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
    schema_version: 1,
  };
  return { digest: await digestObject(document), document };
}

function deploymentMember(
  artifactKind: "BOOTSTRAP_DENY" | "FINAL_AUTHORITY",
  workerVersionId: string,
  percentage: number,
  seed: number,
  authority?: {
    configuration_sha256: string;
    source_sha256: string;
    version_resource_projection_sha256: string;
  },
) {
  return {
    artifact_kind: artifactKind,
    configuration_sha256: authority?.configuration_sha256 ?? digest(seed + 1),
    percentage,
    provisioning_record_id: digest(seed + 2),
    provisioning_record_sha256: digest(seed + 3),
    script_etag: `etag-${seed}`,
    source_sha256: authority?.source_sha256 ?? digest(seed + 4),
    version_resource_projection_sha256:
      authority?.version_resource_projection_sha256 ?? digest(seed + 5),
    worker_version_id: workerVersionId,
  };
}

function brokerFixture(document: JsonObject): JsonObject {
  const authorities = document.authorities as JsonObject[];
  const networkSurface = document.network_surface as JsonObject;
  const workerHostname = requiredString(networkSurface, "hostname");
  const ingress = requireDefined(
    authorities.find((row) => row.authority_role === "release_authority_ingress"),
    "missing ingress authority",
  );
  const privateServices: JsonObject = {};
  for (const row of authorities) {
    const authorityRole = requiredString(row, "authority_role");
    if (authorityRole === "release_authority_ingress") continue;
    privateServices[authorityRole] = {
      binding: requiredString(row, "binding"),
      configuration_sha256: requiredString(row, "configuration_sha256"),
      service: requiredString(row, "service"),
      service_identity: requiredString(row, "service_identity"),
      source_commit_sha: requiredString(row, "source_commit_sha"),
      source_sha256: requiredString(row, "source_sha256"),
      version_resource_projection_sha256: requiredString(row, "version_resource_projection_sha256"),
      worker_version_id: requiredString(row, "worker_version_id"),
    };
  }
  return {
    configuration_sha256: requiredString(ingress, "configuration_sha256"),
    endpoint: `https://${workerHostname}`,
    private_services: privateServices,
    service_identity: requiredString(ingress, "service_identity"),
    source_commit_sha: requiredString(ingress, "source_commit_sha"),
    source_sha256: requiredString(ingress, "source_sha256"),
    version_resource_projection_sha256: requiredString(
      ingress,
      "version_resource_projection_sha256",
    ),
    worker_hostname: workerHostname,
    worker_script: requiredString(ingress, "service"),
    worker_version_id: requiredString(ingress, "worker_version_id"),
  };
}

function acceptedObservation(expectationSha256: string) {
  const services = SERVICE_AUTHORITY_ROLES.map((authorityRole, index) => ({
    authority_role: authorityRole,
    current_deployment_id: uuid(index + 100),
    deployment_created_on: "2026-08-19T12:00:00.000Z",
    deployment_source: "api",
    deployment_strategy: "percentage",
    deployment_versions: [{ percentage: 100, version_id: uuid(index + 10) }],
    get_deployment_provider_response_sha256: digest(index + 600),
    list_deployments_provider_response_sha256: digest(index + 620),
    script_settings: {
      logpush: false,
      observability: { enabled: false },
      tags: [],
      tail_consumers: [],
    },
    script_settings_provider_response_sha256: digest(index + 640),
    service: SERVICE_AUTHORITY_DEFINITIONS[authorityRole].service,
    subdomain: { enabled: false, previews_enabled: false },
    subdomain_provider_response_sha256: digest(index + 660),
    versions: [
      {
        created_on: "2026-08-19T12:00:00.000Z",
        get_version_provider_response_sha256: digest(index + 680),
        has_preview: false,
        modified_on: "2026-08-19T12:00:00.000Z",
        source: "api",
        version_number: 1,
        version_resource_projection: { script: { etag: `etag-${index}` } },
        version_resource_projection_sha256: digest(index + 700),
        worker_version_id: uuid(index + 10),
      },
    ],
  }));
  const b2ObserverIndex = SERVICE_AUTHORITY_ROLES.indexOf("worm_version_observer");
  const b2ObserverService = SERVICE_AUTHORITY_DEFINITIONS.worm_version_observer.service;
  const wormIndex = SERVICE_AUTHORITY_ROLES.indexOf("worm_mirror");
  const wormService = SERVICE_AUTHORITY_DEFINITIONS.worm_mirror.service;
  return {
    b2ObserverServiceIdentity: `cloudflare-worker:${ACCOUNT_ID}/${b2ObserverService}@${uuid(b2ObserverIndex + 10)}`,
    brokerAcceptedAt: "2026-08-19T12:00:01.000Z",
    networkSurfaceEvidenceEntry: networkEvidenceEntry(),
    observation: {
      expectation_sha256: expectationSha256,
      network_surface: {
        domain: { hostname: "release.example.test" },
        get_domain_provider_response_sha256: digest(801),
        list_domains_provider_response_sha256: digest(802),
        list_routes_provider_response_sha256: digest(803),
        routes: [],
      },
      observed_at: "2026-08-19T12:00:00.000Z",
      observer_service_identity: `cloudflare-worker:${ACCOUNT_ID}/dpone-release-cloudflare-deployment-observer@${uuid(900)}`,
      observer_worker_version_id: uuid(900),
      phase: "A1_PRECOMMIT",
      provider_observation_sha256: digest(800),
      services,
    } as JsonObject,
    serviceEvidenceEntries: services.map((service, index) => serviceEvidenceEntry(service, index)),
    wormServiceIdentity: `cloudflare-worker:${ACCOUNT_ID}/${wormService}@${uuid(wormIndex + 10)}`,
  };
}

function serviceEvidenceEntry(service: JsonObject, index: number): JsonObject {
  const recordSha = digest(index + 900);
  return {
    authority_role: requiredString(service, "authority_role"),
    deployment_observation_record: {},
    deployment_observation_record_id: digest(index + 850),
    deployment_observation_record_sha256: recordSha,
    deployment_observation_sha256: digest(index + 870),
    worm: worm(recordSha, `service-${index}`),
  };
}

function networkEvidenceEntry(): JsonObject {
  const recordSha = digest(980);
  return {
    network_surface_observation_record: {},
    network_surface_observation_record_id: digest(981),
    network_surface_observation_record_sha256: recordSha,
    network_surface_observation_sha256: digest(982),
    worm: worm(recordSha, "network"),
  };
}

function worm(recordSha: string, suffix: string): JsonObject {
  return {
    digest: recordSha,
    key: `receipts/v1/cloudflare-observations/${suffix}.json`,
    retention_until: "2033-08-19T12:00:00.000Z",
    version_id: `worm-version-${suffix}`,
  };
}

function digest(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}

function hex(value: number, length: number): string {
  return value.toString(16).padStart(length, "0");
}

function uuid(value: number): string {
  return `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`;
}

function requiredString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`missing ${key}`);
  return candidate;
}

function requireDefined<T>(value: T | null | undefined, message: string): T {
  if (value === null || value === undefined) throw new Error(message);
  return value;
}
