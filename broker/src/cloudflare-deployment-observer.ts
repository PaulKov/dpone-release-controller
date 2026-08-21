import { canonicalJson, digestObject } from "./canonical";
import {
  MAX_EVIDENCE_ENTRY_BYTES,
  MAX_PARALLEL_SERVICES,
  ACCOUNT_ID,
  SERVICE_IDENTITY,
  VERSION,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
  CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA,
  CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA,
  CLOUDFLARE_NETWORK_EVIDENCE_KIND,
  CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA,
  type CloudflareDeploymentObservationRequest,
  type CloudflareDeploymentObservationResult,
  type ObservedNetworkSurface,
  type ObservedService,
} from "./cloudflare-deployment-observation-contract";
import {
  canonicalUtcMilliseconds,
  compareWorkerVersion,
  deploymentJson,
  mapConcurrent,
  requireJsonObject,
  validateRequest,
} from "./cloudflare-deployment-observation-common";
import { assertCloudflareDeploymentEvidenceSet } from "./cloudflare-deployment-observation-evidence";
import {
  assertDeploymentMatchesExpected,
  assertExpectedNetworkSurface,
  parseDeployment,
  parseDeploymentList,
  parseVersionObservation,
  rawEvidenceRow,
  rawNetworkEvidenceRow,
} from "./cloudflare-deployment-observation-provider";
import {
  projectCloudflareScriptSettings,
  projectCloudflareWorkerDomain,
  projectCloudflareWorkerRoutes,
  projectCloudflareWorkerSubdomain,
  projectCloudflareWorkersDomains,
} from "./cloudflare-worker-topology";
import { assert, BrokerError } from "./errors";
import type {
  ExpectedCloudflareNetworkSurface,
  ExpectedServiceDeployment,
} from "./service-authority";
import type { JsonObject } from "./types";
import { requireString } from "./validation";
import type {
  CloudflareProviderRead,
  CloudflareWorkersDeploymentReader,
} from "./private/cloudflare-provider";

/** Freshly re-query all fourteen allowlisted Worker deployments and versions. */
export class CloudflareDeploymentObserver {
  public constructor(
    private readonly reader: CloudflareWorkersDeploymentReader,
    private readonly cloudflareAccountId: string,
    private readonly observerServiceIdentity: string,
    private readonly observerWorkerVersionId: string,
    private readonly now: () => number = Date.now,
  ) {
    assert(
      ACCOUNT_ID.test(cloudflareAccountId) &&
        SERVICE_IDENTITY.test(observerServiceIdentity) &&
        VERSION.test(observerWorkerVersionId) &&
        observerServiceIdentity.startsWith(
          `cloudflare-worker:${cloudflareAccountId}/dpone-release-cloudflare-deployment-observer@`,
        ) &&
        observerServiceIdentity.endsWith(`@${observerWorkerVersionId}`),
      "CLOUDFLARE_DEPLOYMENT_OBSERVER_IDENTITY_INVALID",
      500,
    );
  }

  public async observe(
    request: CloudflareDeploymentObservationRequest,
  ): Promise<CloudflareDeploymentObservationResult> {
    validateRequest(request);
    const [observedServices, observedNetwork] = await Promise.all([
      mapConcurrent(request.expectedDeployments, MAX_PARALLEL_SERVICES, (expected) =>
        this.observeService(expected),
      ),
      this.observeNetworkSurface(request.expectedNetworkSurface),
    ]);
    const observedAt = canonicalUtcMilliseconds(this.now());
    const unsigned: JsonObject = {
      cloudflare_account_id: this.cloudflareAccountId,
      expectation_sha256: request.expectationSha256,
      network_surface: observedNetwork.observation,
      observed_at: observedAt,
      observer_service_identity: this.observerServiceIdentity,
      observer_worker_version_id: this.observerWorkerVersionId,
      phase: request.phase,
      schema: CLOUDFLARE_DEPLOYMENT_OBSERVATION_SCHEMA,
      schema_version: 1,
      services: observedServices.map((service) => service.observation),
    };
    const providerObservationSha256 = await digestObject(unsigned);
    const observation: JsonObject = {
      ...unsigned,
      provider_observation_sha256: providerObservationSha256,
    };
    const evidenceEntries = observedServices.map((service, index) => {
      const expected = request.expectedDeployments[index];
      if (expected === undefined) {
        throw new BrokerError("CLOUDFLARE_DEPLOYMENT_OBSERVATION_INVALID", 500, false);
      }
      const evidence: JsonObject = {
        authority_role: expected.authority_role,
        cloudflare_account_id: this.cloudflareAccountId,
        evidence_kind: CLOUDFLARE_DEPLOYMENT_EVIDENCE_KIND,
        expectation_sha256: request.expectationSha256,
        observed_at: observedAt,
        observer_service_identity: this.observerServiceIdentity,
        observer_worker_version_id: this.observerWorkerVersionId,
        phase: request.phase,
        provider_observation_sha256: providerObservationSha256,
        raw_responses: service.evidenceReads.map((read) => rawEvidenceRow(expected, read)),
        schema: CLOUDFLARE_DEPLOYMENT_EVIDENCE_SCHEMA,
        schema_version: 1,
        service: expected.service,
        service_observation: service.observation,
      };
      assert(
        new TextEncoder().encode(canonicalJson(evidence)).byteLength <= MAX_EVIDENCE_ENTRY_BYTES,
        "CLOUDFLARE_DEPLOYMENT_EVIDENCE_TOO_LARGE",
        503,
      );
      return evidence;
    });
    const networkEvidenceEntry: JsonObject = {
      cloudflare_account_id: this.cloudflareAccountId,
      evidence_kind: CLOUDFLARE_NETWORK_EVIDENCE_KIND,
      expectation_sha256: request.expectationSha256,
      network_surface_observation: observedNetwork.observation,
      observed_at: observedAt,
      observer_service_identity: this.observerServiceIdentity,
      observer_worker_version_id: this.observerWorkerVersionId,
      phase: request.phase,
      provider_observation_sha256: providerObservationSha256,
      raw_responses: observedNetwork.evidenceReads.map(rawNetworkEvidenceRow),
      schema: CLOUDFLARE_NETWORK_EVIDENCE_SCHEMA,
      schema_version: 1,
    };
    assert(
      new TextEncoder().encode(canonicalJson(networkEvidenceEntry)).byteLength <=
        MAX_EVIDENCE_ENTRY_BYTES,
      "CLOUDFLARE_NETWORK_EVIDENCE_TOO_LARGE",
      503,
    );
    await assertCloudflareDeploymentEvidenceSet(observation, evidenceEntries, networkEvidenceEntry);
    return {
      evidenceEntries: Object.freeze(evidenceEntries),
      networkEvidenceEntry,
      observation,
    };
  }

  private async observeService(expected: ExpectedServiceDeployment): Promise<ObservedService> {
    const listed = await this.reader.listDeployments(expected.authority_role);
    const deployments = parseDeploymentList(listed.result);
    const current = deployments[0];
    if (current === undefined) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_MISSING", 503, false);
    }
    assertDeploymentMatchesExpected(current, expected);
    const fetched = await this.reader.getDeployment(expected.authority_role, current.id);
    const fetchedDeployment = parseDeployment(fetched.result);
    if (
      canonicalJson(deploymentJson(current)) !== canonicalJson(deploymentJson(fetchedDeployment))
    ) {
      throw new BrokerError("CLOUDFLARE_DEPLOYMENT_REQUERY_MISMATCH", 503, false);
    }
    const versionReads: CloudflareProviderRead[] = [];
    const versions: JsonObject[] = [];
    for (const member of current.versions) {
      const versionId = requireString(member, "worker_version_id", 128, VERSION);
      const read = await this.reader.getVersion(expected.authority_role, versionId);
      versionReads.push(read);
      const version = await parseVersionObservation(read.result, versionId);
      version.get_version_provider_response_sha256 = read.rawResponseSha256;
      versions.push(version);
    }
    const settingsRead = await this.reader.getScriptSettings(expected.authority_role);
    const settingsProjection = projectCloudflareScriptSettings(settingsRead.result);
    const subdomainRead = await this.reader.getSubdomain(expected.authority_role);
    const subdomainProjection = projectCloudflareWorkerSubdomain(subdomainRead.result);
    versions.sort(compareWorkerVersion);
    const observation: JsonObject = {
      authority_role: expected.authority_role,
      current_deployment_id: current.id,
      deployment_created_on: current.created_on,
      deployment_source: current.source,
      deployment_strategy: "percentage",
      deployment_versions: current.versions.map((member) => ({ ...member })),
      get_deployment_provider_response_sha256: fetched.rawResponseSha256,
      list_deployments_provider_response_sha256: listed.rawResponseSha256,
      script_settings: settingsProjection,
      script_settings_provider_response_sha256: settingsRead.rawResponseSha256,
      service: expected.service,
      subdomain: subdomainProjection,
      subdomain_provider_response_sha256: subdomainRead.rawResponseSha256,
      versions,
    };
    return {
      evidenceReads: Object.freeze([listed, fetched, ...versionReads, settingsRead, subdomainRead]),
      observation,
    };
  }

  private async observeNetworkSurface(
    expected: ExpectedCloudflareNetworkSurface,
  ): Promise<ObservedNetworkSurface> {
    const listed = await this.reader.listDomains();
    const listedProjection = projectCloudflareWorkersDomains(listed.result, listed.resultInfo);
    const listedDomain = requireJsonObject(listedProjection.domain);
    assertExpectedNetworkSurface(listedDomain, expected);
    const fetched = await this.reader.getDomain(expected.domain_id);
    const fetchedDomain = projectCloudflareWorkerDomain(fetched.result);
    if (canonicalJson(listedDomain) !== canonicalJson(fetchedDomain)) {
      throw new BrokerError("CLOUDFLARE_WORKERS_DOMAIN_REQUERY_MISMATCH", 503, false);
    }
    const routes = await this.reader.listRoutes(expected.zone_id);
    const routesProjection = projectCloudflareWorkerRoutes(routes.result);
    return {
      evidenceReads: Object.freeze([listed, fetched, routes]),
      observation: {
        domain: listedDomain,
        get_domain_provider_response_sha256: fetched.rawResponseSha256,
        list_domains_provider_response_sha256: listed.rawResponseSha256,
        list_routes_provider_response_sha256: routes.rawResponseSha256,
        routes: routesProjection,
      },
    };
  }
}
