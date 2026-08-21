import { DurableObject } from "cloudflare:workers";

import {
  assertObservedAtBounded,
  buildActivatedRecord,
  buildProvisionedRecord,
  parseFinalizeRequest,
  parseProvisionRequest,
  provisionedRecordServicePin,
  provisionRequestServicePin,
  verifyProvisionEvidenceDigests,
  verifyAdminAccessPrincipalDigests,
} from "./activation-schema";
import { ActivatedAuthorityHeadClient } from "./activated-authority-head-client";
import {
  assertActivationChronology,
  assertAuthorityObservationCommitFreshness,
  canonicalTimestamp,
  decodeCanonicalObject,
  decodeCanonicalText,
  digestBytes,
  encodeAdminResult,
  requireGlobalHeadNamespace,
  requireObjectField,
  requirePrivateFetcher,
  requireStringField,
  snapshotJson,
} from "./activation-registry-codec";
import { ActivationRegistryEvidence } from "./activation-registry-evidence";
import { ActivationRegistryRecords } from "./activation-registry-records";
import { verifyActivationSnapshot } from "./activation-snapshot-verifier";
import { canonicalBytes, canonicalJson } from "./canonical";
import { requireLiveConfig, TRUST } from "./config";
import {
  ControllerActionBundleClient,
  controllerActionBundleAppPin,
} from "./controller-action-bundle-client";
import { BrokerError, errorResponse } from "./errors";
import { GitHubOidcEvidenceClient } from "./github-oidc-evidence-client";
import {
  assertServiceAuthorityExpectationMatchesBroker,
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
} from "./service-authority-activation";
import {
  GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
  RAW_PROVIDER_EVIDENCE_KIND,
} from "./provider-evidence";
import type { ActivationSnapshot, LiveConfigEnv } from "./types";
import { TargetRulesetClient } from "./target-ruleset-client";
import { WormMirrorClient } from "./worm-client";

/**
 * Version-scoped, append-once activation authority.
 *
 * The ingress chooses this DO by immutable Worker version ID. Each version can
 * contain exactly one A0 and one A1. A different deployment gets a new DO key;
 * no record can be replaced or deleted.
 */
export class ActivationRegistry extends DurableObject<LiveConfigEnv> {
  private readonly evidence: ActivationRegistryEvidence;
  private readonly records: ActivationRegistryRecords;
  private serialTail: Promise<void> = Promise.resolve();

  public constructor(ctx: DurableObjectState, env: LiveConfigEnv) {
    super(ctx, env);
    this.evidence = new ActivationRegistryEvidence(env);
    this.records = new ActivationRegistryRecords(ctx.storage, env);
  }

  public provision(canonicalRequest: string): Promise<string> {
    const value = decodeCanonicalText(canonicalRequest);
    return this.exclusive(async () => {
      const config = requireLiveConfig(this.env);
      const request = parseProvisionRequest(value, config);
      const wormPin = provisionRequestServicePin(request, "worm_mirror");
      const observerPin = provisionRequestServicePin(request, "worm_version_observer");
      const requestDigest = await digestBytes(canonicalBytes(request.body));
      let row = this.records.find(0);
      if (row === undefined) {
        const admissionNow = Date.now();
        assertObservedAtBounded(request.observedAt, admissionNow);
        await verifyAdminAccessPrincipalDigests(request, config);
        await verifyProvisionEvidenceDigests(request);
        const authorityExpectation = await parseServiceAuthorityExpectation(
          request.serviceAuthorities.expectation,
          request.serviceAuthorities.expectation_sha256,
          config.cloudflareAccountId,
          requireStringField(request.broker, "source_commit_sha"),
        );
        assertServiceAuthorityExpectationMatchesBroker(authorityExpectation, request.broker);
        const controllerReader = requirePrivateFetcher(
          this.env.CONTROLLER_RUN_READER,
          "CONTROLLER_RUN_READER_UNAVAILABLE",
        );
        const controllerReaderApp = controllerActionBundleAppPin(
          requireObjectField(
            requireObjectField(request.evidence, "github_apps"),
            "controller_run_reader",
          ),
        );
        const actionObservation = await new ControllerActionBundleClient(
          controllerReader,
          provisionRequestServicePin(request, "controller_run_reader"),
          controllerReaderApp,
        ).observe(
          requireStringField(request.controller, "controller_action_commit_sha"),
          request.requestId,
        );
        const controllerOidcEvidence = await new GitHubOidcEvidenceClient(
          controllerReader,
          provisionRequestServicePin(request, "controller_run_reader"),
          {
            observerRole: "controller_run_reader",
            repository: TRUST.controllerRepository,
            repositoryId: TRUST.controllerRepositoryId,
          },
        ).observe(request.requestId);
        const governanceReader = requirePrivateFetcher(
          this.env.GOVERNANCE_READER,
          "GOVERNANCE_READER_UNAVAILABLE",
        );
        const governancePin = provisionRequestServicePin(request, "governance_reader");
        const targetOidcEvidence = await new GitHubOidcEvidenceClient(
          governanceReader,
          governancePin,
          {
            observerRole: "governance_reader",
            repository: TRUST.targetRepository,
            repositoryId: TRUST.targetRepositoryId,
          },
        ).observe(request.requestId);
        const targetGovernance = requireObjectField(request.evidence, "target_governance");
        const rulesetObservation = await new TargetRulesetClient(
          governanceReader,
          governancePin,
        ).observe(
          requireStringField(targetGovernance, "branch_ruleset_id"),
          requireObjectField(targetGovernance, "branch_ruleset_projection"),
          requireStringField(targetGovernance, "branch_ruleset_projection_sha256"),
          request.requestId,
        );
        const wormService = requirePrivateFetcher(this.env.WORM_MIRROR, "WORM_MIRROR_UNAVAILABLE");
        const wormClient = new WormMirrorClient(wormService, wormPin, observerPin, {
          key: config.wormRpcAuthKey,
          serviceIdentity: config.workerServiceIdentity,
          versionId: config.workerVersionId,
        });
        const controllerOidc = await this.evidence.mirrorProviderEvidence(
          wormClient,
          controllerOidcEvidence,
          RAW_PROVIDER_EVIDENCE_KIND,
          config.workerVersionId,
        );
        const targetOidc = await this.evidence.mirrorProviderEvidence(
          wormClient,
          targetOidcEvidence,
          RAW_PROVIDER_EVIDENCE_KIND,
          config.workerVersionId,
        );
        const rulesetEvidence = await this.evidence.mirrorProviderEvidence(
          wormClient,
          rulesetObservation.evidence,
          GITHUB_BRANCH_RULESET_EVIDENCE_KIND,
          config.workerVersionId,
        );
        if (rulesetEvidence.canonicalSha256 !== rulesetObservation.evidenceCanonicalSha256) {
          throw new BrokerError("ACTIVATION_TARGET_RULESET_EVIDENCE_DIGEST_MISMATCH", 503, false);
        }
        const authorityObservation = await this.evidence.observeServiceAuthorities(
          authorityExpectation,
          "A0_PRE",
          request.requestId,
          provisionRequestServicePin(request, "cloudflare_deployment_observer"),
        );
        const commitNow = Date.now();
        assertAuthorityObservationCommitFreshness(authorityObservation, commitNow);
        const committedAt = canonicalTimestamp(commitNow);
        const record = await buildProvisionedRecord(
          request,
          committedAt,
          actionObservation,
          { controller: controllerOidc, target: targetOidc },
          rulesetObservation,
          rulesetEvidence,
          authorityObservation,
        );
        row = await this.records.append(0, requestDigest, record, committedAt);
      } else {
        this.records.assertIdempotent(row, requestDigest);
      }
      return encodeAdminResult(await this.records.confirmMirror(row, wormPin, observerPin));
    });
  }

  public finalize(canonicalRequest: string): Promise<string> {
    const value = decodeCanonicalText(canonicalRequest);
    return this.exclusive(async () => {
      const config = requireLiveConfig(this.env);
      const request = parseFinalizeRequest(value);
      const provisioned = this.records.requireConfirmed(0);
      const provisionedEnvelope = decodeCanonicalObject(
        new Uint8Array(provisioned.canonical_bytes),
      );
      const wormPin = provisionedRecordServicePin(provisionedEnvelope, "worm_mirror");
      const observerPin = provisionedRecordServicePin(provisionedEnvelope, "worm_version_observer");
      this.records.assertProvisionedPointer(request.provisioned, provisioned);
      const requestDigest = await digestBytes(canonicalBytes(request.body));
      let row = this.records.find(1);
      if (row === undefined) {
        const admissionNow = Date.now();
        assertObservedAtBounded(request.observedAt, admissionNow);
        const evidence = requireObjectField(provisionedEnvelope, "evidence");
        const broker = requireObjectField(evidence, "broker");
        const serviceAuthorities = requireObjectField(evidence, "service_authorities");
        const expectation = await parseServiceAuthorityExpectation(
          serviceAuthorities.expectation,
          serviceAuthorities.expectation_sha256,
          config.cloudflareAccountId,
          requireStringField(broker, "source_commit_sha"),
        );
        const promotedDeploymentId = requireStringField(request.promotion, "deployment_id");
        const finalDeployments = materializeA1PrecommitDeployments(
          expectation.a1PrecommitDeployments,
          promotedDeploymentId,
        );
        const ingress = finalDeployments.find(
          (deployment) => deployment.authority_role === "release_authority_ingress",
        );
        const ingressVersion = ingress?.deployment_versions[0];
        if (
          ingress?.deployment_id !== promotedDeploymentId ||
          ingressVersion?.worker_version_id !==
            requireStringField(request.promotion, "worker_version_id") ||
          ingressVersion.worker_version_id !== config.workerVersionId
        ) {
          throw new BrokerError("ACTIVATION_PROMOTION_BINDING_MISMATCH", 409, false);
        }
        const authorityObservation = await this.evidence.observeServiceAuthorities(
          { ...expectation, a1PrecommitDeployments: finalDeployments },
          "A1_PRECOMMIT",
          request.requestId,
          provisionedRecordServicePin(provisionedEnvelope, "cloudflare_deployment_observer"),
        );
        const commitNow = Date.now();
        assertActivationChronology(
          provisioned.committed_at,
          request.promotion,
          authorityObservation,
          commitNow,
        );
        const committedAt = canonicalTimestamp(commitNow);
        const record = await buildActivatedRecord(
          request,
          committedAt,
          provisioned.record_id,
          provisionedEnvelope,
          authorityObservation,
        );
        row = await this.records.append(1, requestDigest, record, committedAt);
      } else {
        this.records.assertIdempotent(row, requestDigest);
      }
      const view = await this.records.confirmMirror(row, wormPin, observerPin);
      if (config.workerVersionId !== request.provisioned.worker_version_id) {
        throw new BrokerError("ACTIVATION_DEPLOYMENT_VERSION_MISMATCH", 409, false);
      }
      const snapshot: ActivationSnapshot = {
        activated: view,
        provisioned: await this.records.toConfirmedView(provisioned),
      };
      const verified = await verifyActivationSnapshot(snapshot, config);
      await new ActivatedAuthorityHeadClient(
        requireGlobalHeadNamespace(this.env.GLOBAL_ACTIVATED_AUTHORITY_HEAD),
      ).advance(snapshot, verified, request.requestId, Date.now());
      return encodeAdminResult(view);
    });
  }

  public async snapshotCanonical(): Promise<string | null> {
    await this.serialTail;
    const provisioned = this.records.find(0);
    if (provisioned === undefined) {
      return null;
    }
    const activated = this.records.find(1);
    const snapshot: ActivationSnapshot = {
      activated: activated === undefined ? null : await this.records.toConfirmedView(activated),
      provisioned: await this.records.toConfirmedView(provisioned),
    };
    return canonicalJson(snapshotJson(snapshot));
  }

  public async activationStatus(): Promise<"active" | "provisioned" | "unprovisioned"> {
    await this.serialTail;
    if (this.records.find(0) === undefined) {
      return "unprovisioned";
    }
    if (this.records.find(1) === undefined) {
      return "provisioned";
    }
    this.records.requireConfirmed(0);
    this.records.requireConfirmed(1);
    return "active";
  }

  public override fetch(request: Request): Response {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    return errorResponse(new BrokerError("INTERNAL_RPC_REQUIRED", 404, false), requestId);
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.serialTail;
    let release: (() => void) | undefined;
    this.serialTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
}
