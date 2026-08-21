import { describe, expect, it } from "vitest";

import {
  activationTrustFromSnapshot,
  assertActivationRecordDigest,
  buildActivatedRecord,
  buildProvisionedRecord,
} from "../src/activation-schema";
import type { ActivationRecordView, ActivationSnapshot } from "../src/types";
import { requireObject } from "../src/validation";
import {
  actionBundleObservation,
  digest,
  finalizeRequest,
  mirroredProviderEvidence,
  provisionRequest,
  recordView,
  serviceAuthorityObservation,
  targetRulesetObservation,
} from "./activation-schema-record.fixtures";
import { WORKER_VERSION, tagged } from "./activation-schema-topology.fixtures";

describe("activation epoch record integrity", () => {
  it("builds domain-stable A0/A1 records and detects byte corruption", async () => {
    const provision = provisionRequest();
    const controllerOidcEvidence = await mirroredProviderEvidence(
      "github_oidc_subject_customization",
      "PaulKov/dpone-release-controller",
      1_305_993_853,
      96,
    );
    const targetOidcEvidence = await mirroredProviderEvidence(
      "github_oidc_subject_customization",
      "PaulKov/dpone",
      1_255_975_556,
      97,
    );
    const targetRulesetEvidence = await mirroredProviderEvidence(
      "github_branch_ruleset",
      "PaulKov/dpone",
      1_255_975_556,
      98,
    );
    const a0 = await buildProvisionedRecord(
      provision,
      "2026-08-15T12:00:00.000Z",
      actionBundleObservation(provision.controller),
      { controller: controllerOidcEvidence, target: targetOidcEvidence },
      targetRulesetObservation(targetRulesetEvidence),
      targetRulesetEvidence,
      serviceAuthorityObservation("A0_PRE"),
    );
    const storedEvidence = requireObject(a0.evidence, "missing evidence");
    const storedOidc = requireObject(storedEvidence.oidc, "missing OIDC evidence");
    const storedOidcPointers = requireObject(
      storedOidc.provider_evidence,
      "missing OIDC evidence pointers",
    );
    expect(
      requireObject(storedOidcPointers.controller, "missing controller OIDC pointer"),
    ).toMatchObject({
      canonical_sha256: controllerOidcEvidence.canonicalSha256,
      evidence_kind: "github_oidc_subject_customization",
      repository: "PaulKov/dpone-release-controller",
      repository_id: 1_305_993_853,
    });
    expect(requireObject(storedOidcPointers.target, "missing target OIDC pointer")).toMatchObject({
      canonical_sha256: targetOidcEvidence.canonicalSha256,
      evidence_kind: "github_oidc_subject_customization",
      repository: "PaulKov/dpone",
      repository_id: 1_255_975_556,
    });
    const storedTargetGovernance = requireObject(
      storedEvidence.target_governance,
      "missing target governance",
    );
    expect(storedTargetGovernance.branch_ruleset_provider_observation_sha256).toBe(tagged(96));
    expect(
      requireObject(
        storedTargetGovernance.branch_ruleset_provider_evidence,
        "missing ruleset evidence pointer",
      ),
    ).toMatchObject({
      canonical_sha256: targetRulesetEvidence.canonicalSha256,
      evidence_kind: "github_branch_ruleset",
      repository: "PaulKov/dpone",
      repository_id: 1_255_975_556,
    });

    const wrongWormPointer = structuredClone(targetRulesetEvidence);
    wrongWormPointer.worm.key = wrongWormPointer.worm.key.replace(
      "/github_branch_ruleset/",
      "/github_oidc_subject_customization/",
    );
    await expect(
      buildProvisionedRecord(
        provision,
        "2026-08-15T12:00:00.000Z",
        actionBundleObservation(provision.controller),
        { controller: controllerOidcEvidence, target: targetOidcEvidence },
        targetRulesetObservation(targetRulesetEvidence),
        wrongWormPointer,
        serviceAuthorityObservation("A0_PRE"),
      ),
    ).rejects.toThrow("ACTIVATION_PROVIDER_EVIDENCE_WORM_POINTER_MISMATCH");
    const a0Id = digest(a0, "record_id");
    await expect(assertActivationRecordDigest(a0, a0Id)).resolves.toBeUndefined();
    await expect(
      assertActivationRecordDigest({ ...a0, committed_at: "2026-08-15T12:00:01.000Z" }, a0Id),
    ).rejects.toThrow("ACTIVATION_RECORD_DIGEST_INVALID");

    const a0View = await recordView(a0, 0, "a0-worm-version-0001");
    const finalize = finalizeRequest(a0View);
    const a1 = await buildActivatedRecord(
      finalize,
      "2026-08-15T12:00:02.000Z",
      a0Id,
      a0,
      serviceAuthorityObservation("A1_PRECOMMIT"),
    );
    const snapshot: ActivationSnapshot = {
      activated: await recordView(a1, 1, "a1-worm-version-0001"),
      provisioned: a0View,
    };
    const trust = activationTrustFromSnapshot(snapshot, WORKER_VERSION);
    expect(trust.controllerWorkflowId).toBe(987_654_321);
    expect(trust.controllerActionCommitSha).toBe("d".repeat(40));
    expect(trust.activatedRecordId).toBe(digest(a1, "record_id"));

    const actionDrift = structuredClone(snapshot);
    if (actionDrift.activated === null) throw new Error("missing activated fixture");
    actionDrift.activated.envelope.controller_action_bundle_sha256 = tagged(255);
    expect(() => activationTrustFromSnapshot(actionDrift, WORKER_VERSION)).toThrow(
      "ACTIVATION_CONTROLLER_ACTION_CHAIN_MISMATCH",
    );

    const corrupted: ActivationSnapshot = {
      ...snapshot,
      activated: {
        ...snapshot.activated,
        envelope: {
          ...snapshot.activated?.envelope,
          previous: `sha256:${"f".repeat(64)}`,
        },
      } as ActivationRecordView,
    };
    expect(() => activationTrustFromSnapshot(corrupted, WORKER_VERSION)).toThrow(
      "ACTIVATION_CHAIN_MISMATCH",
    );
  });
});
