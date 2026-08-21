import { provisionRequestServicePin, type ProvisionRequest } from "./activation-schema";
import { requireObjectField, requireStringField } from "./activation-registry-codec";
import {
  buildControllerActionBundleObservationRequest,
  controllerActionBundleAppPin,
} from "./controller-action-bundle-client";
import { buildGitHubOidcEvidenceRequest } from "./github-oidc-evidence-client";
import { buildTargetRulesetObservationRequest } from "./target-ruleset-client";
import { BrokerError } from "./errors";
import type { PrivateServicePin } from "./types";

export type ActivationOperationReadSlotId =
  | "CONTROLLER_ACTION"
  | "CONTROLLER_OIDC"
  | "TARGET_OIDC"
  | "TARGET_RULESET";

export interface ActivationOperationReadPlan {
  readonly canonicalRequestBytes: Uint8Array;
  readonly providerPin: PrivateServicePin;
  readonly slotId: ActivationOperationReadSlotId;
}

/** Derive the closed A0 provider-read roster before any remote request is allowed. */
export function provisionReadPlan(
  request: ProvisionRequest,
  internalRequestId: string,
): readonly ActivationOperationReadPlan[] {
  const controllerPin = provisionRequestServicePin(request, "controller_run_reader");
  const governancePin = provisionRequestServicePin(request, "governance_reader");
  const githubApps = requireObjectField(request.evidence, "github_apps");
  const controllerApp = controllerActionBundleAppPin(
    requireObjectField(githubApps, "controller_run_reader"),
  );
  const governance = requireObjectField(request.evidence, "target_governance");
  const oidcRequest = buildGitHubOidcEvidenceRequest(internalRequestId);
  return Object.freeze([
    {
      canonicalRequestBytes: buildControllerActionBundleObservationRequest(
        requireStringField(request.controller, "controller_action_commit_sha"),
        internalRequestId,
        controllerApp,
      ),
      providerPin: controllerPin,
      slotId: "CONTROLLER_ACTION",
    },
    {
      canonicalRequestBytes: oidcRequest,
      providerPin: controllerPin,
      slotId: "CONTROLLER_OIDC",
    },
    {
      canonicalRequestBytes: oidcRequest,
      providerPin: governancePin,
      slotId: "TARGET_OIDC",
    },
    {
      canonicalRequestBytes: buildTargetRulesetObservationRequest(
        requireStringField(governance, "branch_ruleset_id"),
        requireStringField(governance, "branch_ruleset_projection_sha256"),
        internalRequestId,
      ),
      providerPin: governancePin,
      slotId: "TARGET_RULESET",
    },
  ]);
}

export function requireProvisionReadPlan(
  plans: readonly ActivationOperationReadPlan[],
  slotId: ActivationOperationReadSlotId,
): ActivationOperationReadPlan {
  const plan = plans.find((candidate) => candidate.slotId === slotId);
  if (plan === undefined) {
    throw new BrokerError("ACTIVATION_OPERATION_SLOT_MISSING", 500, false);
  }
  return plan;
}
