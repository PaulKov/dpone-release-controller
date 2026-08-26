import type { ActivationWorm, JsonObject } from "./types";

export interface ProvisionRequest {
  readonly body: JsonObject;
  readonly broker: JsonObject;
  readonly controller: JsonObject;
  readonly evidence: JsonObject;
  readonly observedAt: string;
  readonly oidc: JsonObject;
  readonly requestId: string;
  readonly serviceAuthorities: JsonObject;
}

export interface FinalizeRequest {
  readonly approvals: JsonObject;
  readonly body: JsonObject;
  readonly observedAt: string;
  readonly provisioned: JsonObject;
  readonly promotion: JsonObject;
  readonly requestId: string;
  readonly target: JsonObject;
}

export interface MirroredProviderEvidence {
  readonly canonicalSha256: string;
  readonly evidence: JsonObject;
  readonly worm: ActivationWorm;
}
