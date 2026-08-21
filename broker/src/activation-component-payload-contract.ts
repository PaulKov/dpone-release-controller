import type {
  ActivationComponentDescriptor,
  ActivationComponentKind,
} from "./activation-component-contract";
import type { ServiceAuthorityExpectation } from "./service-authority-expectation";
import type { JsonObject } from "./types";

export type ActivationComponentPayloadMap = Readonly<Record<ActivationComponentKind, JsonObject>>;

/** Exact decoded payloads; no semantic authority is implied before reconstruction. */
export interface ParsedActivationComponentPayloadSet {
  readonly descriptor: ActivationComponentDescriptor;
  readonly payloads: ActivationComponentPayloadMap;
  readonly trust: "UNTRUSTED";
}

/** Owned scalar descriptor projection safe to expose after semantic validation. */
export type ValidatedActivationComponentDescriptor = Readonly<
  Omit<ActivationComponentDescriptor, "canonicalBytes" | "trust">
>;

/** Closed A0 evidence rebuilt exclusively from the complete validated component set. */
export interface ValidatedActivationComponentSet {
  readonly broker: JsonObject;
  readonly descriptor: ValidatedActivationComponentDescriptor;
  readonly evidence: JsonObject;
  readonly githubApps: JsonObject;
  readonly payloads: ActivationComponentPayloadMap;
  readonly serviceAuthorityExpectation: ServiceAuthorityExpectation;
  readonly trust: "VALIDATED";
}
