import type {
  ConfirmedActivationComponentJournalDescriptor,
  ConfirmedActivationComponentJournalSession,
} from "./activation-component-journal-contract";
import type {
  ActivationCloudflareBatchPins,
  ActivationOperationExecutorPins,
} from "./activation-operation-pins";
import type { JsonObject, PrivateServicePin } from "./types";

export const CONFIRMED_ACTIVATION_PROVISION_AUTHORITY_TRUST =
  "CONFIRMED_COMPONENT_OPERATION_AUTHORITY" as const;

/** Stable semantic commitments derived from the exact resolved projection. */
export interface ActivationProvisionSemanticCommitments {
  readonly cloudflareAccountId: string;
  readonly controllerActionBundleSha256: string;
  readonly serviceAuthorityExpectationSha256: string;
  readonly targetBranchRulesetEvidenceSha256: string;
  readonly targetBranchRulesetProjectionSha256: string;
}

/** Provider pins needed by the four compact A0 direct-read slots. */
export interface ActivationProvisionProviderPins {
  readonly controllerAction: PrivateServicePin;
  readonly controllerOidc: PrivateServicePin;
  readonly targetOidc: PrivateServicePin;
  readonly targetRuleset: PrivateServicePin;
}

/** Pin-only projection. Full provider requests and Cloudflare expectations remain out of scope. */
export interface ActivationProvisionPinProjection {
  readonly cloudflareBatch: ActivationCloudflareBatchPins;
  readonly directEvidenceWorm: ActivationOperationExecutorPins;
  readonly providerReads: ActivationProvisionProviderPins;
}

/**
 * Private local A0 authority minted only from independently branded journal and resolver values.
 * Exact bytes are fresh copies; the literal trust label is never accepted without the private brand.
 */
export interface ConfirmedActivationProvisionAuthority {
  readonly canonicalComponentAuthorityBytes: Uint8Array;
  readonly canonicalDescriptorBytes: Uint8Array;
  readonly canonicalManifestPointerBytes: Uint8Array;
  readonly canonicalProvisionIntentBytes: Uint8Array;
  readonly canonicalResolvedProjectionBytes: Uint8Array;
  readonly componentAuthority: JsonObject;
  readonly componentAuthoritySha256: string;
  readonly descriptor: ConfirmedActivationComponentJournalDescriptor;
  readonly historicalWorker: PrivateServicePin;
  readonly manifestPointerSha256: string;
  readonly pins: ActivationProvisionPinProjection;
  readonly provisionIntentSha256: string;
  readonly resolvedProjectionSha256: string;
  readonly semanticCommitments: ActivationProvisionSemanticCommitments;
  readonly session: ConfirmedActivationComponentJournalSession;
  readonly trust: typeof CONFIRMED_ACTIVATION_PROVISION_AUTHORITY_TRUST;
}
