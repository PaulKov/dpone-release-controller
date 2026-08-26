import type {
  ActivationComponentSetSemanticDecision,
  ActivationComponentSetSemanticInput,
  ActivationComponentSetSemanticValidator,
} from "./activation-component-journal-contract";
import {
  boundedJournalBytes,
  componentJournalError,
  snapshotJournalPins,
  snapshotJournalSemanticRejection,
} from "./activation-component-journal-boundary";
import type { ActivationComponentDescriptor } from "./activation-component-contract";
import type { ValidatedActivationComponentSet } from "./activation-component-payload-contract";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { validateAndReconstructActivationComponentSet } from "./activation-component-reconstruction";
import { BrokerError } from "./errors";
import type { ActivationComponentSemanticTrust } from "./types";
import type { WormExactObjectEffectPins } from "./worm-exact-object-effect-contract";

interface AcceptedSemanticDecisionState {
  readonly canonicalDescriptorBytes: Uint8Array;
  readonly descriptorId: string;
  readonly descriptorSha256: string;
  readonly pins: WormExactObjectEffectPins;
  readonly setId: string;
  readonly workerVersionId: string;
}

const ACCEPTED_SEMANTIC_DECISIONS = new WeakMap<object, AcceptedSemanticDecisionState>();

/** Closed async journal validator; known caller/input failures reject without sealing effects. */
export class ClosedActivationComponentSetSemanticValidator
  implements ActivationComponentSetSemanticValidator
{
  private readonly config: ActivationComponentSemanticTrust;

  public constructor(config: ActivationComponentSemanticTrust) {
    this.config = Object.freeze({ ...config });
  }

  public async validate(
    input: ActivationComponentSetSemanticInput,
  ): Promise<ActivationComponentSetSemanticDecision> {
    try {
      const descriptorBytes = boundedJournalBytes(input.descriptor.canonicalBytes);
      const [descriptor, validated] = await Promise.all([
        parseActivationComponentSetDescriptor(descriptorBytes),
        validateAndReconstructActivationComponentSet(input, this.config),
      ]);
      assertValidatedDescriptor(descriptor, validated);
      return mintAcceptedDecision(descriptor, semanticWormPins(validated));
    } catch (error) {
      if (isActivationComponentSemanticRejection(error)) {
        return Object.freeze({ outcome: "REJECT" });
      }
      throw error;
    }
  }
}

/**
 * Verify an ACCEPT capability and bind it to the exact descriptor being acted on.
 * REJECT remains a safe exact structural verdict because it cannot authorize effects.
 */
export function snapshotActivationComponentSemanticDecision(
  input: unknown,
  expectedDescriptor: ActivationComponentDescriptor,
): ActivationComponentSetSemanticDecision {
  if (input !== null && typeof input === "object") {
    const state = ACCEPTED_SEMANTIC_DECISIONS.get(input);
    if (state !== undefined) {
      if (
        state.descriptorId !== expectedDescriptor.descriptorId ||
        state.descriptorSha256 !== expectedDescriptor.descriptorSha256 ||
        state.setId !== expectedDescriptor.setId ||
        state.workerVersionId !== expectedDescriptor.workerVersionId ||
        !sameBytes(state.canonicalDescriptorBytes, expectedDescriptor.canonicalBytes)
      ) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SEMANTIC_BINDING_CONFLICT");
      }
      return Object.freeze({ outcome: "ACCEPT", pins: snapshotJournalPins(state.pins) });
    }
  }
  return snapshotJournalSemanticRejection(input);
}

/** Input errors are terminal; operational and unexpected failures remain retryable by the caller. */
export function isActivationComponentSemanticRejection(error: unknown): error is BrokerError {
  return (
    error instanceof BrokerError &&
    !error.retryable &&
    (error.status < 500 || error.code === "GITHUB_RULESET_PROJECTION_INVALID")
  );
}

function semanticWormPins(validated: ValidatedActivationComponentSet): WormExactObjectEffectPins {
  const executor = validated.serviceAuthorityExpectation.authorities.find(
    ({ authority_role }) => authority_role === "worm_mirror",
  );
  const observer = validated.serviceAuthorityExpectation.authorities.find(
    ({ authority_role }) => authority_role === "worm_version_observer",
  );
  if (executor === undefined || observer === undefined) {
    throw new BrokerError("ACTIVATION_COMPONENT_WORM_AUTHORITY_MISSING", 500, false);
  }
  return snapshotJournalPins({
    executorServiceIdentity: executor.service_identity,
    executorVersionId: executor.worker_version_id,
    observerServiceIdentity: observer.service_identity,
    observerVersionId: observer.worker_version_id,
  });
}

function mintAcceptedDecision(
  descriptor: ActivationComponentDescriptor,
  pins: WormExactObjectEffectPins,
): ActivationComponentSetSemanticDecision {
  const decision = Object.freeze({ outcome: "ACCEPT" as const, pins: snapshotJournalPins(pins) });
  ACCEPTED_SEMANTIC_DECISIONS.set(
    decision,
    Object.freeze({
      canonicalDescriptorBytes: boundedJournalBytes(descriptor.canonicalBytes),
      descriptorId: descriptor.descriptorId,
      descriptorSha256: descriptor.descriptorSha256,
      pins: decision.pins,
      setId: descriptor.setId,
      workerVersionId: descriptor.workerVersionId,
    }),
  );
  return decision;
}

function assertValidatedDescriptor(
  descriptor: ActivationComponentDescriptor,
  validated: ValidatedActivationComponentSet,
): void {
  if (
    descriptor.committedAt !== validated.descriptor.committedAt ||
    descriptor.descriptorId !== validated.descriptor.descriptorId ||
    descriptor.descriptorSha256 !== validated.descriptor.descriptorSha256 ||
    descriptor.setId !== validated.descriptor.setId ||
    descriptor.workerVersionId !== validated.descriptor.workerVersionId
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SEMANTIC_BINDING_CONFLICT", 500);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
