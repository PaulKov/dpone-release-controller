import type {
  ConfirmedActivationComponentJournalDescriptor,
  ConfirmedActivationComponentJournalSession,
} from "./activation-component-journal-contract";
import { snapshotConfirmedActivationComponentJournalAuthority } from "./activation-component-journal-confirmed-authority";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentManifestPointer } from "./activation-component-manifest";
import {
  CONFIRMED_ACTIVATION_PROVISION_AUTHORITY_TRUST,
  type ActivationProvisionPinProjection,
  type ActivationProvisionSemanticCommitments,
  type ConfirmedActivationProvisionAuthority,
} from "./activation-component-operation-authority-contract";
import { deriveActivationProvisionOperationProjection } from "./activation-component-operation-pins";
import { parseActivationComponentResolverProjection } from "./activation-component-resolver-projection";
import {
  snapshotResolvedActivationComponentExecutionSource,
  snapshotResolvedActivationComponentSet,
} from "./activation-component-resolver";
import type { ResolvedActivationComponentExecutionSource } from "./activation-component-resolver-execution-contract";
import { ACTIVATION_PROVISION_INTENT_V2_SCHEMA } from "./activation-record-v2-contract";
import { freezeRecordV2Json, snapshotActivationRecordV2Data } from "./activation-record-v2-codec";
import {
  activationRecordV2IntentSha256,
  validateActivationRecordV2ComponentAuthority,
} from "./activation-record-v2-evidence";
import { canonicalBytes, sha256Hex, timingSafeEqual } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject, PrivateServicePin } from "./types";
import type { WormExactObjectEffectPins } from "./worm-exact-object-effect-contract";

const INVALID = "ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID";

interface JournalAuthorityInput {
  readonly descriptor: ConfirmedActivationComponentJournalDescriptor;
  readonly descriptorBytes: Uint8Array;
  readonly journalPins: WormExactObjectEffectPins;
  readonly pointerBytes: Uint8Array;
  readonly pointerSha256: string;
  readonly session: ConfirmedActivationComponentJournalSession;
}

interface ResolvedAuthorityInput {
  readonly executionSource: ResolvedActivationComponentExecutionSource;
  readonly projectionBytes: Uint8Array;
  readonly projectionSha256: string;
}

interface ProvisionAuthorityState extends JournalAuthorityInput, ResolvedAuthorityInput {
  readonly componentAuthority: JsonObject;
  readonly componentAuthorityBytes: Uint8Array;
  readonly componentAuthoritySha256: string;
  readonly historicalWorker: PrivateServicePin;
  readonly pins: ActivationProvisionPinProjection;
  readonly provisionIntentBytes: Uint8Array;
  readonly provisionIntentSha256: string;
  readonly semanticCommitments: ActivationProvisionSemanticCommitments;
}

const PROVISION_AUTHORITIES = new WeakMap<object, ProvisionAuthorityState>();

/** Cross-bind the two independent private authorities and mint one local A0 capability. */
export async function bindActivationProvisionAuthority(
  journalInput: unknown,
  resolvedInput: unknown,
): Promise<ConfirmedActivationProvisionAuthority> {
  const [journal, executionSource] = await Promise.all([
    snapshotConfirmedActivationComponentJournalAuthority(journalInput),
    snapshotResolvedActivationComponentExecutionSource(resolvedInput),
  ]);
  const resolved = await snapshotResolvedActivationComponentSet(executionSource);
  return provisionAuthorityValue(
    await deriveProvisionAuthority(
      {
        descriptor: journal.descriptor,
        descriptorBytes: journal.canonicalDescriptorBytes,
        journalPins: journal.pins,
        pointerBytes: journal.canonicalPointerBytes,
        pointerSha256: journal.pointerSha256,
        session: journal.session,
      },
      {
        executionSource,
        projectionBytes: resolved.canonicalProjectionBytes,
        projectionSha256: resolved.projectionSha256,
      },
    ),
  );
}

/** Require the private operation brand, then reparse and rederive every exact retry snapshot. */
export async function snapshotConfirmedActivationProvisionAuthority(
  input: unknown,
): Promise<ConfirmedActivationProvisionAuthority> {
  const state = provisionAuthorityState(input);
  const executionSource = await snapshotResolvedActivationComponentExecutionSource(
    state.executionSource,
  );
  const resolved = await snapshotResolvedActivationComponentSet(executionSource);
  return provisionAuthorityValue(
    await deriveProvisionAuthority(state, {
      executionSource,
      projectionBytes: resolved.canonicalProjectionBytes,
      projectionSha256: resolved.projectionSha256,
    }),
  );
}

async function deriveProvisionAuthority(
  journal: JournalAuthorityInput,
  resolved: ResolvedAuthorityInput,
): Promise<ProvisionAuthorityState> {
  const descriptorBytes = Uint8Array.from(journal.descriptorBytes);
  const pointerBytes = Uint8Array.from(journal.pointerBytes);
  const projectionBytes = Uint8Array.from(resolved.projectionBytes);
  const [descriptor, pointer, projection, pointerSha256, projectionSha256] = await Promise.all([
    parseActivationComponentSetDescriptor(descriptorBytes),
    Promise.resolve(parseActivationComponentManifestPointer(pointerBytes)),
    Promise.resolve(parseActivationComponentResolverProjection(projectionBytes)),
    taggedDigest(pointerBytes),
    taggedDigest(projectionBytes),
  ]);
  const set = object(projection.document.component_set);
  const runtime = object(projection.document.runtime);
  const projectionPointerBytes = canonicalBytes({
    manifest_id: set.manifest_id ?? null,
    manifest_sha256: set.manifest_sha256 ?? null,
    worm: set.manifest_worm ?? null,
  });
  if (
    !sameDescriptor(journal.descriptor, descriptor) ||
    !sameBytes(pointerBytes, projectionPointerBytes) ||
    !timingSafeEqual(pointerSha256, journal.pointerSha256) ||
    !timingSafeEqual(projectionSha256, resolved.projectionSha256) ||
    !timingSafeEqual(projectionSha256, resolved.executionSource.projectionSha256) ||
    set.component_set_committed_at !== descriptor.committedAt ||
    set.component_set_descriptor_id !== descriptor.descriptorId ||
    set.component_set_descriptor_sha256 !== descriptor.descriptorSha256 ||
    set.component_set_id !== descriptor.setId ||
    set.worker_version_id !== descriptor.workerVersionId ||
    pointer.setId !== descriptor.setId ||
    pointer.workerVersionId !== descriptor.workerVersionId
  ) {
    fail();
  }

  const componentAuthority = freezeRecordV2Json(
    snapshotActivationRecordV2Data({
      descriptor: {
        committed_at: descriptor.committedAt,
        descriptor_id: descriptor.descriptorId,
        descriptor_sha256: descriptor.descriptorSha256,
        set_id: descriptor.setId,
        worker_version_id: descriptor.workerVersionId,
      },
      manifest_pointer: pointer.document,
      manifest_pointer_sha256: pointerSha256,
      resolved_projection_sha256: projectionSha256,
      session: {
        fresh_until: journal.session.freshUntil,
        generation: journal.session.generation,
        journal_ordinal: journal.session.journalOrdinal,
        predecessor_session_id: journal.session.predecessorSessionId,
        session_id: journal.session.sessionId,
        state: journal.session.state,
      },
    }),
  );
  const parsedAuthority = await validateActivationRecordV2ComponentAuthority(
    componentAuthority,
    descriptor.workerVersionId,
  );
  const provisionIntent = freezeRecordV2Json(
    snapshotActivationRecordV2Data({
      component_authority: parsedAuthority.intent,
      schema: ACTIVATION_PROVISION_INTENT_V2_SCHEMA,
      schema_version: 2,
    }),
  );
  const componentAuthorityBytes = canonicalBytes(componentAuthority);
  const provisionIntentBytes = canonicalBytes(provisionIntent);
  const provisionIntentSha256 = await activationRecordV2IntentSha256(parsedAuthority.intent, 0);
  if (!timingSafeEqual(await taggedDigest(provisionIntentBytes), provisionIntentSha256)) fail();
  const operation = deriveActivationProvisionOperationProjection(
    runtime,
    descriptor.workerVersionId,
  );
  assertJournalPins(journal.journalPins, operation.pins);
  return freezeState({
    componentAuthority,
    componentAuthorityBytes,
    componentAuthoritySha256: await taggedDigest(componentAuthorityBytes),
    descriptor: journal.descriptor,
    descriptorBytes,
    executionSource: resolved.executionSource,
    historicalWorker: operation.historicalWorker,
    journalPins: journal.journalPins,
    pins: operation.pins,
    pointerBytes,
    pointerSha256,
    projectionBytes,
    projectionSha256,
    provisionIntentBytes,
    provisionIntentSha256,
    semanticCommitments: operation.semanticCommitments,
    session: journal.session,
  });
}

function provisionAuthorityValue(
  input: ProvisionAuthorityState,
): ConfirmedActivationProvisionAuthority {
  const state = freezeState(input);
  const value = Object.freeze({
    get canonicalComponentAuthorityBytes(): Uint8Array {
      return Uint8Array.from(state.componentAuthorityBytes);
    },
    get canonicalDescriptorBytes(): Uint8Array {
      return Uint8Array.from(state.descriptorBytes);
    },
    get canonicalManifestPointerBytes(): Uint8Array {
      return Uint8Array.from(state.pointerBytes);
    },
    get canonicalProvisionIntentBytes(): Uint8Array {
      return Uint8Array.from(state.provisionIntentBytes);
    },
    get canonicalResolvedProjectionBytes(): Uint8Array {
      return Uint8Array.from(state.projectionBytes);
    },
    componentAuthority: state.componentAuthority,
    componentAuthoritySha256: state.componentAuthoritySha256,
    descriptor: state.descriptor,
    historicalWorker: state.historicalWorker,
    manifestPointerSha256: state.pointerSha256,
    pins: state.pins,
    provisionIntentSha256: state.provisionIntentSha256,
    resolvedProjectionSha256: state.projectionSha256,
    semanticCommitments: state.semanticCommitments,
    session: state.session,
    trust: CONFIRMED_ACTIVATION_PROVISION_AUTHORITY_TRUST,
  });
  PROVISION_AUTHORITIES.set(value, state);
  return value;
}

function provisionAuthorityState(input: unknown): ProvisionAuthorityState {
  if (input === null || typeof input !== "object") fail();
  const state = PROVISION_AUTHORITIES.get(input);
  if (state === undefined) fail();
  return freezeState(state);
}

function freezeState(input: ProvisionAuthorityState): ProvisionAuthorityState {
  return Object.freeze({
    componentAuthority: input.componentAuthority,
    componentAuthorityBytes: Uint8Array.from(input.componentAuthorityBytes),
    componentAuthoritySha256: input.componentAuthoritySha256,
    descriptor: Object.freeze({ ...input.descriptor }),
    descriptorBytes: Uint8Array.from(input.descriptorBytes),
    executionSource: input.executionSource,
    historicalWorker: Object.freeze({ ...input.historicalWorker }),
    journalPins: Object.freeze({ ...input.journalPins }),
    pins: input.pins,
    pointerBytes: Uint8Array.from(input.pointerBytes),
    pointerSha256: input.pointerSha256,
    projectionBytes: Uint8Array.from(input.projectionBytes),
    projectionSha256: input.projectionSha256,
    provisionIntentBytes: Uint8Array.from(input.provisionIntentBytes),
    provisionIntentSha256: input.provisionIntentSha256,
    semanticCommitments: input.semanticCommitments,
    session: Object.freeze({ ...input.session }),
  });
}

function sameDescriptor(
  expected: ConfirmedActivationComponentJournalDescriptor,
  actual: Awaited<ReturnType<typeof parseActivationComponentSetDescriptor>>,
): boolean {
  return (
    expected.committedAt === actual.committedAt &&
    expected.descriptorId === actual.descriptorId &&
    expected.descriptorSha256 === actual.descriptorSha256 &&
    expected.setId === actual.setId &&
    expected.workerVersionId === actual.workerVersionId
  );
}

function assertJournalPins(
  journal: WormExactObjectEffectPins,
  operation: ActivationProvisionPinProjection,
): void {
  const resolved = operation.directEvidenceWorm;
  if (
    journal.executorServiceIdentity !== resolved.executorServiceIdentity ||
    journal.executorVersionId !== resolved.executorWorkerVersionId ||
    journal.observerServiceIdentity !== resolved.observerServiceIdentity ||
    journal.observerVersionId !== resolved.observerWorkerVersionId
  ) {
    fail();
  }
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value as JsonObject;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

async function taggedDigest(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

function fail(): never {
  throw new BrokerError(INVALID, 409, false);
}
