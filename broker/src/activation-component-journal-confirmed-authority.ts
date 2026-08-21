import { sha256Hex, timingSafeEqual } from "./canonical";
import type {
  ConfirmedActivationComponentJournalAuthority,
  ConfirmedActivationComponentJournalDescriptor,
  ConfirmedActivationComponentJournalSession,
} from "./activation-component-journal-contract";
import type { ActivationComponentJournalAuthorityReader } from "./activation-component-journal-authority";
import { readActivationComponentManifestAuthority } from "./activation-component-journal-manifest-authority";
import { selectedJournalPins } from "./activation-component-journal-confirmation";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  activationComponentJournalSessionId,
  componentJournalError,
  journalFreshUntil,
  snapshotJournalPins,
} from "./activation-component-journal-validation";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentManifestPointer } from "./activation-component-manifest";
import type { WormExactObjectEffectPins } from "./worm-exact-object-effect-contract";

interface ConfirmedActivationComponentJournalState {
  readonly descriptor: ConfirmedActivationComponentJournalDescriptor;
  readonly descriptorBytes: Uint8Array;
  readonly pins: WormExactObjectEffectPins;
  readonly pointerBytes: Uint8Array;
  readonly pointerSha256: string;
  readonly session: ConfirmedActivationComponentJournalSession;
}

const CONFIRMED_AUTHORITIES = new WeakMap<object, ConfirmedActivationComponentJournalState>();

/** Rebuild the complete SQLite chain before privately minting final local authority. */
export async function confirmedActivationComponentJournalAuthority(
  reader: ActivationComponentJournalAuthorityReader,
  queries: ActivationComponentJournalQueries,
  sessionId: string,
): Promise<ConfirmedActivationComponentJournalAuthority> {
  const rebuilt = await readActivationComponentManifestAuthority(reader, queries, sessionId);
  if (
    rebuilt.row.status !== "CONFIRMED" ||
    rebuilt.pointer === null ||
    rebuilt.authority.selection.state !== "CONFIRMED" ||
    rebuilt.row.pointer_sha256 === null
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_NOT_CONFIRMED");
  }
  const session = rebuilt.authority.session;
  if (session.state !== "SELECTED") {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID", 500);
  }
  return confirmedAuthorityValue({
    descriptor: Object.freeze({
      committedAt: rebuilt.authority.descriptor.committedAt,
      descriptorId: rebuilt.authority.descriptor.descriptorId,
      descriptorSha256: rebuilt.authority.descriptor.descriptorSha256,
      setId: rebuilt.authority.descriptor.setId,
      workerVersionId: rebuilt.authority.descriptor.workerVersionId,
    }),
    descriptorBytes: Uint8Array.from(rebuilt.authority.descriptor.canonicalBytes),
    pins: selectedJournalPins(rebuilt.authority),
    pointerBytes: Uint8Array.from(rebuilt.pointer.canonicalBytes),
    pointerSha256: rebuilt.row.pointer_sha256,
    session: Object.freeze({
      freshUntil: session.freshUntil,
      generation: session.generation,
      journalOrdinal: session.journalOrdinal,
      predecessorSessionId: session.predecessorSessionId,
      sessionId: session.sessionId,
      state: "SELECTED" as const,
    }),
  });
}

/** Require the private journal brand, then re-own and reparse both exact authorities. */
export async function snapshotConfirmedActivationComponentJournalAuthority(
  input: unknown,
): Promise<ConfirmedActivationComponentJournalAuthority> {
  const state = confirmedAuthorityState(input);
  const descriptor = await parseActivationComponentSetDescriptor(state.descriptorBytes);
  const pointer = parseActivationComponentManifestPointer(state.pointerBytes);
  const pointerSha256 = `sha256:${await sha256Hex(pointer.canonicalBytes)}`;
  const sessionId = await activationComponentJournalSessionId(
    descriptor.workerVersionId,
    descriptor.setId,
    descriptor.descriptorId,
    descriptor.descriptorSha256,
    state.session.generation,
    state.session.journalOrdinal,
    state.session.predecessorSessionId,
  );
  if (
    !sameDescriptor(state.descriptor, descriptor) ||
    state.session.sessionId !== sessionId ||
    state.session.freshUntil !== journalFreshUntil(descriptor.committedAt) ||
    pointer.setId !== descriptor.setId ||
    pointer.workerVersionId !== descriptor.workerVersionId ||
    !timingSafeEqual(pointerSha256, state.pointerSha256)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID");
  }
  return confirmedAuthorityValue(state);
}

function confirmedAuthorityValue(
  input: ConfirmedActivationComponentJournalState,
): ConfirmedActivationComponentJournalAuthority {
  const state = Object.freeze({
    descriptor: Object.freeze({ ...input.descriptor }),
    descriptorBytes: Uint8Array.from(input.descriptorBytes),
    pins: snapshotJournalPins(input.pins),
    pointerBytes: Uint8Array.from(input.pointerBytes),
    pointerSha256: input.pointerSha256,
    session: Object.freeze({ ...input.session }),
  });
  const value = Object.freeze({
    get canonicalDescriptorBytes(): Uint8Array {
      return Uint8Array.from(state.descriptorBytes);
    },
    get canonicalPointerBytes(): Uint8Array {
      return Uint8Array.from(state.pointerBytes);
    },
    descriptor: state.descriptor,
    pins: state.pins,
    pointerSha256: state.pointerSha256,
    session: state.session,
    trust: "CONFIRMED_JOURNAL" as const,
  });
  CONFIRMED_AUTHORITIES.set(value, state);
  return value;
}

function confirmedAuthorityState(input: unknown): ConfirmedActivationComponentJournalState {
  if (input === null || typeof input !== "object") {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID");
  }
  const state = CONFIRMED_AUTHORITIES.get(input);
  if (state === undefined) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID");
  }
  return {
    descriptor: state.descriptor,
    descriptorBytes: Uint8Array.from(state.descriptorBytes),
    pins: snapshotJournalPins(state.pins),
    pointerBytes: Uint8Array.from(state.pointerBytes),
    pointerSha256: state.pointerSha256,
    session: state.session,
  };
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
