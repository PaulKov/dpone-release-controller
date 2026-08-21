import { sha256Hex } from "./canonical";
import {
  confirmActivationComponentEnvelopeObject,
  prepareActivationComponentEnvelopeEffect,
} from "./activation-component-confirmation";
import {
  ACTIVATION_COMPONENT_KINDS,
  type ActivationComponentDescriptor,
  type PreparedActivationComponentEnvelope,
} from "./activation-component-contract";
import {
  type ActivationComponentJournalHoldCode,
  type ActivationComponentJournalSession,
  type ActivationComponentJournalSessionState,
} from "./activation-component-journal-contract";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import type {
  ActivationComponentJournalEntryRow,
  ActivationComponentJournalSelectionRow,
  ActivationComponentJournalSessionRow,
} from "./activation-component-journal-schema";
import {
  activationComponentJournalSessionId,
  assertSameJournalEntries,
  assertSameJournalSelection,
  assertSameJournalSession,
  componentJournalError,
  journalFreshUntil,
  sameJournalBytes,
  sessionState,
  snapshotJournalPins,
} from "./activation-component-journal-validation";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

const HOLD_CODES = new Set<ActivationComponentJournalHoldCode>([
  "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT",
  "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT",
]);

export interface ActivationComponentJournalAuthority {
  readonly descriptor: ActivationComponentDescriptor;
  readonly effects: readonly PreparedWormExactObjectEffect[];
  readonly entries: readonly ActivationComponentJournalEntryRow[];
  readonly envelopes: readonly PreparedActivationComponentEnvelope[];
  readonly row: ActivationComponentJournalSessionRow;
  readonly selection: ActivationComponentJournalSelectionRow;
  readonly session: ActivationComponentJournalSession;
}

/** Rebuild every identity from owned SQLite bytes, then fence the parsed snapshot. */
export class ActivationComponentJournalAuthorityReader {
  public constructor(
    private readonly queries: ActivationComponentJournalQueries,
    private readonly workerVersionId: string,
  ) {}

  public async load(sessionId: string): Promise<ActivationComponentJournalAuthority> {
    const row = snapshotSession(requireSession(this.queries.session(sessionId)));
    const entries = this.queries.entries(sessionId).map(snapshotEntry);
    const selection = snapshotSelection(this.queries.selection());
    const authority = await this.parse(row, entries, selection);
    assertSameJournalSession(row, this.queries.session(sessionId));
    assertSameJournalEntries(entries, this.queries.entries(sessionId));
    assertSameJournalSelection(selection, this.queries.selection());
    return authority;
  }

  private async parse(
    row: ActivationComponentJournalSessionRow,
    entries: readonly ActivationComponentJournalEntryRow[],
    selection: ActivationComponentJournalSelectionRow,
  ): Promise<ActivationComponentJournalAuthority> {
    const descriptor = await parseActivationComponentSetDescriptor(
      new Uint8Array(row.descriptor_bytes),
    );
    await assertSessionIdentity(row, descriptor, this.workerVersionId);
    await this.assertPredecessor(row, descriptor);
    const { state, terminalCode } = sessionState(row);
    assertSelectionShape(selection);
    if (isTerminal(state)) {
      if (entries.length !== 0 || selection.selected_session_id === row.session_id) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_TERMINAL_STATE_INVALID", 500);
      }
      return authority(row, entries, selection, descriptor, [], [], state, terminalCode);
    }
    if (entries.length !== ACTIVATION_COMPONENT_KINDS.length) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
    }
    const pins = selectionPins(selection, row.session_id, state);
    const envelopes: PreparedActivationComponentEnvelope[] = [];
    const effects: PreparedWormExactObjectEffect[] = [];
    for (let ordinal = 0; ordinal < ACTIVATION_COMPONENT_KINDS.length; ordinal += 1) {
      const entry = entries[ordinal];
      const expected = descriptor.components[ordinal];
      if (
        entry === undefined ||
        expected === undefined ||
        entry.ordinal !== ordinal ||
        entry.component_kind !== expected.componentKind ||
        entry.expected_payload_sha256 !== expected.payloadSha256
      ) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
      }
      if (entry.status === "EXPECTED") continue;
      if (entry.envelope_bytes === null) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
      }
      const envelope = await parseActivationComponentEnvelope(
        new Uint8Array(entry.envelope_bytes),
        descriptor.canonicalBytes,
      );
      assertEnvelopeRow(entry, envelope);
      envelopes.push(envelope);
      if (entry.status === "STAGED") continue;
      if (entry.status !== "SEALED" && entry.status !== "CONFIRMED") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
      }
      if (pins === null || entry.effect_id === null) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
      }
      const effect = await prepareActivationComponentEnvelopeEffect(
        descriptor.canonicalBytes,
        envelope.canonicalBytes,
        pins,
      );
      if (effect.effectId !== entry.effect_id) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_CONFLICT", 500);
      }
      effects.push(effect);
      if (entry.status === "CONFIRMED") await assertConfirmedEntry(descriptor, entry, effect);
    }
    assertActiveState(state, entries, selection, row.session_id);
    return authority(row, entries, selection, descriptor, envelopes, effects, state, terminalCode);
  }

  private async assertPredecessor(
    row: ActivationComponentJournalSessionRow,
    descriptor: ActivationComponentDescriptor,
  ): Promise<void> {
    if (row.predecessor_session_id === null) {
      if (row.generation !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_INVALID", 500);
      }
      return;
    }
    if (row.generation <= 1) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_INVALID", 500);
    }
    const predecessor = await this.load(row.predecessor_session_id);
    if (
      predecessor.session.generation !== row.generation - 1 ||
      predecessor.session.state !== "ABANDONED" ||
      predecessor.session.terminalCode !== "ACTIVATION_COMPONENT_SESSION_EXPIRED" ||
      predecessor.descriptor.setId !== descriptor.setId ||
      predecessor.descriptor.workerVersionId !== descriptor.workerVersionId ||
      row.component_set_committed_at <= predecessor.session.freshUntil ||
      row.journal_ordinal <= predecessor.session.journalOrdinal
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_INVALID", 500);
    }
  }
}

async function assertSessionIdentity(
  row: ActivationComponentJournalSessionRow,
  descriptor: ActivationComponentDescriptor,
  expectedWorkerVersionId: string,
): Promise<void> {
  const expectedSessionId = await activationComponentJournalSessionId(
    descriptor.workerVersionId,
    descriptor.setId,
    descriptor.descriptorId,
    descriptor.descriptorSha256,
    row.generation,
    row.journal_ordinal,
    row.predecessor_session_id,
  );
  if (
    row.session_id !== expectedSessionId ||
    row.worker_version_id !== expectedWorkerVersionId ||
    descriptor.workerVersionId !== expectedWorkerVersionId ||
    row.set_id !== descriptor.setId ||
    row.descriptor_id !== descriptor.descriptorId ||
    row.descriptor_sha256 !== descriptor.descriptorSha256 ||
    row.component_set_committed_at !== descriptor.committedAt ||
    row.fresh_until !== journalFreshUntil(descriptor.committedAt)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_IDENTITY_CONFLICT", 500);
  }
}

function assertSelectionShape(selection: ActivationComponentJournalSelectionRow): void {
  if (selection.state === "OPEN") {
    if (
      selection.selected_session_id !== null ||
      selection.worm_service_identity !== null ||
      selection.worm_version_id !== null ||
      selection.observer_service_identity !== null ||
      selection.observer_version_id !== null ||
      selection.hold_code !== null
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID", 500);
    }
    return;
  }
  if (selection.selected_session_id === null) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID", 500);
  }
  if (
    (selection.state === "HOLD" &&
      !HOLD_CODES.has(selection.hold_code as ActivationComponentJournalHoldCode)) ||
    (selection.state !== "HOLD" && selection.hold_code !== null)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID", 500);
  }
  selectionPins(selection, selection.selected_session_id, "SELECTED");
}

function selectionPins(
  selection: ActivationComponentJournalSelectionRow,
  sessionId: string,
  state: ActivationComponentJournalSessionState,
) {
  if (state !== "SELECTED") return null;
  if (
    selection.state === "OPEN" ||
    selection.selected_session_id !== sessionId ||
    selection.worm_service_identity === null ||
    selection.worm_version_id === null ||
    selection.observer_service_identity === null ||
    selection.observer_version_id === null
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID", 500);
  }
  return snapshotJournalPins({
    executorServiceIdentity: selection.worm_service_identity,
    executorVersionId: selection.worm_version_id,
    observerServiceIdentity: selection.observer_service_identity,
    observerVersionId: selection.observer_version_id,
  });
}

function assertEnvelopeRow(
  row: ActivationComponentJournalEntryRow,
  envelope: PreparedActivationComponentEnvelope,
): void {
  if (
    row.component_id !== envelope.componentId ||
    row.component_kind !== envelope.componentKind ||
    row.envelope_sha256 !== envelope.envelopeSha256 ||
    row.expected_payload_sha256 !== envelope.payloadSha256 ||
    row.object_key !== envelope.key ||
    !sameJournalBytes(row.envelope_bytes, envelope.canonicalBytes.buffer)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_CONFLICT", 500);
  }
}

async function assertConfirmedEntry(
  descriptor: ActivationComponentDescriptor,
  row: ActivationComponentJournalEntryRow,
  effect: PreparedWormExactObjectEffect,
): Promise<void> {
  if (row.result_bytes === null || row.result_sha256 === null) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
  }
  const result = new Uint8Array(row.result_bytes);
  if (`sha256:${await sha256Hex(result)}` !== row.result_sha256) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_RESULT_CONFLICT", 500);
  }
  await confirmActivationComponentEnvelopeObject(descriptor.canonicalBytes, effect, result);
}

function assertActiveState(
  state: ActivationComponentJournalSessionState,
  entries: readonly ActivationComponentJournalEntryRow[],
  selection: ActivationComponentJournalSelectionRow,
  sessionId: string,
): void {
  const statuses = entries.map(({ status }) => status);
  const selected = state === "SELECTED" && selection.selected_session_id === sessionId;
  const valid =
    (state === "PROVISIONAL" &&
      statuses.includes("EXPECTED") &&
      statuses.every((status) => status === "EXPECTED" || status === "STAGED")) ||
    (state === "STAGED" && statuses.every((status) => status === "STAGED")) ||
    (selected &&
      selection.state === "COMPONENT_EFFECTS_SEALED" &&
      statuses.includes("SEALED") &&
      statuses.every((status) => status === "SEALED" || status === "CONFIRMED")) ||
    (selected &&
      ["COMPONENTS_CONFIRMED", "MANIFEST_EFFECT_SEALED", "CONFIRMED", "HOLD"].includes(
        selection.state,
      ) &&
      statuses.every((status) => status === "CONFIRMED"));
  if (!valid) throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_STATE_INVALID", 500);
}

function authority(
  row: ActivationComponentJournalSessionRow,
  entries: readonly ActivationComponentJournalEntryRow[],
  selection: ActivationComponentJournalSelectionRow,
  descriptor: ActivationComponentDescriptor,
  envelopes: readonly PreparedActivationComponentEnvelope[],
  effects: readonly PreparedWormExactObjectEffect[],
  state: ActivationComponentJournalSessionState,
  terminalCode: ActivationComponentJournalSession["terminalCode"],
): ActivationComponentJournalAuthority {
  return Object.freeze({
    descriptor,
    effects: Object.freeze([...effects]),
    entries,
    envelopes: Object.freeze([...envelopes]),
    row,
    selection,
    session: Object.freeze({
      descriptor,
      freshUntil: row.fresh_until,
      generation: row.generation,
      journalOrdinal: row.journal_ordinal,
      predecessorSessionId: row.predecessor_session_id,
      sessionId: row.session_id,
      stagedCount: envelopes.length,
      state,
      terminalCode,
    }),
  });
}

function isTerminal(state: ActivationComponentJournalSessionState): boolean {
  return state === "ABANDONED" || state === "REJECTED" || state === "SUPERSEDED";
}

function requireSession(
  row: ActivationComponentJournalSessionRow | undefined,
): ActivationComponentJournalSessionRow {
  if (row === undefined)
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SESSION_MISSING");
  return row;
}

function snapshotSession(
  row: ActivationComponentJournalSessionRow,
): ActivationComponentJournalSessionRow {
  return { ...row, descriptor_bytes: copyBuffer(row.descriptor_bytes) };
}

function snapshotEntry(
  row: ActivationComponentJournalEntryRow,
): ActivationComponentJournalEntryRow {
  return {
    ...row,
    envelope_bytes: row.envelope_bytes === null ? null : copyBuffer(row.envelope_bytes),
    result_bytes: row.result_bytes === null ? null : copyBuffer(row.result_bytes),
  };
}

function snapshotSelection(
  row: ActivationComponentJournalSelectionRow,
): ActivationComponentJournalSelectionRow {
  return { ...row };
}

function copyBuffer(input: ArrayBuffer): ArrayBuffer {
  return Uint8Array.from(new Uint8Array(input)).buffer;
}
