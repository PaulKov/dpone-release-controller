import {
  ACTIVATION_COMPONENT_DIGEST,
  ACTIVATION_COMPONENT_WORKER_VERSION,
} from "./activation-component-codec";
import { componentJournalError } from "./activation-component-journal-boundary";
import {
  ACTIVATION_COMPONENT_JOURNAL_TTL_MS,
  type ActivationComponentJournalSessionState,
  type ActivationComponentJournalTerminalCode,
} from "./activation-component-journal-contract";
import type {
  ActivationComponentJournalEntryRow,
  ActivationComponentJournalSelectionRow,
  ActivationComponentJournalSessionRow,
} from "./activation-component-journal-schema";
import { digestDomain } from "./identity";
import type { WormExactObjectEffectPins } from "./worm-exact-object-effect-contract";

export {
  boundedJournalBytes,
  componentJournalError,
  snapshotJournalEffect,
  snapshotJournalPins,
} from "./activation-component-journal-boundary";

const SESSION_STATES = new Set<ActivationComponentJournalSessionState>([
  "ABANDONED",
  "PROVISIONAL",
  "REJECTED",
  "SELECTED",
  "STAGED",
  "SUPERSEDED",
]);
const TERMINAL_CODES = new Set<ActivationComponentJournalTerminalCode>([
  "ACTIVATION_COMPONENT_SESSION_EXPIRED",
  "ACTIVATION_COMPONENT_SESSION_SUPERSEDED",
  "ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID",
]);
export function journalTimestamp(nowMs: number): string {
  if (!Number.isSafeInteger(nowMs)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_TIME_INVALID");
  }
  try {
    return new Date(nowMs).toISOString();
  } catch {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_TIME_INVALID");
  }
}

export function journalClockNow(now: () => number): {
  readonly milliseconds: number;
  readonly timestamp: string;
} {
  let milliseconds: number;
  try {
    milliseconds = now();
  } catch {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_TIME_INVALID");
  }
  return { milliseconds, timestamp: journalTimestamp(milliseconds) };
}

export function journalFreshUntil(committedAt: string): string {
  const committedMs = Date.parse(committedAt);
  if (!Number.isFinite(committedMs) || new Date(committedMs).toISOString() !== committedAt) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_TIME_INVALID");
  }
  return journalTimestamp(committedMs + ACTIVATION_COMPONENT_JOURNAL_TTL_MS);
}

export function assertJournalFresh(freshUntil: string, nowMs: number): void {
  const now = journalTimestamp(nowMs);
  if (now > freshUntil) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SESSION_EXPIRED");
  }
}

export function assertJournalExpired(freshUntil: string, nowMs: number): void {
  const now = journalTimestamp(nowMs);
  if (now <= freshUntil) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SESSION_FRESH");
  }
}

export function assertSameJournalPins(
  expected: WormExactObjectEffectPins,
  actual: WormExactObjectEffectPins,
): void {
  if (
    expected.executorServiceIdentity !== actual.executorServiceIdentity ||
    expected.executorVersionId !== actual.executorVersionId ||
    expected.observerServiceIdentity !== actual.observerServiceIdentity ||
    expected.observerVersionId !== actual.observerVersionId
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PIN_CONFLICT");
  }
}

export function activationComponentJournalSessionId(
  workerVersionId: string,
  setId: string,
  descriptorId: string,
  descriptorSha256: string,
  generation: number,
  journalOrdinal: number,
  predecessorSessionId: string | null,
): Promise<string> {
  if (
    !ACTIVATION_COMPONENT_WORKER_VERSION.test(workerVersionId) ||
    ![setId, descriptorId, descriptorSha256].every((value) =>
      ACTIVATION_COMPONENT_DIGEST.test(value),
    ) ||
    !Number.isSafeInteger(generation) ||
    generation < 1 ||
    generation > 8 ||
    !Number.isSafeInteger(journalOrdinal) ||
    journalOrdinal < 1 ||
    journalOrdinal > 8 ||
    (predecessorSessionId !== null && !ACTIVATION_COMPONENT_DIGEST.test(predecessorSessionId))
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_IDENTITY_INVALID");
  }
  return digestDomain("dpone.activation-component-journal-session.v2", {
    descriptor_id: descriptorId,
    descriptor_sha256: descriptorSha256,
    generation,
    journal_ordinal: journalOrdinal,
    predecessor_session_id: predecessorSessionId,
    set_id: setId,
    worker_version_id: workerVersionId,
  });
}

export function sessionState(row: ActivationComponentJournalSessionRow): {
  readonly state: ActivationComponentJournalSessionState;
  readonly terminalCode: ActivationComponentJournalTerminalCode | null;
} {
  if (!SESSION_STATES.has(row.state as ActivationComponentJournalSessionState)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_STATE_INVALID", 500);
  }
  if (row.terminal_code !== null && !TERMINAL_CODES.has(row.terminal_code as never)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_STATE_INVALID", 500);
  }
  return {
    state: row.state as ActivationComponentJournalSessionState,
    terminalCode: row.terminal_code as ActivationComponentJournalTerminalCode | null,
  };
}

export function sameJournalBytes(
  left: ArrayBufferLike | null,
  right: ArrayBufferLike | null,
): boolean {
  if (left === null || right === null) return left === right;
  const leftBytes = new Uint8Array(left);
  const rightBytes = new Uint8Array(right);
  if (leftBytes.byteLength !== rightBytes.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.byteLength; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

export function assertSameJournalSession(
  expected: ActivationComponentJournalSessionRow,
  actual: ActivationComponentJournalSessionRow | undefined,
): void {
  if (
    !sameSessionIdentity(expected, actual) ||
    expected.state !== actual.state ||
    expected.terminal_code !== actual.terminal_code
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
}

export function assertSameJournalSessionIdentity(
  expected: ActivationComponentJournalSessionRow,
  actual: ActivationComponentJournalSessionRow | undefined,
): void {
  if (!sameSessionIdentity(expected, actual)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
}

export function assertSameJournalEntries(
  expected: readonly ActivationComponentJournalEntryRow[],
  actual: readonly ActivationComponentJournalEntryRow[],
): void {
  if (expected.length !== actual.length) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
  for (let index = 0; index < expected.length; index += 1) {
    const left = expected[index];
    const right = actual[index];
    if (left === undefined || right === undefined) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
    }
    if (
      left.session_id !== right.session_id ||
      left.ordinal !== right.ordinal ||
      left.component_kind !== right.component_kind ||
      left.expected_payload_sha256 !== right.expected_payload_sha256 ||
      left.component_id !== right.component_id ||
      left.envelope_sha256 !== right.envelope_sha256 ||
      left.object_key !== right.object_key ||
      left.effect_id !== right.effect_id ||
      left.result_sha256 !== right.result_sha256 ||
      left.status !== right.status ||
      !sameJournalBytes(left.envelope_bytes, right.envelope_bytes) ||
      !sameJournalBytes(left.result_bytes, right.result_bytes)
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
    }
  }
}

export function assertSameJournalSelection(
  expected: ActivationComponentJournalSelectionRow,
  actual: ActivationComponentJournalSelectionRow,
): void {
  if (
    expected.selected_session_id !== actual.selected_session_id ||
    expected.state !== actual.state ||
    expected.worm_service_identity !== actual.worm_service_identity ||
    expected.worm_version_id !== actual.worm_version_id ||
    expected.observer_service_identity !== actual.observer_service_identity ||
    expected.observer_version_id !== actual.observer_version_id ||
    expected.hold_code !== actual.hold_code
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
}

function sameSessionIdentity(
  expected: ActivationComponentJournalSessionRow,
  actual: ActivationComponentJournalSessionRow | undefined,
): actual is ActivationComponentJournalSessionRow {
  return (
    expected.session_id === actual?.session_id &&
    expected.journal_ordinal === actual.journal_ordinal &&
    expected.generation === actual.generation &&
    expected.predecessor_session_id === actual.predecessor_session_id &&
    expected.set_id === actual.set_id &&
    expected.worker_version_id === actual.worker_version_id &&
    expected.descriptor_id === actual.descriptor_id &&
    expected.descriptor_sha256 === actual.descriptor_sha256 &&
    expected.component_set_committed_at === actual.component_set_committed_at &&
    expected.fresh_until === actual.fresh_until &&
    sameJournalBytes(expected.descriptor_bytes, actual.descriptor_bytes)
  );
}
