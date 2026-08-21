import { sha256Hex } from "./canonical";
import {
  confirmActivationComponentEnvelopeObject,
  type ConfirmedActivationComponentEnvelopeObject,
} from "./activation-component-confirmation";
import { ACTIVATION_COMPONENT_KINDS } from "./activation-component-contract";
import type { UnresolvedActivationComponentEffects } from "./activation-component-journal-contract";
import type {
  ActivationComponentJournalAuthority,
  ActivationComponentJournalAuthorityReader,
} from "./activation-component-journal-authority";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  assertSameJournalEntries,
  assertSameJournalPins,
  assertSameJournalSelection,
  assertSameJournalSession,
  boundedJournalBytes,
  componentJournalError,
  sameJournalBytes,
  snapshotJournalEffect,
  snapshotJournalPins,
} from "./activation-component-journal-validation";
import type {
  PreparedWormExactObjectEffect,
  WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

const EFFECT_ID = /^sha256:[0-9a-f]{64}$/u;

/** Exact result confirmation for already sealed component effects. */
export class ActivationComponentJournalConfirmation {
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly queries: ActivationComponentJournalQueries,
    private readonly reader: ActivationComponentJournalAuthorityReader,
  ) {
    this.sql = storage.sql;
  }

  public async unresolved(
    sessionId: string,
    expectedPins?: WormExactObjectEffectPins,
  ): Promise<UnresolvedActivationComponentEffects> {
    const expected = expectedPins === undefined ? null : snapshotJournalPins(expectedPins);
    const authority = await this.reader.load(sessionId);
    const pins = selectedJournalPins(authority);
    if (expected !== null) assertSameJournalPins(expected, pins);
    assertContinuationState(authority);
    const effects = unresolvedEffects(authority);
    return Object.freeze({
      effects: Object.freeze(effects.map(snapshotJournalEffect)),
      pins,
      session: authority.session,
    });
  }

  public async confirm(
    sessionId: string,
    effectId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<UnresolvedActivationComponentEffects> {
    const exactEffectId = exactEffectIdentity(effectId);
    const resultBytes = boundedJournalBytes(canonicalResultBytes);
    const authority = await this.reader.load(sessionId);
    assertContinuationState(authority);
    const entry = authority.entries.find(({ effect_id }) => effect_id === exactEffectId);
    if (entry?.effect_id == null) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_MISSING");
    }
    const effect = authority.effects[entry.ordinal];
    if (effect?.effectId !== exactEffectId) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_CONFLICT", 500);
    }
    await confirmActivationComponentEnvelopeObject(
      authority.descriptor.canonicalBytes,
      effect,
      resultBytes,
    );
    const resultSha256 = `sha256:${await sha256Hex(resultBytes)}`;
    this.persist(authority, entry.ordinal, effect, resultBytes, resultSha256);
    return this.unresolved(sessionId);
  }

  private persist(
    authority: ActivationComponentJournalAuthority,
    ordinal: number,
    effect: PreparedWormExactObjectEffect,
    resultBytes: Uint8Array,
    resultSha256: string,
  ): void {
    this.storage.transactionSync(() => {
      const current = this.queries.entryByEffectId(authority.session.sessionId, effect.effectId);
      if (current === undefined) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_MISSING");
      }
      if (current.status === "CONFIRMED") {
        if (
          current.result_sha256 !== resultSha256 ||
          !sameJournalBytes(current.result_bytes, resultBytes.buffer)
        ) {
          throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_RESULT_CONFLICT");
        }
        return;
      }
      assertSameJournalSession(authority.row, this.queries.session(authority.session.sessionId));
      const expectedEntry = authority.entries[ordinal];
      if (expectedEntry === undefined) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
      }
      assertSameJournalEntries([expectedEntry], [current]);
      assertSameJournalSelection(authority.selection, this.queries.selection());
      if (current.status !== "SEALED" || authority.selection.state !== "COMPONENT_EFFECTS_SEALED") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMATION_INVALID");
      }
      const changed = this.sql
        .exec<{ readonly ordinal: number }>(
          `UPDATE activation_component_session_entries_v2
           SET result_bytes = ?, result_sha256 = ?, status = 'CONFIRMED'
           WHERE session_id = ? AND ordinal = ? AND effect_id = ? AND status = 'SEALED'
           RETURNING ordinal`,
          resultBytes,
          resultSha256,
          authority.session.sessionId,
          ordinal,
          effect.effectId,
        )
        .toArray();
      if (changed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      const remaining = this.sql
        .exec<{ readonly count: number }>(
          `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
           WHERE session_id = ? AND status = 'SEALED'`,
          authority.session.sessionId,
        )
        .one().count;
      if (remaining === 0) {
        const advanced = this.sql
          .exec<{ readonly selected_session_id: string }>(
            `UPDATE activation_component_selection_v2 SET state = 'COMPONENTS_CONFIRMED'
             WHERE singleton = 1 AND state = 'COMPONENT_EFFECTS_SEALED'
               AND selected_session_id = ?
             RETURNING selected_session_id`,
            authority.session.sessionId,
          )
          .toArray();
        if (advanced.length !== 1) {
          throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
        }
      }
    });
  }
}

/** Rebuild all 15 opaque confirmations solely from the current SQLite authority. */
export async function confirmedJournalComponentObjects(
  authority: ActivationComponentJournalAuthority,
): Promise<readonly ConfirmedActivationComponentEnvelopeObject[]> {
  if (
    authority.entries.length !== ACTIVATION_COMPONENT_KINDS.length ||
    authority.effects.length !== ACTIVATION_COMPONENT_KINDS.length ||
    !authority.entries.every(({ status }) => status === "CONFIRMED")
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_COMPONENTS_NOT_CONFIRMED");
  }
  return Object.freeze(
    await Promise.all(
      authority.entries.map(async (entry, ordinal) => {
        const effect = authority.effects[ordinal];
        if (effect === undefined || entry.result_bytes === null) {
          throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ENTRY_INVALID", 500);
        }
        return confirmActivationComponentEnvelopeObject(
          authority.descriptor.canonicalBytes,
          effect,
          new Uint8Array(entry.result_bytes),
        );
      }),
    ),
  );
}

export function selectedJournalPins(
  authority: ActivationComponentJournalAuthority,
): WormExactObjectEffectPins {
  const selection = authority.selection;
  if (
    authority.session.state !== "SELECTED" ||
    selection.selected_session_id !== authority.session.sessionId ||
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

function unresolvedEffects(
  authority: ActivationComponentJournalAuthority,
): readonly PreparedWormExactObjectEffect[] {
  if (authority.effects.length !== ACTIVATION_COMPONENT_KINDS.length) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
  }
  return authority.entries.flatMap((entry, ordinal) => {
    if (entry.status !== "SEALED") return [];
    const effect = authority.effects[ordinal];
    if (effect === undefined) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_CONFLICT", 500);
    }
    return [effect];
  });
}

function assertContinuationState(authority: ActivationComponentJournalAuthority): void {
  if (
    authority.session.state !== "SELECTED" ||
    ![
      "COMPONENT_EFFECTS_SEALED",
      "COMPONENTS_CONFIRMED",
      "MANIFEST_EFFECT_SEALED",
      "CONFIRMED",
      "HOLD",
    ].includes(authority.selection.state)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CONFIRMATION_INVALID");
  }
  selectedJournalPins(authority);
}

function exactEffectIdentity(value: string): string {
  if (typeof value !== "string" || !EFFECT_ID.test(value)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_INVALID");
  }
  return value;
}
