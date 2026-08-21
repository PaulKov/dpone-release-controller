import { prepareActivationComponentEnvelopeEffect } from "./activation-component-confirmation";
import { ACTIVATION_COMPONENT_KINDS } from "./activation-component-contract";
import {
  type ActivationComponentSetSelection,
  type ActivationComponentSetSemanticInput,
  type ActivationComponentSetSemanticValidator,
  type SealedActivationComponentSet,
} from "./activation-component-journal-contract";
import type {
  ActivationComponentJournalAuthority,
  ActivationComponentJournalAuthorityReader,
} from "./activation-component-journal-authority";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  assertJournalFresh,
  assertSameJournalPins,
  assertSameJournalEntries,
  assertSameJournalSelection,
  assertSameJournalSession,
  componentJournalError,
  journalClockNow,
  snapshotJournalPins,
  snapshotJournalEffect,
} from "./activation-component-journal-validation";
import { snapshotActivationComponentSemanticDecision } from "./activation-component-semantic-validator";
import { parseActivationComponentSetDescriptor } from "./activation-component-descriptor";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import type {
  PreparedWormExactObjectEffect,
  WormExactObjectEffectPins,
} from "./worm-exact-object-effect-contract";

/** Pure validation and atomic group sealing; no executor/provider port is accepted. */
export class ActivationComponentJournalSelection {
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly queries: ActivationComponentJournalQueries,
    private readonly reader: ActivationComponentJournalAuthorityReader,
    private readonly validator: ActivationComponentSetSemanticValidator,
    private readonly now: () => number,
  ) {
    this.sql = storage.sql;
  }

  public async selectAndSeal(sessionId: string): Promise<ActivationComponentSetSelection> {
    const initial = await this.reader.load(sessionId);
    if (initial.session.state === "REJECTED") {
      return { outcome: "REJECTED", session: initial.session };
    }
    if (initial.session.state !== "STAGED" && initial.session.state !== "SELECTED") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID");
    }
    const semanticInput = await semanticSnapshot(initial);
    const rawDecision = await this.validator.validate(semanticInput);
    const initialDecision = snapshotActivationComponentSemanticDecision(
      rawDecision,
      initial.descriptor,
    );
    const current = await this.reader.load(sessionId);
    const decision = snapshotActivationComponentSemanticDecision(rawDecision, current.descriptor);
    if (initial.session.state === "SELECTED") {
      if (current.session.state !== "SELECTED") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      if (decision.outcome !== "ACCEPT") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SEMANTIC_CONFLICT");
      }
      return { outcome: "SEALED", sealed: await this.sealedPlans(sessionId, decision.pins) };
    }
    if (current.session.state === "SELECTED" && decision.outcome === "ACCEPT") {
      return { outcome: "SEALED", sealed: await this.sealedPlans(sessionId, decision.pins) };
    }
    if (current.session.state !== "STAGED") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
    }
    assertSameJournalSession(initial.row, current.row);
    assertSameJournalEntries(initial.entries, current.entries);
    assertSameJournalSelection(initial.selection, current.selection);
    if (initialDecision.outcome !== decision.outcome) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
    }
    if (decision.outcome === "REJECT") {
      this.reject(current);
      return { outcome: "REJECTED", session: (await this.reader.load(sessionId)).session };
    }
    const effects = await Promise.all(
      current.envelopes.map((envelope) =>
        prepareActivationComponentEnvelopeEffect(
          current.descriptor.canonicalBytes,
          envelope.canonicalBytes,
          decision.pins,
        ),
      ),
    );
    if (effects.length !== ACTIVATION_COMPONENT_KINDS.length) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
    }
    this.seal(current, effects, decision.pins);
    return { outcome: "SEALED", sealed: await this.sealedPlans(sessionId, decision.pins) };
  }

  public async sealedPlans(
    sessionId: string,
    expectedPins?: WormExactObjectEffectPins,
  ): Promise<SealedActivationComponentSet> {
    const expected = expectedPins === undefined ? null : snapshotJournalPins(expectedPins);
    const authority = await this.reader.load(sessionId);
    const selection = authority.selection;
    const recoverableState = [
      "COMPONENT_EFFECTS_SEALED",
      "COMPONENTS_CONFIRMED",
      "MANIFEST_EFFECT_SEALED",
      "CONFIRMED",
      "HOLD",
    ].includes(selection.state);
    if (
      authority.session.state !== "SELECTED" ||
      !recoverableState ||
      selection.selected_session_id !== sessionId ||
      authority.effects.length !== ACTIVATION_COMPONENT_KINDS.length ||
      !authority.entries.every(({ status }) => status === "SEALED" || status === "CONFIRMED") ||
      selection.worm_service_identity === null ||
      selection.worm_version_id === null ||
      selection.observer_service_identity === null ||
      selection.observer_version_id === null
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_NOT_SEALED");
    }
    const storedPins = snapshotJournalPins({
      executorServiceIdentity: selection.worm_service_identity,
      executorVersionId: selection.worm_version_id,
      observerServiceIdentity: selection.observer_service_identity,
      observerVersionId: selection.observer_version_id,
    });
    if (expected !== null) assertSameJournalPins(expected, storedPins);
    return Object.freeze({
      effects: Object.freeze(authority.effects.map(snapshotJournalEffect)),
      pins: storedPins,
      session: authority.session,
    });
  }

  private reject(authority: ActivationComponentJournalAuthority): void {
    this.storage.transactionSync(() => {
      assertSameJournalSession(authority.row, this.queries.session(authority.session.sessionId));
      assertSameJournalEntries(
        authority.entries,
        this.queries.entries(authority.session.sessionId),
      );
      assertSameJournalSelection(authority.selection, this.queries.selection());
      if (authority.selection.state !== "OPEN") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_CLOSED");
      }
      const changed = this.sql
        .exec<{ readonly session_id: string }>(
          `UPDATE activation_component_sessions_v2
         SET state = 'REJECTED', terminal_code = 'ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID'
         WHERE session_id = ? AND state = 'STAGED'
         RETURNING session_id`,
          authority.session.sessionId,
        )
        .toArray();
      if (changed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      this.sql.exec(
        `DELETE FROM activation_component_session_entries_v2 WHERE session_id = ?`,
        authority.session.sessionId,
      );
    });
  }

  private seal(
    authority: ActivationComponentJournalAuthority,
    effects: readonly PreparedWormExactObjectEffect[],
    pins: WormExactObjectEffectPins,
  ): void {
    this.storage.transactionSync(() => {
      const currentSelection = this.queries.selection();
      if (
        currentSelection.state === "COMPONENT_EFFECTS_SEALED" &&
        currentSelection.selected_session_id === authority.session.sessionId &&
        currentSelection.worm_service_identity !== null &&
        currentSelection.worm_version_id !== null &&
        currentSelection.observer_service_identity !== null &&
        currentSelection.observer_version_id !== null
      ) {
        assertSameJournalPins(pins, {
          executorServiceIdentity: currentSelection.worm_service_identity,
          executorVersionId: currentSelection.worm_version_id,
          observerServiceIdentity: currentSelection.observer_service_identity,
          observerVersionId: currentSelection.observer_version_id,
        });
        return;
      }
      assertSameJournalSession(authority.row, this.queries.session(authority.session.sessionId));
      assertSameJournalEntries(
        authority.entries,
        this.queries.entries(authority.session.sessionId),
      );
      assertSameJournalSelection(authority.selection, this.queries.selection());
      assertJournalFresh(authority.session.freshUntil, journalClockNow(this.now).milliseconds);
      const claimed = this.sql
        .exec<{ readonly selected_session_id: string }>(
          `UPDATE activation_component_selection_v2
         SET selected_session_id = ?, state = 'COMPONENT_EFFECTS_SEALED',
             worm_service_identity = ?, worm_version_id = ?,
             observer_service_identity = ?, observer_version_id = ?
         WHERE singleton = 1 AND state = 'OPEN' AND selected_session_id IS NULL
         RETURNING selected_session_id`,
          authority.session.sessionId,
          pins.executorServiceIdentity,
          pins.executorVersionId,
          pins.observerServiceIdentity,
          pins.observerVersionId,
        )
        .toArray();
      if (claimed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_CAS_CONFLICT");
      }
      const selected = this.sql
        .exec<{ readonly session_id: string }>(
          `UPDATE activation_component_sessions_v2 SET state = 'SELECTED'
         WHERE session_id = ? AND state = 'STAGED'
         RETURNING session_id`,
          authority.session.sessionId,
        )
        .toArray();
      if (selected.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      effects.forEach((effect, ordinal) => {
        const changed = this.sql
          .exec<{ readonly ordinal: number }>(
            `UPDATE activation_component_session_entries_v2
           SET effect_id = ?, status = 'SEALED'
           WHERE session_id = ? AND ordinal = ? AND status = 'STAGED'
           RETURNING ordinal`,
            effect.effectId,
            authority.session.sessionId,
            ordinal,
          )
          .toArray();
        if (changed.length !== 1) {
          throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
        }
      });
      this.sql.exec(
        `UPDATE activation_component_sessions_v2
         SET state = 'SUPERSEDED', terminal_code = 'ACTIVATION_COMPONENT_SESSION_SUPERSEDED'
         WHERE session_id != ? AND state IN ('PROVISIONAL', 'STAGED')`,
        authority.session.sessionId,
      );
      this.sql.exec(
        `DELETE FROM activation_component_session_entries_v2
         WHERE session_id IN (
           SELECT session_id FROM activation_component_sessions_v2 WHERE state = 'SUPERSEDED'
         )`,
      );
    });
  }
}

async function semanticSnapshot(
  authority: ActivationComponentJournalAuthority,
): Promise<ActivationComponentSetSemanticInput> {
  const descriptor = await parseActivationComponentSetDescriptor(
    Uint8Array.from(authority.descriptor.canonicalBytes),
  );
  const envelopes = await Promise.all(
    authority.envelopes.map((envelope) =>
      parseActivationComponentEnvelope(
        Uint8Array.from(envelope.canonicalBytes),
        descriptor.canonicalBytes,
      ),
    ),
  );
  return Object.freeze({ descriptor, envelopes: Object.freeze(envelopes) });
}
