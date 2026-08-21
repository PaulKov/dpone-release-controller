import type {
  ActivationComponentJournalEntryRow,
  ActivationComponentJournalSelectionRow,
  ActivationComponentJournalSessionRow,
} from "./activation-component-journal-schema";
import type { ActivationComponentJournalManifestRow } from "./activation-component-journal-manifest-schema";
import { componentJournalError } from "./activation-component-journal-validation";

/** Small closed query surface shared by admission, staging, and selection. */
export class ActivationComponentJournalQueries {
  public constructor(private readonly sql: SqlStorage) {}

  public session(sessionId: string): ActivationComponentJournalSessionRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalSessionRow>(
        `SELECT * FROM activation_component_sessions_v2 WHERE session_id = ?`,
        sessionId,
      )
      .toArray()[0];
  }

  public initial(setId: string): ActivationComponentJournalSessionRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalSessionRow>(
        `SELECT * FROM activation_component_sessions_v2
         WHERE set_id = ? AND generation = 1`,
        setId,
      )
      .toArray()[0];
  }

  public successor(predecessorSessionId: string): ActivationComponentJournalSessionRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalSessionRow>(
        `SELECT * FROM activation_component_sessions_v2 WHERE predecessor_session_id = ?`,
        predecessorSessionId,
      )
      .toArray()[0];
  }

  public entries(sessionId: string): readonly ActivationComponentJournalEntryRow[] {
    return this.sql
      .exec<ActivationComponentJournalEntryRow>(
        `SELECT * FROM activation_component_session_entries_v2
         WHERE session_id = ? ORDER BY ordinal`,
        sessionId,
      )
      .toArray();
  }

  public entry(
    sessionId: string,
    componentKind: string,
  ): ActivationComponentJournalEntryRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalEntryRow>(
        `SELECT * FROM activation_component_session_entries_v2
         WHERE session_id = ? AND component_kind = ?`,
        sessionId,
        componentKind,
      )
      .toArray()[0];
  }

  public entryByEffectId(
    sessionId: string,
    effectId: string,
  ): ActivationComponentJournalEntryRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalEntryRow>(
        `SELECT * FROM activation_component_session_entries_v2
         WHERE session_id = ? AND effect_id = ?`,
        sessionId,
        effectId,
      )
      .toArray()[0];
  }

  public manifest(sessionId: string): ActivationComponentJournalManifestRow | undefined {
    return this.sql
      .exec<ActivationComponentJournalManifestRow>(
        `SELECT * FROM activation_component_manifest_authority_v2 WHERE session_id = ?`,
        sessionId,
      )
      .toArray()[0];
  }

  public selection(): ActivationComponentJournalSelectionRow {
    const rows = this.sql
      .exec<ActivationComponentJournalSelectionRow>(
        `SELECT selected_session_id, state, worm_service_identity, worm_version_id,
                observer_service_identity, observer_version_id, hold_code
         FROM activation_component_selection_v2 WHERE singleton = 1`,
      )
      .toArray();
    if (rows.length !== 1 || rows[0] === undefined) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_INVALID", 500);
    }
    return rows[0];
  }

  public lifetimeCount(): number {
    return this.count(`SELECT COUNT(*) AS count FROM activation_component_sessions_v2`);
  }

  public liveCount(): number {
    return this.count(
      `SELECT COUNT(*) AS count FROM activation_component_sessions_v2
       WHERE state IN ('PROVISIONAL', 'STAGED')`,
    );
  }

  public nextJournalOrdinal(): number {
    const row = this.sql
      .exec<{ readonly ordinal: number }>(
        `SELECT COALESCE(MAX(journal_ordinal), 0) + 1 AS ordinal
         FROM activation_component_sessions_v2`,
      )
      .one();
    return row.ordinal;
  }

  private count(query: string): number {
    const count = this.sql.exec<{ readonly count: number }>(query).one().count;
    if (!Number.isSafeInteger(count) || count < 0) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_COUNT_INVALID", 500);
    }
    return count;
  }
}
