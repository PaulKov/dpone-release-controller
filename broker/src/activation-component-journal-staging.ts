import type { ActivationComponentJournalAuthorityReader } from "./activation-component-journal-authority";
import type { ActivationComponentJournalSession } from "./activation-component-journal-contract";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  assertJournalFresh,
  assertSameJournalSessionIdentity,
  boundedJournalBytes,
  componentJournalError,
  journalClockNow,
  sameJournalBytes,
} from "./activation-component-journal-validation";
import { parseActivationComponentEnvelope } from "./activation-component-envelope";
import type { PreparedActivationComponentEnvelope } from "./activation-component-contract";

/** Exact envelope staging; this class cannot derive or dispatch any remote effect. */
export class ActivationComponentJournalStaging {
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly queries: ActivationComponentJournalQueries,
    private readonly reader: ActivationComponentJournalAuthorityReader,
    private readonly now: () => number,
  ) {
    this.sql = storage.sql;
  }

  public async stageEnvelope(
    sessionId: string,
    canonicalEnvelopeBytes: Uint8Array,
  ): Promise<ActivationComponentJournalSession> {
    const envelopeBytes = boundedJournalBytes(canonicalEnvelopeBytes);
    const authority = await this.reader.load(sessionId);
    const envelope = await parseActivationComponentEnvelope(
      envelopeBytes,
      authority.descriptor.canonicalBytes,
    );
    const existing = authority.entries.find(
      ({ component_kind }) => component_kind === envelope.componentKind,
    );
    if (existing === undefined) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
    }
    if (existing.status !== "EXPECTED") {
      assertEnvelopeStored(existing, envelope);
      return authority.session;
    }
    if (authority.session.state !== "PROVISIONAL") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_STAGE_INVALID");
    }
    this.storage.transactionSync(() => {
      const session = this.queries.session(sessionId);
      assertSameJournalSessionIdentity(authority.row, session);
      const current = this.queries.entry(sessionId, envelope.componentKind);
      if (current === undefined) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID", 500);
      }
      if (current.status !== "EXPECTED") {
        assertEnvelopeStored(current, envelope);
        return;
      }
      if (session?.state !== "PROVISIONAL" || this.queries.selection().state !== "OPEN") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_CLOSED");
      }
      assertJournalFresh(session.fresh_until, journalClockNow(this.now).milliseconds);
      const changed = this.sql
        .exec<{ readonly ordinal: number }>(
          `UPDATE activation_component_session_entries_v2
         SET component_id = ?, envelope_sha256 = ?, envelope_bytes = ?, object_key = ?,
             status = 'STAGED'
         WHERE session_id = ? AND component_kind = ? AND status = 'EXPECTED'
         RETURNING ordinal`,
          envelope.componentId,
          envelope.envelopeSha256,
          Uint8Array.from(envelope.canonicalBytes).buffer,
          envelope.key,
          sessionId,
          envelope.componentKind,
        )
        .toArray();
      if (changed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      const remaining = this.sql
        .exec<{ readonly count: number }>(
          `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
           WHERE session_id = ? AND status = 'EXPECTED'`,
          sessionId,
        )
        .one().count;
      if (remaining === 0) {
        const advanced = this.sql
          .exec<{ readonly session_id: string }>(
            `UPDATE activation_component_sessions_v2 SET state = 'STAGED'
           WHERE session_id = ? AND state = 'PROVISIONAL'
           RETURNING session_id`,
            sessionId,
          )
          .toArray();
        if (advanced.length !== 1) {
          throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
        }
      }
    });
    return (await this.reader.load(sessionId)).session;
  }
}

function assertEnvelopeStored(
  row: ReturnType<ActivationComponentJournalQueries["entries"]>[number],
  envelope: PreparedActivationComponentEnvelope,
): void {
  if (
    row.component_id !== envelope.componentId ||
    row.envelope_sha256 !== envelope.envelopeSha256 ||
    row.expected_payload_sha256 !== envelope.payloadSha256 ||
    row.object_key !== envelope.key ||
    !sameJournalBytes(row.envelope_bytes, envelope.canonicalBytes.buffer)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_STAGE_CONFLICT");
  }
}
