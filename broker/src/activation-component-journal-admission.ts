import {
  ACTIVATION_COMPONENT_KINDS,
  type ActivationComponentDigestInput,
  type ActivationComponentDescriptor,
  type ActivationComponentKind,
} from "./activation-component-contract";
import {
  ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS,
  ACTIVATION_COMPONENT_JOURNAL_MAX_LIVE_SESSIONS,
  type ActivationComponentJournalInitialInput,
  type ActivationComponentJournalReissueInput,
  type ActivationComponentJournalSession,
} from "./activation-component-journal-contract";
import type {
  ActivationComponentJournalAuthority,
  ActivationComponentJournalAuthorityReader,
} from "./activation-component-journal-authority";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  activationComponentJournalSessionId,
  assertJournalExpired,
  assertJournalFresh,
  assertSameJournalEntries,
  assertSameJournalSelection,
  assertSameJournalSession,
  componentJournalError,
  journalClockNow,
  journalFreshUntil,
} from "./activation-component-journal-validation";
import {
  buildActivationComponentSetDescriptor,
  type ActivationComponentDescriptorInput,
} from "./activation-component-descriptor";

/** Admission and explicit expiry/reissue policy for provisional component sets. */
export class ActivationComponentJournalAdmission {
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly queries: ActivationComponentJournalQueries,
    private readonly reader: ActivationComponentJournalAuthorityReader,
    private readonly workerVersionId: string,
    private readonly now: () => number,
  ) {
    this.sql = storage.sql;
  }

  public async beginInitial(
    input: ActivationComponentJournalInitialInput,
  ): Promise<ActivationComponentJournalSession> {
    const components = snapshotRoster(input.components);
    const descriptor = await this.buildDescriptor(components);
    const existing = this.queries.initial(descriptor.setId);
    if (existing !== undefined) {
      return this.resolveExisting(existing.session_id);
    }
    return (
      await this.createSession({
        descriptor,
        generation: 1,
        predecessorSessionId: null,
      })
    ).session;
  }

  public async abandonExpired(sessionId: string): Promise<ActivationComponentJournalSession> {
    const authority = await this.reader.load(sessionId);
    if (authority.session.state === "ABANDONED") return authority.session;
    if (authority.session.state !== "PROVISIONAL" && authority.session.state !== "STAGED") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ABANDON_INVALID");
    }
    assertJournalExpired(authority.session.freshUntil, journalClockNow(this.now).milliseconds);
    this.storage.transactionSync(() => {
      this.assertOpenUnsealed();
      assertSameJournalSession(authority.row, this.queries.session(sessionId));
      assertSameJournalEntries(authority.entries, this.queries.entries(sessionId));
      assertSameJournalSelection(authority.selection, this.queries.selection());
      assertJournalExpired(authority.session.freshUntil, journalClockNow(this.now).milliseconds);
      const changed = this.sql
        .exec<{ readonly session_id: string }>(
          `UPDATE activation_component_sessions_v2
         SET state = 'ABANDONED', terminal_code = 'ACTIVATION_COMPONENT_SESSION_EXPIRED'
         WHERE session_id = ? AND state IN ('PROVISIONAL', 'STAGED')
         RETURNING session_id`,
          sessionId,
        )
        .toArray();
      if (changed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      this.sql.exec(
        `DELETE FROM activation_component_session_entries_v2 WHERE session_id = ?`,
        sessionId,
      );
    });
    return (await this.reader.load(sessionId)).session;
  }

  public async reissueExpired(
    input: ActivationComponentJournalReissueInput,
  ): Promise<ActivationComponentJournalSession> {
    const predecessorIdentity = Object.freeze({
      descriptorId: input.predecessorDescriptorId,
      descriptorSha256: input.predecessorDescriptorSha256,
      sessionId: input.predecessorSessionId,
    });
    const predecessor = await this.reader.load(predecessorIdentity.sessionId);
    if (
      predecessor.descriptor.descriptorId !== predecessorIdentity.descriptorId ||
      predecessor.descriptor.descriptorSha256 !== predecessorIdentity.descriptorSha256
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_CONFLICT");
    }
    if (
      predecessor.session.state !== "ABANDONED" ||
      predecessor.session.terminalCode !== "ACTIVATION_COMPONENT_SESSION_EXPIRED"
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_REISSUE_INVALID");
    }
    const existing = this.queries.successor(predecessorIdentity.sessionId);
    if (existing !== undefined) return this.resolveExisting(existing.session_id);
    const generation = predecessor.session.generation + 1;
    if (generation > ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_LIFETIME_EXHAUSTED");
    }
    const descriptor = await this.buildDescriptor(predecessor.descriptor.components);
    if (
      descriptor.setId !== predecessor.descriptor.setId ||
      descriptor.committedAt <= predecessor.session.freshUntil
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_CONFLICT", 500);
    }
    return (
      await this.createSession({
        descriptor,
        generation,
        predecessorSessionId: predecessorIdentity.sessionId,
      })
    ).session;
  }

  private async buildDescriptor(
    components: ActivationComponentDescriptorInput["components"],
  ): Promise<ActivationComponentDescriptor> {
    return buildActivationComponentSetDescriptor({
      committedAt: journalClockNow(this.now).timestamp,
      components,
      workerVersionId: this.workerVersionId,
    });
  }

  private async resolveExisting(sessionId: string): Promise<ActivationComponentJournalSession> {
    const existing = (await this.reader.load(sessionId)).session;
    if (
      (existing.state === "PROVISIONAL" || existing.state === "STAGED") &&
      journalClockNow(this.now).timestamp > existing.freshUntil
    ) {
      return this.abandonExpired(sessionId);
    }
    return existing;
  }

  private async createSession(input: {
    readonly descriptor: ActivationComponentDescriptor;
    readonly generation: number;
    readonly predecessorSessionId: string | null;
  }): Promise<ActivationComponentJournalAuthority> {
    for (
      let attempt = 0;
      attempt < ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS;
      attempt += 1
    ) {
      const journalOrdinal = this.queries.nextJournalOrdinal();
      if (journalOrdinal > ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_LIFETIME_EXHAUSTED");
      }
      const sessionId = await activationComponentJournalSessionId(
        this.workerVersionId,
        input.descriptor.setId,
        input.descriptor.descriptorId,
        input.descriptor.descriptorSha256,
        input.generation,
        journalOrdinal,
        input.predecessorSessionId,
      );
      let resolvedId: string | undefined;
      this.storage.transactionSync(() => {
        const existing =
          input.predecessorSessionId === null
            ? this.queries.initial(input.descriptor.setId)
            : this.queries.successor(input.predecessorSessionId);
        if (existing !== undefined) {
          resolvedId = existing.session_id;
          return;
        }
        this.assertOpenUnsealed();
        this.expireStaleSessions();
        this.assertCapacity();
        assertJournalFresh(
          journalFreshUntil(input.descriptor.committedAt),
          journalClockNow(this.now).milliseconds,
        );
        if (this.queries.nextJournalOrdinal() !== journalOrdinal) {
          return;
        }
        this.assertPredecessorForInsert(input, journalOrdinal);
        this.insertSession(input, sessionId, journalOrdinal);
        resolvedId = sessionId;
      });
      if (resolvedId === undefined) continue;
      return this.reader.load(resolvedId);
    }
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ADMISSION_CONFLICT");
  }

  private insertSession(
    input: {
      readonly descriptor: ActivationComponentDescriptor;
      readonly generation: number;
      readonly predecessorSessionId: string | null;
    },
    sessionId: string,
    journalOrdinal: number,
  ): void {
    const descriptor = input.descriptor;
    this.sql.exec(
      `INSERT INTO activation_component_sessions_v2(
         session_id, journal_ordinal, generation, predecessor_session_id, set_id,
         worker_version_id, descriptor_id, descriptor_sha256, descriptor_bytes,
         component_set_committed_at, fresh_until, state, terminal_code
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROVISIONAL', NULL)`,
      sessionId,
      journalOrdinal,
      input.generation,
      input.predecessorSessionId,
      descriptor.setId,
      descriptor.workerVersionId,
      descriptor.descriptorId,
      descriptor.descriptorSha256,
      Uint8Array.from(descriptor.canonicalBytes).buffer,
      descriptor.committedAt,
      journalFreshUntil(descriptor.committedAt),
    );
    descriptor.components.forEach(({ componentKind, payloadSha256 }, ordinal) => {
      this.sql.exec(
        `INSERT INTO activation_component_session_entries_v2(
           session_id, ordinal, component_kind, expected_payload_sha256, status
         ) VALUES (?, ?, ?, ?, 'EXPECTED')`,
        sessionId,
        ordinal,
        componentKind,
        payloadSha256,
      );
    });
  }

  private assertPredecessorForInsert(
    input: {
      readonly descriptor: ActivationComponentDescriptor;
      readonly generation: number;
      readonly predecessorSessionId: string | null;
    },
    journalOrdinal: number,
  ): void {
    if (input.predecessorSessionId === null) return;
    const predecessor = this.queries.session(input.predecessorSessionId);
    if (
      predecessor?.state !== "ABANDONED" ||
      predecessor.terminal_code !== "ACTIVATION_COMPONENT_SESSION_EXPIRED" ||
      predecessor.set_id !== input.descriptor.setId ||
      predecessor.generation + 1 !== input.generation ||
      predecessor.journal_ordinal >= journalOrdinal ||
      predecessor.fresh_until >= input.descriptor.committedAt
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_PREDECESSOR_CONFLICT");
    }
  }

  private assertCapacity(): void {
    if (this.queries.liveCount() >= ACTIVATION_COMPONENT_JOURNAL_MAX_LIVE_SESSIONS) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_LIVE_CAPACITY_EXHAUSTED", 429);
    }
    if (this.queries.lifetimeCount() >= ACTIVATION_COMPONENT_JOURNAL_MAX_LIFETIME_SESSIONS) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_LIFETIME_EXHAUSTED", 429);
    }
  }

  private expireStaleSessions(): void {
    const now = journalClockNow(this.now).timestamp;
    this.sql.exec(
      `UPDATE activation_component_sessions_v2
       SET state = 'ABANDONED', terminal_code = 'ACTIVATION_COMPONENT_SESSION_EXPIRED'
       WHERE state IN ('PROVISIONAL', 'STAGED') AND fresh_until < ?`,
      now,
    );
    this.sql.exec(
      `DELETE FROM activation_component_session_entries_v2
       WHERE session_id IN (
         SELECT session_id FROM activation_component_sessions_v2 WHERE state = 'ABANDONED'
       )`,
    );
  }

  private assertOpenUnsealed(): void {
    const selection = this.queries.selection();
    const sealed = this.sql
      .exec<{ readonly count: number }>(
        `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
         WHERE status IN ('SEALED', 'CONFIRMED')`,
      )
      .one().count;
    const selected = this.sql
      .exec<{
        readonly count: number;
      }>(`SELECT COUNT(*) AS count FROM activation_component_sessions_v2 WHERE state = 'SELECTED'`)
      .one().count;
    if (
      selection.state !== "OPEN" ||
      selection.selected_session_id !== null ||
      sealed !== 0 ||
      selected !== 0
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_SELECTION_CLOSED");
    }
  }
}

function snapshotRoster(input: unknown): readonly ActivationComponentDigestInput[] {
  if (!Array.isArray(input) || input.length !== ACTIVATION_COMPONENT_KINDS.length) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID");
  }
  return input.map((candidate: unknown) => {
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID");
    }
    const value = candidate as Record<string, unknown>;
    const componentKind = value.componentKind;
    const payloadSha256 = value.payloadSha256;
    if (
      typeof componentKind !== "string" ||
      !ACTIVATION_COMPONENT_KINDS.includes(componentKind as ActivationComponentKind) ||
      typeof payloadSha256 !== "string"
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_ROSTER_INVALID");
    }
    return { componentKind: componentKind as ActivationComponentKind, payloadSha256 };
  });
}
