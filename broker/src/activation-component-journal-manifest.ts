import { sha256Hex } from "./canonical";
import {
  confirmActivationComponentManifestObject,
  prepareActivationComponentManifestEffect,
} from "./activation-component-confirmation";
import type {
  ActivationComponentJournalAuthority,
  ActivationComponentJournalAuthorityReader,
} from "./activation-component-journal-authority";
import {
  confirmedJournalComponentObjects,
  selectedJournalPins,
} from "./activation-component-journal-confirmation";
import type {
  ActivationComponentManifestConfirmation,
  ActivationComponentManifestSeal,
  SealedActivationComponentManifest,
} from "./activation-component-journal-contract";
import { confirmedActivationComponentJournalAuthority } from "./activation-component-journal-confirmed-authority";
import {
  hasDuplicateVersions,
  heldActivationComponentJournalAuthority,
  readActivationComponentManifestAuthority,
  type RebuiltActivationComponentManifestAuthority,
} from "./activation-component-journal-manifest-authority";
import {
  assertExactManifestResultRetry,
  assertManifestPointerRetry,
  assertSameManifestSeal,
  exactJournalEffectIdentity,
  fenceManifestJournalAuthority,
  manifestConfirmationVersionCollides,
  sealedManifestRow,
} from "./activation-component-journal-manifest-validation";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  boundedJournalBytes,
  componentJournalError,
  snapshotJournalEffect,
} from "./activation-component-journal-validation";
import {
  buildActivationComponentManifest,
  buildActivationComponentManifestPointer,
} from "./activation-component-manifest";
import type { PreparedActivationComponentManifestPointer } from "./activation-component-contract";

/** Sole mutation owner for the manifest seal, exact result, and compact pointer. */
export class ActivationComponentJournalManifestLifecycle {
  private readonly sql: SqlStorage;

  public constructor(
    private readonly storage: DurableObjectStorage,
    private readonly queries: ActivationComponentJournalQueries,
    private readonly reader: ActivationComponentJournalAuthorityReader,
  ) {
    this.sql = storage.sql;
  }

  public async seal(sessionId: string): Promise<ActivationComponentManifestSeal> {
    const authority = await this.reader.load(sessionId);
    if (authority.selection.state !== "COMPONENTS_CONFIRMED") {
      return this.sealOutcome(sessionId);
    }
    const confirmations = await confirmedJournalComponentObjects(authority);
    if (hasDuplicateVersions(confirmations)) {
      this.holdComponentVersionConflict(authority);
      return this.sealOutcome(sessionId);
    }
    const manifest = await buildActivationComponentManifest(
      authority.descriptor.canonicalBytes,
      confirmations,
    );
    const effect = await prepareActivationComponentManifestEffect(
      manifest.canonicalBytes,
      selectedJournalPins(authority),
    );
    this.persistSeal(authority, manifest, effect);
    return this.sealOutcome(sessionId);
  }

  public async confirm(
    sessionId: string,
    effectId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationComponentManifestConfirmation> {
    const exactEffectId = exactJournalEffectIdentity(effectId);
    const resultBytes = boundedJournalBytes(canonicalResultBytes);
    const rebuilt = await readActivationComponentManifestAuthority(
      this.reader,
      this.queries,
      sessionId,
    );
    if (rebuilt.effect.effectId !== exactEffectId) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_EFFECT_CONFLICT");
    }
    const resultSha256 = `sha256:${await sha256Hex(resultBytes)}`;
    if (rebuilt.row.status !== "SEALED") {
      assertExactManifestResultRetry(rebuilt.row, resultBytes, resultSha256);
      return this.confirmedOutcome(sessionId);
    }
    const confirmation = await confirmActivationComponentManifestObject(
      rebuilt.effect,
      resultBytes,
    );
    const collision = manifestConfirmationVersionCollides(rebuilt, confirmation);
    const pointer = collision ? null : await buildActivationComponentManifestPointer(confirmation);
    const pointerSha256 =
      pointer === null ? null : `sha256:${await sha256Hex(pointer.canonicalBytes)}`;
    this.persistResult(rebuilt, resultBytes, resultSha256, pointer, pointerSha256);
    return this.confirmedOutcome(sessionId);
  }

  public confirmed(sessionId: string) {
    return confirmedActivationComponentJournalAuthority(this.reader, this.queries, sessionId);
  }

  private async sealOutcome(sessionId: string): Promise<ActivationComponentManifestSeal> {
    const authority = await this.reader.load(sessionId);
    if (authority.selection.state === "CONFIRMED") {
      return {
        authority: await confirmedActivationComponentJournalAuthority(
          this.reader,
          this.queries,
          sessionId,
        ),
        outcome: "CONFIRMED",
      };
    }
    if (authority.selection.state === "HOLD") {
      return {
        held: await heldActivationComponentJournalAuthority(this.reader, this.queries, sessionId),
        outcome: "HOLD",
      };
    }
    if (authority.selection.state !== "MANIFEST_EFFECT_SEALED") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_NOT_READY");
    }
    const rebuilt = await readActivationComponentManifestAuthority(
      this.reader,
      this.queries,
      sessionId,
    );
    if (rebuilt.row.status !== "SEALED") {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_STATE_INVALID", 500);
    }
    const sealed: SealedActivationComponentManifest = Object.freeze({
      effect: snapshotJournalEffect(rebuilt.effect),
      pins: selectedJournalPins(rebuilt.authority),
      session: rebuilt.authority.session,
    });
    return { outcome: "SEALED", sealed };
  }

  private async confirmedOutcome(
    sessionId: string,
  ): Promise<ActivationComponentManifestConfirmation> {
    const authority = await this.reader.load(sessionId);
    return authority.selection.state === "HOLD"
      ? {
          held: await heldActivationComponentJournalAuthority(this.reader, this.queries, sessionId),
          outcome: "HOLD",
        }
      : {
          authority: await confirmedActivationComponentJournalAuthority(
            this.reader,
            this.queries,
            sessionId,
          ),
          outcome: "CONFIRMED",
        };
  }

  private holdComponentVersionConflict(authority: ActivationComponentJournalAuthority): void {
    this.storage.transactionSync(() => {
      const selection = this.queries.selection();
      if (
        selection.state === "HOLD" &&
        selection.selected_session_id === authority.session.sessionId &&
        selection.hold_code === "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT" &&
        this.queries.manifest(authority.session.sessionId) === undefined
      ) {
        return;
      }
      fenceManifestJournalAuthority(authority, this.queries);
      if (
        authority.selection.state !== "COMPONENTS_CONFIRMED" ||
        this.queries.manifest(authority.session.sessionId) !== undefined
      ) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      updateSelection(
        this.sql,
        authority.session.sessionId,
        "COMPONENTS_CONFIRMED",
        "HOLD",
        "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT",
      );
    });
  }

  private persistSeal(
    authority: ActivationComponentJournalAuthority,
    manifest: Awaited<ReturnType<typeof buildActivationComponentManifest>>,
    effect: Awaited<ReturnType<typeof prepareActivationComponentManifestEffect>>,
  ): void {
    const expected = sealedManifestRow(authority.session.sessionId, manifest, effect);
    this.storage.transactionSync(() => {
      const existing = this.queries.manifest(authority.session.sessionId);
      if (existing !== undefined) {
        assertSameManifestSeal(expected, existing);
        return;
      }
      fenceManifestJournalAuthority(authority, this.queries);
      if (authority.selection.state !== "COMPONENTS_CONFIRMED") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      this.sql.exec(
        `INSERT INTO activation_component_manifest_authority_v2(
           session_id, manifest_id, manifest_sha256, manifest_bytes,
           object_key, effect_id, status
         ) VALUES (?, ?, ?, ?, ?, ?, 'SEALED')`,
        expected.session_id,
        expected.manifest_id,
        expected.manifest_sha256,
        new Uint8Array(expected.manifest_bytes),
        expected.object_key,
        expected.effect_id,
      );
      updateSelection(
        this.sql,
        authority.session.sessionId,
        "COMPONENTS_CONFIRMED",
        "MANIFEST_EFFECT_SEALED",
      );
    });
  }

  private persistResult(
    rebuilt: RebuiltActivationComponentManifestAuthority,
    resultBytes: Uint8Array,
    resultSha256: string,
    pointer: PreparedActivationComponentManifestPointer | null,
    pointerSha256: string | null,
  ): void {
    this.storage.transactionSync(() => {
      const current = this.queries.manifest(rebuilt.authority.session.sessionId);
      if (current === undefined) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_MISSING");
      }
      if (current.status !== "SEALED") {
        assertSameManifestSeal(rebuilt.row, current);
        assertExactManifestResultRetry(current, resultBytes, resultSha256);
        assertManifestPointerRetry(current, pointer, pointerSha256);
        return;
      }
      fenceManifestJournalAuthority(rebuilt.authority, this.queries);
      assertSameManifestSeal(rebuilt.row, current);
      if (rebuilt.authority.selection.state !== "MANIFEST_EFFECT_SEALED") {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      const collision = pointer === null;
      const changed = this.sql
        .exec<{ readonly session_id: string }>(
          `UPDATE activation_component_manifest_authority_v2
           SET result_bytes = ?, result_sha256 = ?, pointer_bytes = ?, pointer_sha256 = ?,
               status = ?
           WHERE session_id = ? AND status = 'SEALED'
           RETURNING session_id`,
          resultBytes,
          resultSha256,
          pointer?.canonicalBytes ?? null,
          pointerSha256,
          collision ? "RESULT_CONFIRMED" : "CONFIRMED",
          rebuilt.authority.session.sessionId,
        )
        .toArray();
      if (changed.length !== 1) {
        throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
      }
      updateSelection(
        this.sql,
        rebuilt.authority.session.sessionId,
        "MANIFEST_EFFECT_SEALED",
        collision ? "HOLD" : "CONFIRMED",
        collision ? "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT" : null,
      );
    });
  }
}

function updateSelection(
  sql: SqlStorage,
  sessionId: string,
  from: string,
  to: string,
  holdCode: string | null = null,
): void {
  const changed = sql
    .exec<{ readonly selected_session_id: string }>(
      `UPDATE activation_component_selection_v2 SET state = ?, hold_code = ?
       WHERE singleton = 1 AND state = ? AND selected_session_id = ?
       RETURNING selected_session_id`,
      to,
      holdCode,
      from,
      sessionId,
    )
    .toArray();
  if (changed.length !== 1) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
}
