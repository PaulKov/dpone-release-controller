import type {
  ActivationComponentManifestConfirmation,
  ConfirmedActivationComponentJournalAuthority,
  SealedActivationComponentManifest,
  SealedActivationComponentSet,
} from "../src/activation-component-journal-contract";
import type { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import type { ActivationWorm } from "../src/types";
import type { PreparedWormExactObjectEffect } from "../src/worm-exact-object-effect-contract";
import { COMPONENT_RETENTION_UNTIL, resultBytes } from "./activation-component-manifest.fixtures";
import {
  type JournalClock,
  type PreparedJournalSession,
  journalClock,
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";

export interface SelectedContinuationFixture {
  readonly clock: JournalClock;
  readonly prepared: PreparedJournalSession;
  readonly sealed: SealedActivationComponentSet;
  readonly store: ActivationComponentJournalStore;
}

export interface ConfirmedContinuationFixture extends SelectedContinuationFixture {
  readonly authority: ConfirmedActivationComponentJournalAuthority;
  readonly componentResults: readonly Uint8Array[];
  readonly manifestResult: Uint8Array;
  readonly manifestSeal: SealedActivationComponentManifest;
}

export interface ContinuationSelectionSummary extends Record<string, SqlStorageValue> {
  readonly hold_code: string | null;
  readonly state: string;
}

export interface ContinuationEntrySummary extends Record<string, SqlStorageValue> {
  readonly result_bytes: ArrayBuffer | null;
  readonly result_sha256: string | null;
  readonly status: string;
}

export interface ContinuationManifestSummary extends ContinuationEntrySummary {
  readonly pointer_bytes: ArrayBuffer | null;
  readonly pointer_sha256: string | null;
}

/** Stage and select one complete synthetic roster without any provider port. */
export async function selectedContinuationFixture(
  storage: DurableObjectStorage,
  clock: JournalClock = journalClock(),
): Promise<SelectedContinuationFixture> {
  const store = journalStore(storage, clock);
  const prepared = await prepareJournalSession(store);
  await stagePreparedJournalSession(store, prepared);
  const selection = await store.selectAndSeal(prepared.session.sessionId);
  if (selection.outcome !== "SEALED") throw new Error("continuation fixture was not selected");
  return { clock, prepared, sealed: selection.sealed, store };
}

/** Produce the exact generic-effect result for one sealed journal effect. */
export function continuationResultBytes(
  effect: PreparedWormExactObjectEffect,
  versionId: string,
  absenceOrdinal: number,
): Uint8Array {
  const worm: ActivationWorm = {
    digest: effect.digest,
    key: effect.key,
    retentionUntil: COMPONENT_RETENTION_UNTIL,
    versionId,
  };
  return resultBytes(effect, worm, absenceOrdinal);
}

export function componentVersion(ordinal: number): string {
  return `4_z-journal-component-${String(ordinal).padStart(2, "0")}`;
}

export function manifestVersion(): string {
  return "4_z-journal-manifest-0001";
}

export function componentResults(
  sealed: SealedActivationComponentSet,
  versionFor: (ordinal: number) => string = componentVersion,
): readonly Uint8Array[] {
  return sealed.effects.map((effect, ordinal) =>
    continuationResultBytes(effect, versionFor(ordinal), 1_000 + ordinal),
  );
}

/** Confirm all components in a caller-selected order and return their exact result bytes. */
export async function confirmComponents(
  fixture: SelectedContinuationFixture,
  order: readonly number[] = reverseOrdinals(fixture.sealed.effects.length),
  versionFor: (ordinal: number) => string = componentVersion,
): Promise<readonly Uint8Array[]> {
  const results = componentResults(fixture.sealed, versionFor);
  for (const ordinal of order) {
    const effect = fixture.sealed.effects[ordinal];
    const bytes = results[ordinal];
    if (effect === undefined || bytes === undefined) throw new Error("component ordinal missing");
    await fixture.store.confirmComponentEffect(
      fixture.prepared.session.sessionId,
      effect.effectId,
      bytes,
    );
  }
  return results;
}

export async function sealManifest(
  fixture: SelectedContinuationFixture,
): Promise<SealedActivationComponentManifest> {
  const outcome = await fixture.store.sealManifestEffect(fixture.prepared.session.sessionId);
  if (outcome.outcome !== "SEALED") throw new Error("manifest effect was not sealed");
  return outcome.sealed;
}

export function manifestResultBytes(
  sealed: SealedActivationComponentManifest,
  versionId = manifestVersion(),
  absenceOrdinal = 2_000,
): Uint8Array {
  return continuationResultBytes(sealed.effect, versionId, absenceOrdinal);
}

export async function confirmManifest(
  fixture: SelectedContinuationFixture,
  sealed: SealedActivationComponentManifest,
  bytes: Uint8Array = manifestResultBytes(sealed),
): Promise<ActivationComponentManifestConfirmation> {
  return fixture.store.confirmManifestEffect(
    fixture.prepared.session.sessionId,
    sealed.effect.effectId,
    bytes,
  );
}

/** Complete the whole continuation through the compact confirmed journal authority. */
export async function confirmedContinuationFixture(
  storage: DurableObjectStorage,
  clock: JournalClock = journalClock(),
): Promise<ConfirmedContinuationFixture> {
  const selected = await selectedContinuationFixture(storage, clock);
  const results = await confirmComponents(selected);
  const manifestSeal = await sealManifest(selected);
  const manifestResult = manifestResultBytes(manifestSeal);
  const confirmation = await confirmManifest(selected, manifestSeal, manifestResult);
  if (confirmation.outcome !== "CONFIRMED") {
    throw new Error("continuation fixture manifest was not confirmed");
  }
  return {
    ...selected,
    authority: confirmation.authority,
    componentResults: results,
    manifestResult,
    manifestSeal,
  };
}

export function restartedStore(
  storage: DurableObjectStorage,
  clock: JournalClock,
): ActivationComponentJournalStore {
  return journalStore(storage, clock);
}

export function reverseOrdinals(length: number): readonly number[] {
  return Array.from({ length }, (_, ordinal) => length - ordinal - 1);
}

export function continuationSelection(storage: DurableObjectStorage): ContinuationSelectionSummary {
  return storage.sql
    .exec<ContinuationSelectionSummary>(
      `SELECT state, hold_code FROM activation_component_selection_v2 WHERE singleton = 1`,
    )
    .one();
}

export function continuationEntry(
  storage: DurableObjectStorage,
  sessionId: string,
  ordinal: number,
): ContinuationEntrySummary {
  return storage.sql
    .exec<ContinuationEntrySummary>(
      `SELECT status, result_bytes, result_sha256
       FROM activation_component_session_entries_v2 WHERE session_id = ? AND ordinal = ?`,
      sessionId,
      ordinal,
    )
    .one();
}

export function continuationManifest(
  storage: DurableObjectStorage,
  sessionId: string,
): ContinuationManifestSummary | undefined {
  return storage.sql
    .exec<ContinuationManifestSummary>(
      `SELECT status, result_bytes, result_sha256, pointer_bytes, pointer_sha256
       FROM activation_component_manifest_authority_v2 WHERE session_id = ?`,
      sessionId,
    )
    .toArray()[0];
}

/** Inject a deterministic abort after an earlier write in the same continuation transaction. */
export function installSelectionAbort(
  storage: DurableObjectStorage,
  triggerName: string,
  targetState: string,
): void {
  if (
    !/^activation_component_test_[a-z_]+$/u.test(triggerName) ||
    !/^[A-Z_]+$/u.test(targetState)
  ) {
    throw new Error("invalid continuation test trigger");
  }
  storage.sql.exec(`
    CREATE TRIGGER ${triggerName}
    BEFORE UPDATE OF state ON activation_component_selection_v2
    WHEN NEW.state = '${targetState}'
    BEGIN
      SELECT RAISE(ABORT, 'TEST_ABORT_CONTINUATION_TRANSITION');
    END;
  `);
}

export function removeTestTrigger(storage: DurableObjectStorage, triggerName: string): void {
  if (!/^activation_component_test_[a-z_]+$/u.test(triggerName)) {
    throw new Error("invalid continuation test trigger");
  }
  storage.sql.exec(`DROP TRIGGER ${triggerName}`);
}
