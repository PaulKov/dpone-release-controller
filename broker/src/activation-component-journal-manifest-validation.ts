import type { ConfirmedActivationComponentManifestObject } from "./activation-component-confirmation";
import type { ActivationComponentJournalAuthority } from "./activation-component-journal-authority";
import type { RebuiltActivationComponentManifestAuthority } from "./activation-component-journal-manifest-authority";
import { snapshotManifestRow } from "./activation-component-journal-manifest-authority";
import type { ActivationComponentJournalManifestRow } from "./activation-component-journal-manifest-schema";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import {
  assertSameJournalEntries,
  assertSameJournalSelection,
  assertSameJournalSession,
  componentJournalError,
  sameJournalBytes,
} from "./activation-component-journal-validation";
import type {
  PreparedActivationComponentManifest,
  PreparedActivationComponentManifestPointer,
} from "./activation-component-contract";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

const EFFECT_ID = /^sha256:[0-9a-f]{64}$/u;

export function sealedManifestRow(
  sessionId: string,
  manifest: PreparedActivationComponentManifest,
  effect: PreparedWormExactObjectEffect,
): ActivationComponentJournalManifestRow {
  return {
    effect_id: effect.effectId,
    manifest_bytes: Uint8Array.from(manifest.canonicalBytes).buffer,
    manifest_id: manifest.manifestId,
    manifest_sha256: manifest.manifestSha256,
    object_key: manifest.key,
    pointer_bytes: null,
    pointer_sha256: null,
    result_bytes: null,
    result_sha256: null,
    session_id: sessionId,
    status: "SEALED",
  };
}

export function assertSameManifestSeal(
  expected: ActivationComponentJournalManifestRow,
  actualInput: ActivationComponentJournalManifestRow,
): void {
  const actual = snapshotManifestRow(actualInput);
  if (
    expected.session_id !== actual.session_id ||
    expected.manifest_id !== actual.manifest_id ||
    expected.manifest_sha256 !== actual.manifest_sha256 ||
    expected.object_key !== actual.object_key ||
    expected.effect_id !== actual.effect_id ||
    !sameJournalBytes(expected.manifest_bytes, actual.manifest_bytes)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_CONFLICT");
  }
}

export function assertExactManifestResultRetry(
  row: ActivationComponentJournalManifestRow,
  resultBytes: Uint8Array,
  resultSha256: string,
): void {
  if (
    row.result_sha256 !== resultSha256 ||
    !sameJournalBytes(row.result_bytes, resultBytes.buffer)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_CONFLICT");
  }
}

export function assertManifestPointerRetry(
  row: ActivationComponentJournalManifestRow,
  pointer: PreparedActivationComponentManifestPointer | null,
  pointerSha256: string | null,
): void {
  if (
    row.pointer_sha256 !== pointerSha256 ||
    !sameJournalBytes(row.pointer_bytes, pointer?.canonicalBytes.buffer ?? null)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_POINTER_CONFLICT");
  }
}

export function manifestConfirmationVersionCollides(
  rebuilt: RebuiltActivationComponentManifestAuthority,
  confirmation: ConfirmedActivationComponentManifestObject,
): boolean {
  return rebuilt.componentConfirmations.some(
    ({ confirmed }) => confirmed.worm.versionId === confirmation.confirmed.worm.versionId,
  );
}

export function fenceManifestJournalAuthority(
  authority: ActivationComponentJournalAuthority,
  queries: ActivationComponentJournalQueries,
): void {
  assertSameJournalSession(authority.row, queries.session(authority.session.sessionId));
  assertSameJournalEntries(authority.entries, queries.entries(authority.session.sessionId));
  assertSameJournalSelection(authority.selection, queries.selection());
}

export function exactJournalEffectIdentity(value: string): string {
  if (typeof value !== "string" || !EFFECT_ID.test(value)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_EFFECT_INVALID");
  }
  return value;
}
