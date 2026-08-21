import { sha256Hex, timingSafeEqual } from "./canonical";
import {
  confirmActivationComponentManifestObject,
  prepareActivationComponentManifestEffect,
  type ConfirmedActivationComponentEnvelopeObject,
  type ConfirmedActivationComponentManifestObject,
} from "./activation-component-confirmation";
import type { HeldActivationComponentJournalAuthority } from "./activation-component-journal-contract";
import type {
  ActivationComponentJournalAuthority,
  ActivationComponentJournalAuthorityReader,
} from "./activation-component-journal-authority";
import {
  confirmedJournalComponentObjects,
  selectedJournalPins,
} from "./activation-component-journal-confirmation";
import type { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import type { ActivationComponentJournalManifestRow } from "./activation-component-journal-manifest-schema";
import {
  assertSameJournalEntries,
  assertSameJournalSelection,
  assertSameJournalSession,
  componentJournalError,
  sameJournalBytes,
  snapshotJournalEffect,
} from "./activation-component-journal-validation";
import {
  buildActivationComponentManifest,
  buildActivationComponentManifestPointer,
  parseActivationComponentManifestPointer,
} from "./activation-component-manifest";
import type {
  PreparedActivationComponentManifest,
  PreparedActivationComponentManifestPointer,
} from "./activation-component-contract";
import type { PreparedWormExactObjectEffect } from "./worm-exact-object-effect-contract";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;

export interface RebuiltActivationComponentManifestAuthority {
  readonly authority: ActivationComponentJournalAuthority;
  readonly componentConfirmations: readonly ConfirmedActivationComponentEnvelopeObject[];
  readonly effect: PreparedWormExactObjectEffect;
  readonly manifest: PreparedActivationComponentManifest;
  readonly manifestConfirmation: ConfirmedActivationComponentManifestObject | null;
  readonly pointer: PreparedActivationComponentManifestPointer | null;
  readonly row: ActivationComponentJournalManifestRow;
}

/** Read, rebuild, and fence every component/manifest authority from SQLite. */
export async function readActivationComponentManifestAuthority(
  reader: ActivationComponentJournalAuthorityReader,
  queries: ActivationComponentJournalQueries,
  sessionId: string,
): Promise<RebuiltActivationComponentManifestAuthority> {
  const authority = await reader.load(sessionId);
  const componentConfirmations = await confirmedJournalComponentObjects(authority);
  const row = snapshotManifestRow(requireManifest(queries.manifest(sessionId)));
  const manifest = await buildActivationComponentManifest(
    authority.descriptor.canonicalBytes,
    componentConfirmations,
  );
  assertManifestRow(row, manifest);
  const effect = await prepareActivationComponentManifestEffect(
    manifest.canonicalBytes,
    selectedJournalPins(authority),
  );
  if (row.effect_id !== effect.effectId) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_EFFECT_CONFLICT", 500);
  }
  const result = await readManifestResult(row, effect, manifest, componentConfirmations);
  assertManifestSelection(authority, row.status, result.versionCollision);
  refence(authority, row, queries);
  return Object.freeze({
    authority,
    componentConfirmations,
    effect: snapshotJournalEffect(effect),
    manifest,
    manifestConfirmation: result.confirmation,
    pointer: result.pointer,
    row,
  });
}

/** Validate and return either exact terminal HOLD shape without trusting its scalar code. */
export async function heldActivationComponentJournalAuthority(
  reader: ActivationComponentJournalAuthorityReader,
  queries: ActivationComponentJournalQueries,
  sessionId: string,
): Promise<HeldActivationComponentJournalAuthority> {
  const authority = await reader.load(sessionId);
  if (authority.selection.state !== "HOLD" || authority.selection.hold_code === null) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_NOT_HELD");
  }
  const confirmations = await confirmedJournalComponentObjects(authority);
  const componentCollision = hasDuplicateVersions(confirmations);
  if (authority.selection.hold_code === "ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT") {
    if (!componentCollision || queries.manifest(sessionId) !== undefined) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_HOLD_INVALID", 500);
    }
  } else if (authority.selection.hold_code === "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT") {
    const manifest = await readActivationComponentManifestAuthority(reader, queries, sessionId);
    if (manifest.row.status !== "RESULT_CONFIRMED" || !manifestVersionCollision(manifest)) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_HOLD_INVALID", 500);
    }
  } else {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_HOLD_INVALID", 500);
  }
  refenceSession(authority, queries);
  return Object.freeze({
    holdCode: authority.selection.hold_code,
    session: authority.session,
  });
}

export function hasDuplicateVersions(
  confirmations: readonly ConfirmedActivationComponentEnvelopeObject[],
): boolean {
  const versions = confirmations.map(({ confirmed }) => confirmed.worm.versionId);
  return new Set(versions).size !== versions.length;
}

export function manifestVersionCollision(
  rebuilt: RebuiltActivationComponentManifestAuthority,
): boolean {
  const version = rebuilt.manifestConfirmation?.confirmed.worm.versionId;
  return (
    version !== undefined &&
    rebuilt.componentConfirmations.some(({ confirmed }) => confirmed.worm.versionId === version)
  );
}

export function snapshotManifestRow(
  row: ActivationComponentJournalManifestRow,
): ActivationComponentJournalManifestRow {
  return {
    ...row,
    manifest_bytes: copyBuffer(row.manifest_bytes),
    pointer_bytes: row.pointer_bytes === null ? null : copyBuffer(row.pointer_bytes),
    result_bytes: row.result_bytes === null ? null : copyBuffer(row.result_bytes),
  };
}

export function assertSameManifestRow(
  expected: ActivationComponentJournalManifestRow,
  actual: ActivationComponentJournalManifestRow | undefined,
): void {
  if (actual === undefined) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
  if (
    expected.session_id !== actual.session_id ||
    expected.manifest_id !== actual.manifest_id ||
    expected.manifest_sha256 !== actual.manifest_sha256 ||
    expected.object_key !== actual.object_key ||
    expected.effect_id !== actual.effect_id ||
    expected.result_sha256 !== actual.result_sha256 ||
    expected.pointer_sha256 !== actual.pointer_sha256 ||
    expected.status !== actual.status ||
    !sameJournalBytes(expected.manifest_bytes, actual.manifest_bytes) ||
    !sameJournalBytes(expected.result_bytes, actual.result_bytes) ||
    !sameJournalBytes(expected.pointer_bytes, actual.pointer_bytes)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_FENCE_CONFLICT");
  }
}

function assertManifestRow(
  row: ActivationComponentJournalManifestRow,
  manifest: PreparedActivationComponentManifest,
): void {
  if (
    !DIGEST.test(row.session_id) ||
    row.manifest_id !== manifest.manifestId ||
    row.manifest_sha256 !== manifest.manifestSha256 ||
    row.object_key !== manifest.key ||
    !sameJournalBytes(row.manifest_bytes, manifest.canonicalBytes.buffer)
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_CONFLICT", 500);
  }
}

async function readManifestResult(
  row: ActivationComponentJournalManifestRow,
  effect: PreparedWormExactObjectEffect,
  manifest: PreparedActivationComponentManifest,
  components: readonly ConfirmedActivationComponentEnvelopeObject[],
): Promise<{
  readonly confirmation: ConfirmedActivationComponentManifestObject | null;
  readonly pointer: PreparedActivationComponentManifestPointer | null;
  readonly versionCollision: boolean;
}> {
  if (row.status === "SEALED") {
    if (
      row.result_bytes !== null ||
      row.result_sha256 !== null ||
      row.pointer_bytes !== null ||
      row.pointer_sha256 !== null
    ) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_INVALID", 500);
    }
    return { confirmation: null, pointer: null, versionCollision: false };
  }
  if (row.result_bytes === null || row.result_sha256 === null) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_INVALID", 500);
  }
  const resultBytes = new Uint8Array(row.result_bytes);
  const resultSha256 = `sha256:${await sha256Hex(resultBytes)}`;
  if (!timingSafeEqual(resultSha256, row.result_sha256)) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_CONFLICT", 500);
  }
  const confirmation = await confirmActivationComponentManifestObject(effect, resultBytes);
  const versionCollision = components.some(
    ({ confirmed }) => confirmed.worm.versionId === confirmation.confirmed.worm.versionId,
  );
  if (row.status === "RESULT_CONFIRMED") {
    if (!versionCollision || row.pointer_bytes !== null || row.pointer_sha256 !== null) {
      throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_INVALID", 500);
    }
    return { confirmation, pointer: null, versionCollision };
  }
  if (versionCollision) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_RESULT_INVALID", 500);
  }
  const pointer = await buildActivationComponentManifestPointer(confirmation);
  await assertStoredPointer(row, pointer, manifest, confirmation);
  return { confirmation, pointer, versionCollision };
}

async function assertStoredPointer(
  row: ActivationComponentJournalManifestRow,
  rebuilt: PreparedActivationComponentManifestPointer,
  manifest: PreparedActivationComponentManifest,
  confirmation: ConfirmedActivationComponentManifestObject,
): Promise<void> {
  if (row.pointer_bytes === null || row.pointer_sha256 === null) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_POINTER_INVALID", 500);
  }
  const storedBytes = new Uint8Array(row.pointer_bytes);
  const digest = `sha256:${await sha256Hex(storedBytes)}`;
  const parsed = parseActivationComponentManifestPointer(storedBytes);
  if (
    !timingSafeEqual(digest, row.pointer_sha256) ||
    !sameJournalBytes(storedBytes.buffer, rebuilt.canonicalBytes.buffer) ||
    parsed.manifestId !== manifest.manifestId ||
    parsed.manifestSha256 !== manifest.manifestSha256 ||
    parsed.setId !== manifest.setId ||
    parsed.workerVersionId !== manifest.workerVersionId ||
    parsed.worm.digest !== confirmation.confirmed.worm.digest ||
    parsed.worm.key !== confirmation.confirmed.worm.key ||
    parsed.worm.retentionUntil !== confirmation.confirmed.worm.retentionUntil ||
    parsed.worm.versionId !== confirmation.confirmed.worm.versionId
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_POINTER_CONFLICT", 500);
  }
}

function assertManifestSelection(
  authority: ActivationComponentJournalAuthority,
  status: ActivationComponentJournalManifestRow["status"],
  versionCollision: boolean,
): void {
  const expected =
    status === "SEALED" ? "MANIFEST_EFFECT_SEALED" : status === "CONFIRMED" ? "CONFIRMED" : "HOLD";
  if (
    authority.selection.state !== expected ||
    (status === "RESULT_CONFIRMED" &&
      (!versionCollision ||
        authority.selection.hold_code !== "ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT"))
  ) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_STATE_INVALID", 500);
  }
}

function refence(
  authority: ActivationComponentJournalAuthority,
  row: ActivationComponentJournalManifestRow,
  queries: ActivationComponentJournalQueries,
): void {
  refenceSession(authority, queries);
  assertSameManifestRow(row, queries.manifest(authority.session.sessionId));
}

function refenceSession(
  authority: ActivationComponentJournalAuthority,
  queries: ActivationComponentJournalQueries,
): void {
  assertSameJournalSession(authority.row, queries.session(authority.session.sessionId));
  assertSameJournalEntries(authority.entries, queries.entries(authority.session.sessionId));
  assertSameJournalSelection(authority.selection, queries.selection());
}

function requireManifest(
  row: ActivationComponentJournalManifestRow | undefined,
): ActivationComponentJournalManifestRow {
  if (row === undefined) {
    throw componentJournalError("ACTIVATION_COMPONENT_JOURNAL_MANIFEST_MISSING");
  }
  return row;
}

function copyBuffer(input: ArrayBuffer): ArrayBuffer {
  return Uint8Array.from(new Uint8Array(input)).buffer;
}
