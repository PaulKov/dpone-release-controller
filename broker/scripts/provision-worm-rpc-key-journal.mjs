import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { basename, dirname } from "node:path";
import { TextDecoder } from "node:util";

import { ROLE_ORDER, VERSION } from "./provision-worm-rpc-key-constants.mjs";
import { canonicalBytes, taggedSha256 } from "./provision-worm-rpc-key-crypto.mjs";

export function reserveResult(path, recover, afterOpen = undefined) {
  if (path === null) throw new Error("applied authority ceremony requires a HOLD result path");
  const parent = lstatSync(dirname(path));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o022) !== 0) {
    throw new Error("authority ceremony result parent must be a private real directory");
  }
  if (!recover && existsSync(path)) {
    throw new Error("authority ceremony result already exists; use authenticated recovery");
  }
  if (recover && !existsSync(path)) {
    throw new Error("authority ceremony recovery journal does not exist");
  }
  if (recover) {
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o077) !== 0) {
      throw new Error("authority ceremony recovery journal must be an exact mode-0600 file");
    }
  }
  const flags = recover
    ? fsConstants.O_RDWR | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW
    : fsConstants.O_WRONLY |
      fsConstants.O_APPEND |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW;
  const handle = openSync(path, flags, 0o600);
  const stat = fstatSync(handle);
  if (!stat.isFile() || (stat.mode & 0o077) !== 0) {
    closeSync(handle);
    throw new Error("authority ceremony result reservation is not private");
  }
  if (!recover) {
    fsyncParentDirectory(path);
    return {
      entries: [],
      handle,
      nextSequence: 0,
      previousEntrySha256: null,
      terminal: false,
    };
  }
  try {
    if (afterOpen !== undefined) {
      if (typeof afterOpen !== "function") {
        throw new Error("authority ceremony recovery hook is invalid");
      }
      afterOpen({ handle, path });
    }
    const beforeRead = fstatSync(handle);
    const bytes = readFileSync(handle);
    const afterRead = fstatSync(handle);
    const currentPath = lstatSync(path);
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.byteLength !== beforeRead.size ||
      bytes.byteLength === 0 ||
      beforeRead.dev !== afterRead.dev ||
      beforeRead.ino !== afterRead.ino ||
      beforeRead.size !== afterRead.size ||
      beforeRead.mtimeMs !== afterRead.mtimeMs ||
      currentPath.dev !== afterRead.dev ||
      currentPath.ino !== afterRead.ino
    ) {
      throw new Error("authority ceremony recovery journal read is not byte-exact");
    }
    const parsed = parseJournalPrefix(bytes);
    if (parsed.completeBytes < bytes.byteLength) {
      ftruncateSync(handle, parsed.completeBytes);
      fsyncSync(handle);
    }
    return {
      entries: parsed.entries,
      handle,
      nextSequence: parsed.entries.length,
      previousEntrySha256: taggedSha256(canonicalBytes(parsed.entries.at(-1))),
      terminal: parsed.terminal,
    };
  } catch (error) {
    closeSync(handle);
    throw error;
  }
}

function parseJournalPrefix(bytes) {
  const lastNewline = bytes.lastIndexOf(0x0a);
  if (lastNewline === -1) {
    throw new Error("authority ceremony recovery journal has no complete entry");
  }
  const complete = bytes.subarray(0, lastNewline + 1);
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(complete);
  } catch {
    throw new Error("authority ceremony recovery journal is not canonical UTF-8 JSONL");
  }
  const lines = source.slice(0, -1).split("\n");
  const entries = [];
  let terminal = false;
  for (let index = 0; index < lines.length; index += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[index]);
    } catch {
      throw new Error("authority ceremony recovery journal contains malformed JSON");
    }
    if (
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      `${JSON.stringify(entry)}\n` !== `${lines[index]}\n` ||
      entry.journal_sequence !== index ||
      entry.previous_entry_sha256 !==
        (index === 0 ? null : taggedSha256(canonicalBytes(entries[index - 1]))) ||
      entry.schema !== "dpone.release-authority-version-ceremony.v1" ||
      entry.schema_version !== 1 ||
      entry.applied !== true ||
      !["HOLD", "READY_FOR_PRIVATE_PREFLIGHT"].includes(entry.status)
    ) {
      throw new Error("authority ceremony recovery journal chain is invalid");
    }
    if (entry.status === "READY_FOR_PRIVATE_PREFLIGHT") {
      if (terminal || index !== lines.length - 1) {
        throw new Error("authority ceremony recovery journal terminal state is invalid");
      }
      terminal = true;
    } else if (terminal) {
      throw new Error("authority ceremony recovery journal terminal state is invalid");
    }
    entries.push(entry);
  }
  return { completeBytes: complete.byteLength, entries, terminal };
}

export function restoreRecoveredState(
  entries,
  options,
  state,
  fingerprint,
  observerRpcFingerprint,
  evidenceRpcFingerprint,
  principalDigests,
  restrictions,
  bootstrapProvenance,
) {
  const roles = ROLE_ORDER;
  let priorCompleted = [];
  let priorVersionIds = {
    cloudflareObserver: null,
    ingress: null,
    observer: null,
    worm: null,
  };
  for (const entry of entries) {
    const completed = entry.completed_uploads;
    const versionIds = {
      cloudflareObserver: entry.cloudflare_observer_version_id,
      ingress: entry.ingress_version_id,
      observer: entry.observer_version_id,
      worm: entry.worm_version_id,
    };
    if (
      entry.rpc_key_fingerprint !== fingerprint ||
      entry.cloudflare_observer_rpc_key_fingerprint !== observerRpcFingerprint ||
      entry.cloudflare_evidence_rpc_key_fingerprint !== evidenceRpcFingerprint ||
      JSON.stringify(entry.admin_access_principal_digests) !== JSON.stringify(principalDigests) ||
      JSON.stringify(entry.credential_restrictions) !== JSON.stringify(restrictions) ||
      JSON.stringify(entry.bootstrap_provenance) !== JSON.stringify(bootstrapProvenance) ||
      entry.version_tag !== options.versionTag ||
      entry.version_message !== options.versionMessage ||
      entry.ingress_config !== basename(options.ingressConfig) ||
      entry.observer_config !== basename(options.observerConfig) ||
      entry.cloudflare_observer_config !== basename(options.cloudflareObserverConfig) ||
      entry.worm_config !== basename(options.wormConfig) ||
      entry.ingress_upload_mode !== "final-code-version-upload" ||
      entry.runtime_format !== "base64url-256-bit" ||
      entry.private_provider_preflight_required !== true ||
      typeof entry.recovery_mode !== "boolean" ||
      !Array.isArray(completed) ||
      JSON.stringify(completed) !== JSON.stringify(roles.slice(0, completed.length)) ||
      completed.length < priorCompleted.length ||
      completed.length > priorCompleted.length + 1 ||
      !Array.isArray(entry.initial_absence_observations) ||
      !Array.isArray(entry.provider_version_observations) ||
      !Array.isArray(entry.recovery_observations)
    ) {
      throw new Error("authority ceremony recovery identity/state mismatch");
    }
    validateRecoveredObservations(entry, completed, versionIds);
    for (let index = 0; index < roles.length; index += 1) {
      const role = roles[index];
      const value = versionIds[role];
      if (index < completed.length !== (typeof value === "string" && VERSION.test(value))) {
        throw new Error("authority ceremony recovery version state mismatch");
      }
      if (priorVersionIds[role] !== null && value !== priorVersionIds[role]) {
        throw new Error("authority ceremony recovery changed an immutable version ID");
      }
    }
    priorCompleted = [...completed];
    priorVersionIds = versionIds;
  }
  const last = entries.at(-1);
  state.completed_uploads = [...last.completed_uploads];
  state.initial_absence_observations = [...last.initial_absence_observations];
  state.provider_version_observations = [...last.provider_version_observations];
  state.recovery_observations = [...last.recovery_observations];
  state.version_ids = priorVersionIds;
}

function validateRecoveredObservations(entry, completed, versionIds) {
  const absence = entry.initial_absence_observations;
  if (absence.length < completed.length || absence.length > completed.length + 1) {
    throw new Error("authority ceremony recovery absence proof is incomplete");
  }
  for (let index = 0; index < absence.length; index += 1) {
    if (
      absence[index]?.role !== ROLE_ORDER[index] ||
      absence[index]?.outcome !== "ABSENT" ||
      JSON.stringify(absence[index]?.matching_version_ids) !== "[]" ||
      JSON.stringify(absence[index]?.predecessor_completed_uploads) !==
        JSON.stringify(ROLE_ORDER.slice(0, index)) ||
      typeof absence[index]?.raw_provider_response_sha256 !== "string"
    ) {
      throw new Error("authority ceremony recovery absence proof is invalid");
    }
  }
  if (entry.provider_version_observations.length > completed.length) {
    throw new Error("authority ceremony recovery provider observation is ahead of state");
  }
  for (let index = 0; index < entry.provider_version_observations.length; index += 1) {
    const observation = entry.provider_version_observations[index];
    const role = ROLE_ORDER[index];
    if (observation?.role !== role || observation?.version_id !== versionIds[role]) {
      throw new Error("authority ceremony recovery provider observation mismatch");
    }
  }
  const recoveredRoles = new Set();
  for (const observation of entry.recovery_observations) {
    const role = observation?.version_observation?.role;
    if (
      observation?.outcome !== "RECOVERED_EXACT_EFFECT" ||
      !ROLE_ORDER.includes(role) ||
      recoveredRoles.has(role) ||
      observation.version_observation.version_id !== versionIds[role]
    ) {
      throw new Error("authority ceremony recovery effect observation mismatch");
    }
    recoveredRoles.add(role);
  }
}

function fsyncParentDirectory(path) {
  const handle = openSync(dirname(path), fsConstants.O_RDONLY);
  try {
    fsyncSync(handle);
  } finally {
    closeSync(handle);
  }
}

/** Append one fsynced canonical journal entry without damaging prior entries. */
export function appendJournalEntry(handle, value, dependencies = {}) {
  const write = dependencies.writeSync ?? writeSync;
  const sync = dependencies.fsyncSync ?? fsyncSync;
  const bytes = canonicalBytes(value);
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = write(handle, bytes, offset, bytes.byteLength - offset, null);
    if (!Number.isSafeInteger(written) || written <= 0 || written > bytes.byteLength - offset) {
      throw new Error("authority ceremony journal write was incomplete");
    }
    offset += written;
  }
  sync(handle);
  return taggedSha256(bytes);
}
