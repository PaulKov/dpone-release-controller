import { ACTIVATION_COMPONENT_KINDS } from "./activation-component-contract";

export const ACTIVATION_COMPONENT_MANIFEST_AUTHORITY_TABLE =
  "activation_component_manifest_authority_v2";

export const ACTIVATION_COMPONENT_CONTINUATION_TRIGGERS = Object.freeze([
  "activation_component_entry_confirm_transition_v2",
  "activation_component_entry_confirmed_immutable_v2",
  "activation_component_effects_sealed_transition_v2",
  "activation_component_components_confirmed_transition_v2",
  "activation_component_manifest_insert_v2",
  "activation_component_manifest_immutable_v2",
  "activation_component_manifest_confirm_transition_v2",
  "activation_component_manifest_sealed_transition_v2",
  "activation_component_confirmed_transition_v2",
  "activation_component_hold_transition_v2",
  "activation_component_selection_authority_immutable_v2",
  "activation_component_selection_terminal_immutable_v2",
  "activation_component_selection_no_reopen_v2",
  "activation_component_selected_entry_no_delete_v2",
  "activation_component_manifest_no_delete_v2",
  "activation_component_selection_no_delete_v2",
  "activation_component_selected_session_no_delete_v2",
]);

export interface ActivationComponentJournalManifestRow extends Record<string, SqlStorageValue> {
  readonly effect_id: string;
  readonly manifest_bytes: ArrayBuffer;
  readonly manifest_id: string;
  readonly manifest_sha256: string;
  readonly object_key: string;
  readonly pointer_bytes: ArrayBuffer | null;
  readonly pointer_sha256: string | null;
  readonly result_bytes: ArrayBuffer | null;
  readonly result_sha256: string | null;
  readonly session_id: string;
  readonly status: "CONFIRMED" | "RESULT_CONFIRMED" | "SEALED";
}

/** Closed SQL authority and cross-table transition guards for the continuation phase. */
export function activationComponentManifestAuthoritySchemaSql(): string {
  return `
    CREATE TABLE IF NOT EXISTS activation_component_manifest_authority_v2 (
      session_id TEXT PRIMARY KEY CHECK(length(session_id) = 71),
      manifest_id TEXT NOT NULL UNIQUE CHECK(length(manifest_id) = 71),
      manifest_sha256 TEXT NOT NULL UNIQUE CHECK(length(manifest_sha256) = 71),
      manifest_bytes BLOB NOT NULL CHECK(length(manifest_bytes) BETWEEN 1 AND 65536),
      object_key TEXT NOT NULL UNIQUE CHECK(length(object_key) BETWEEN 1 AND 512),
      effect_id TEXT NOT NULL UNIQUE CHECK(length(effect_id) = 71),
      result_bytes BLOB CHECK(length(result_bytes) BETWEEN 1 AND 65536),
      result_sha256 TEXT CHECK(length(result_sha256) = 71),
      pointer_bytes BLOB CHECK(length(pointer_bytes) BETWEEN 1 AND 65536),
      pointer_sha256 TEXT CHECK(length(pointer_sha256) = 71),
      status TEXT NOT NULL CHECK(status IN ('SEALED', 'RESULT_CONFIRMED', 'CONFIRMED')),
      FOREIGN KEY(session_id) REFERENCES activation_component_sessions_v2(session_id),
      CHECK(
        (status = 'SEALED' AND result_bytes IS NULL AND result_sha256 IS NULL
          AND pointer_bytes IS NULL AND pointer_sha256 IS NULL)
        OR
        (status = 'RESULT_CONFIRMED' AND result_bytes IS NOT NULL
          AND result_sha256 IS NOT NULL AND pointer_bytes IS NULL AND pointer_sha256 IS NULL)
        OR
        (status = 'CONFIRMED' AND result_bytes IS NOT NULL AND result_sha256 IS NOT NULL
          AND pointer_bytes IS NOT NULL AND pointer_sha256 IS NOT NULL)
      )
    ) STRICT;

    CREATE TRIGGER IF NOT EXISTS activation_component_entry_confirm_transition_v2
      BEFORE UPDATE OF status ON activation_component_session_entries_v2
      WHEN NEW.status = 'CONFIRMED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_CONFIRM_TRANSITION_INVALID')
        WHERE OLD.status != 'SEALED'
          OR NOT EXISTS (
            SELECT 1 FROM activation_component_selection_v2
            WHERE singleton = 1 AND state = 'COMPONENT_EFFECTS_SEALED'
              AND selected_session_id = NEW.session_id
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_entry_confirmed_immutable_v2
      BEFORE UPDATE ON activation_component_session_entries_v2
      WHEN OLD.status = 'CONFIRMED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_CONFIRMED_IMMUTABLE');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_effects_sealed_transition_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'COMPONENT_EFFECTS_SEALED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_EFFECTS_SEAL_INVALID')
        WHERE OLD.state != 'OPEN';
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_components_confirmed_transition_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'COMPONENTS_CONFIRMED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENTS_CONFIRMED_TRANSITION_INVALID')
        WHERE OLD.state != 'COMPONENT_EFFECTS_SEALED'
          OR NEW.selected_session_id IS NOT OLD.selected_session_id
          OR (SELECT COUNT(*) FROM activation_component_session_entries_v2
              WHERE session_id = NEW.selected_session_id AND status = 'CONFIRMED')
              != ${ACTIVATION_COMPONENT_KINDS.length};
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_manifest_insert_v2
      BEFORE INSERT ON activation_component_manifest_authority_v2
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_MANIFEST_INSERT_INVALID')
        WHERE NEW.status != 'SEALED'
          OR NOT EXISTS (
            SELECT 1 FROM activation_component_selection_v2
            WHERE singleton = 1 AND state = 'COMPONENTS_CONFIRMED'
              AND selected_session_id = NEW.session_id
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_manifest_immutable_v2
      BEFORE UPDATE ON activation_component_manifest_authority_v2
      WHEN OLD.status IN ('RESULT_CONFIRMED', 'CONFIRMED')
        OR NEW.session_id IS NOT OLD.session_id
        OR NEW.manifest_id IS NOT OLD.manifest_id
        OR NEW.manifest_sha256 IS NOT OLD.manifest_sha256
        OR NEW.manifest_bytes IS NOT OLD.manifest_bytes
        OR NEW.object_key IS NOT OLD.object_key
        OR NEW.effect_id IS NOT OLD.effect_id
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_MANIFEST_IMMUTABLE');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_manifest_confirm_transition_v2
      BEFORE UPDATE OF status ON activation_component_manifest_authority_v2
      WHEN NEW.status IN ('RESULT_CONFIRMED', 'CONFIRMED')
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_MANIFEST_CONFIRM_INVALID')
        WHERE OLD.status != 'SEALED'
          OR NOT EXISTS (
            SELECT 1 FROM activation_component_selection_v2
            WHERE singleton = 1 AND state = 'MANIFEST_EFFECT_SEALED'
              AND selected_session_id = NEW.session_id
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_manifest_sealed_transition_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'MANIFEST_EFFECT_SEALED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_MANIFEST_SEAL_INVALID')
        WHERE OLD.state != 'COMPONENTS_CONFIRMED'
          OR NEW.selected_session_id IS NOT OLD.selected_session_id
          OR NOT EXISTS (
            SELECT 1 FROM activation_component_manifest_authority_v2
            WHERE session_id = NEW.selected_session_id AND status = 'SEALED'
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_confirmed_transition_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'CONFIRMED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_CONFIRMED_TRANSITION_INVALID')
        WHERE OLD.state != 'MANIFEST_EFFECT_SEALED'
          OR NEW.selected_session_id IS NOT OLD.selected_session_id
          OR NOT EXISTS (
            SELECT 1 FROM activation_component_manifest_authority_v2
            WHERE session_id = NEW.selected_session_id AND status = 'CONFIRMED'
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_hold_transition_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'HOLD'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_HOLD_TRANSITION_INVALID')
        WHERE NEW.selected_session_id IS NOT OLD.selected_session_id
          OR NOT (
            (OLD.state = 'COMPONENTS_CONFIRMED'
              AND NEW.hold_code IS 'ACTIVATION_COMPONENT_WORM_VERSION_CONFLICT'
              AND NOT EXISTS (
                SELECT 1 FROM activation_component_manifest_authority_v2
                WHERE session_id = NEW.selected_session_id
              ))
            OR
            (OLD.state = 'MANIFEST_EFFECT_SEALED'
              AND NEW.hold_code IS 'ACTIVATION_COMPONENT_MANIFEST_VERSION_CONFLICT'
              AND EXISTS (
                SELECT 1 FROM activation_component_manifest_authority_v2
                WHERE session_id = NEW.selected_session_id AND status = 'RESULT_CONFIRMED'
              ))
          );
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selection_authority_immutable_v2
      BEFORE UPDATE ON activation_component_selection_v2
      WHEN OLD.state != 'OPEN' AND (
        NEW.selected_session_id IS NOT OLD.selected_session_id
        OR NEW.worm_service_identity IS NOT OLD.worm_service_identity
        OR NEW.worm_version_id IS NOT OLD.worm_version_id
        OR NEW.observer_service_identity IS NOT OLD.observer_service_identity
        OR NEW.observer_version_id IS NOT OLD.observer_version_id
      )
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTION_AUTHORITY_IMMUTABLE');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selection_terminal_immutable_v2
      BEFORE UPDATE ON activation_component_selection_v2
      WHEN OLD.state IN ('CONFIRMED', 'HOLD')
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTION_TERMINAL_IMMUTABLE');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selection_no_reopen_v2
      BEFORE UPDATE OF state ON activation_component_selection_v2
      WHEN NEW.state = 'OPEN'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTION_REOPEN_INVALID');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selected_entry_no_delete_v2
      BEFORE DELETE ON activation_component_session_entries_v2
      WHEN EXISTS (
        SELECT 1 FROM activation_component_selection_v2
        WHERE singleton = 1 AND state != 'OPEN' AND selected_session_id = OLD.session_id
      )
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTED_ENTRY_DELETE_INVALID');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_manifest_no_delete_v2
      BEFORE DELETE ON activation_component_manifest_authority_v2
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_MANIFEST_DELETE_INVALID');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selection_no_delete_v2
      BEFORE DELETE ON activation_component_selection_v2
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTION_DELETE_INVALID');
      END;

    CREATE TRIGGER IF NOT EXISTS activation_component_selected_session_no_delete_v2
      BEFORE DELETE ON activation_component_sessions_v2
      WHEN OLD.state = 'SELECTED' OR EXISTS (
        SELECT 1 FROM activation_component_selection_v2
        WHERE singleton = 1 AND selected_session_id = OLD.session_id
      )
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_COMPONENT_SELECTED_SESSION_DELETE_INVALID');
      END;
  `;
}
