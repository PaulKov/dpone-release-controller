export const ACTIVATION_OPERATION_SCHEMA_V2_TRIGGERS = Object.freeze([
  "activation_operation_intent_identity_immutable_v2",
  "activation_operation_intent_initial_state_v2",
  "activation_operation_issuance_identity_immutable_v2",
  "activation_operation_issuance_initial_state_v2",
  "activation_operation_issuance_roster_complete_v2",
  "activation_operation_slot_delete_forbidden_v2",
  "activation_operation_slot_identity_immutable_v2",
  "activation_operation_slot_profile_insert_v2",
  "activation_operation_slot_work_roster_complete_v2",
]);

/** Install compact-v2 identity and sequence-specific roster guards. */
export function initializeActivationOperationSchemaV2Guards(sql: SqlStorage): void {
  const invalidSlotProfile = `NOT EXISTS (
    SELECT 1
    FROM activation_operation_issuances AS issuance
    JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
    WHERE issuance.issuance_id = NEW.issuance_id
      AND issuance.state = 'RESERVED'
      AND NEW.state = 'PREPARED'
      AND (
        (intent.sequence = 0 AND (
          (NEW.slot_id = 'CONTROLLER_ACTION' AND NEW.slot_kind = 'DIRECT_WORM'
            AND NEW.slot_index = 0)
          OR (NEW.slot_id = 'CONTROLLER_OIDC' AND NEW.slot_kind = 'DIRECT_WORM'
            AND NEW.slot_index = 1)
          OR (NEW.slot_id = 'TARGET_OIDC' AND NEW.slot_kind = 'DIRECT_WORM'
            AND NEW.slot_index = 2)
          OR (NEW.slot_id = 'TARGET_RULESET' AND NEW.slot_kind = 'DIRECT_WORM'
            AND NEW.slot_index = 3)
          OR (NEW.slot_id = 'CLOUDFLARE_BATCH' AND NEW.slot_kind = 'CLOUDFLARE_BATCH'
            AND NEW.slot_index = 4)
        ))
        OR (intent.sequence = 1 AND NEW.slot_id = 'CLOUDFLARE_BATCH'
          AND NEW.slot_kind = 'CLOUDFLARE_BATCH' AND NEW.slot_index = 0)
      )
  )`;
  sql.exec(`
    CREATE TRIGGER activation_operation_intent_identity_immutable_v2
      BEFORE UPDATE OF sequence, attempt_id, intent_sha256, semantic_request_bytes,
        worker_version_id, created_at
      ON activation_operation_intents
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_INTENT_IDENTITY_IMMUTABLE');
      END;
    CREATE TRIGGER activation_operation_intent_initial_state_v2
      BEFORE INSERT ON activation_operation_intents
      WHEN NEW.state != 'OPEN'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_INTENT_INITIAL_STATE_INVALID');
      END;
    CREATE TRIGGER activation_operation_issuance_identity_immutable_v2
      BEFORE UPDATE OF attempt_id, ordinal, issuance_id, internal_request_id,
        issued_at, fresh_until
      ON activation_operation_issuances
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_ISSUANCE_IDENTITY_IMMUTABLE');
      END;
    CREATE TRIGGER activation_operation_issuance_initial_state_v2
      BEFORE INSERT ON activation_operation_issuances
      WHEN NEW.state != 'RESERVED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_ISSUANCE_INITIAL_STATE_INVALID');
      END;
    CREATE TRIGGER activation_operation_issuance_roster_complete_v2
      BEFORE UPDATE OF state ON activation_operation_issuances
      WHEN OLD.state = 'RESERVED' AND NEW.state != 'RESERVED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_ROSTER_INCOMPLETE')
        WHERE NOT EXISTS (
          SELECT 1 FROM activation_operation_intents AS intent
          WHERE intent.attempt_id = OLD.attempt_id
            AND (
              (intent.sequence = 0 AND (
                SELECT COUNT(*) FROM activation_operation_slots AS slot
                WHERE slot.issuance_id = OLD.issuance_id
              ) = 5)
              OR (intent.sequence = 1 AND (
                SELECT COUNT(*) FROM activation_operation_slots AS slot
                WHERE slot.issuance_id = OLD.issuance_id
              ) = 1)
            )
        );
      END;
    CREATE TRIGGER activation_operation_slot_profile_insert_v2
      BEFORE INSERT ON activation_operation_slots
      WHEN ${invalidSlotProfile}
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_SLOT_PROFILE_INVALID');
      END;
    CREATE TRIGGER activation_operation_slot_identity_immutable_v2
      BEFORE UPDATE OF issuance_id, slot_id, slot_kind, slot_index
      ON activation_operation_slots
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_SLOT_IDENTITY_IMMUTABLE');
      END;
    CREATE TRIGGER activation_operation_slot_work_roster_complete_v2
      BEFORE UPDATE OF state ON activation_operation_slots
      WHEN OLD.state = 'PREPARED' AND NEW.state != 'PREPARED'
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_ROSTER_INCOMPLETE')
        WHERE NOT EXISTS (
          SELECT 1 FROM activation_operation_issuances AS issuance
          JOIN activation_operation_intents AS intent ON intent.attempt_id = issuance.attempt_id
          WHERE issuance.issuance_id = OLD.issuance_id
            AND (
              (intent.sequence = 0 AND (
                SELECT COUNT(*) FROM activation_operation_slots AS slot
                WHERE slot.issuance_id = OLD.issuance_id
              ) = 5)
              OR (intent.sequence = 1 AND (
                SELECT COUNT(*) FROM activation_operation_slots AS slot
                WHERE slot.issuance_id = OLD.issuance_id
              ) = 1)
            )
        );
      END;
    CREATE TRIGGER activation_operation_slot_delete_forbidden_v2
      BEFORE DELETE ON activation_operation_slots
      BEGIN
        SELECT RAISE(ABORT, 'ACTIVATION_OPERATION_SLOT_DELETE_FORBIDDEN');
      END;
  `);
}
