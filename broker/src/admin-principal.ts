import { canonicalBytes, sha256Hex } from "./canonical";
import { assert } from "./errors";
import type { ActivationAdminSemanticTrust, JsonObject } from "./types";
import { requireString } from "./validation";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;

export const ADMIN_PRINCIPAL_DIGEST_SCHEMA =
  "dpone.release-broker-admin-access-principal-digest.v1";

export type AdminPrincipalField = "access_group" | "access_identity" | "access_subject_id";

/**
 * Derive the pseudonymous field-domain commitment stored in the canonical A0
 * envelope. Plain Access principals remain runtime secrets and never cross
 * the activation/WORM boundary. These unsalted hashes are intentionally not
 * described as irreversible: low-entropy groups, emails and subject IDs can
 * be dictionary-guessed by a party that obtains the private A0 record.
 */
export async function adminPrincipalDigest(
  field: AdminPrincipalField,
  value: string,
): Promise<string> {
  const document = {
    field,
    schema: ADMIN_PRINCIPAL_DIGEST_SCHEMA,
    schema_version: 1,
    value,
  };
  return `sha256:${await sha256Hex(canonicalBytes(document))}`;
}

/** Recompute all three runtime-secret commitments before any provider effect. */
export async function assertAdminPrincipalDigests(
  access: JsonObject,
  config: ActivationAdminSemanticTrust,
): Promise<void> {
  const expected = {
    access_group_sha256: await adminPrincipalDigest("access_group", config.adminAccessGroup),
    access_identity_sha256: await adminPrincipalDigest(
      "access_identity",
      config.adminAccessIdentity,
    ),
    access_subject_id_sha256: await adminPrincipalDigest(
      "access_subject_id",
      config.adminAccessSubjectId,
    ),
  };
  for (const [key, value] of Object.entries(expected)) {
    assert(
      requireString(access, key, 71, DIGEST) === value,
      "ACTIVATION_ADMIN_PRINCIPAL_DIGEST_MISMATCH",
      409,
    );
  }
}
