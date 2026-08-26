import { parseCanonicalUntrustedActivationPair } from "./activation-core";
import { PUBLIC_V2_MAX_BYTES, copyPublicV2Bytes } from "./bytes";
import { candidateAssert } from "./error";
import { sha256Tagged } from "./identity";
import { parseCanonicalUntrustedRuntimeClosure } from "./runtime-closure";
import type {
  UntrustedActivatedPublicCore,
  UntrustedProvisionedPublicCore,
  UntrustedRuntimeClosure,
} from "./trust";
import type { DigestSha256 } from "./types";
import {
  buildDeterministicPublicZip,
  parseDeterministicPublicZip,
  type DeterministicPublicArchiveMembers,
} from "./zip-format";

export interface UntrustedPublicArchive {
  readonly activated: UntrustedActivatedPublicCore;
  readonly activatedBytes: Uint8Array;
  readonly archiveBytes: Uint8Array;
  readonly archiveSha256: DigestSha256;
  readonly closure: UntrustedRuntimeClosure;
  readonly closureBytes: Uint8Array;
  readonly provisioned: UntrustedProvisionedPublicCore;
  readonly provisionedBytes: Uint8Array;
}

/**
 * Validate all semantic links before producing the fixed, deterministic ZIP.
 * The result is still untrusted: a ZIP digest is not broker authenticity.
 */
export async function buildUntrustedPublicArchive(
  input: DeterministicPublicArchiveMembers,
): Promise<UntrustedPublicArchive> {
  const members = snapshotMembers(input);
  const parsed = await parseMembers(members);
  const archiveBytes = buildDeterministicPublicZip(members);
  return {
    ...parsed,
    archiveBytes: Uint8Array.from(archiveBytes),
    archiveSha256: await sha256Tagged(archiveBytes),
  };
}

/** Parse exact ZIP bytes and re-run A0/A1/closure semantic cross-binding. */
export async function parseUntrustedPublicArchive(
  input: Uint8Array,
): Promise<UntrustedPublicArchive> {
  const archiveBytes = copyPublicV2Bytes(input, "PUBLIC_V2_ZIP_RAW_SIZE_INVALID");
  const members = parseDeterministicPublicZip(archiveBytes);
  const parsed = await parseMembers(members);
  return {
    ...parsed,
    archiveBytes: Uint8Array.from(archiveBytes),
    archiveSha256: await sha256Tagged(archiveBytes),
  };
}

async function parseMembers(
  input: DeterministicPublicArchiveMembers,
): Promise<Omit<UntrustedPublicArchive, "archiveBytes" | "archiveSha256">> {
  const members = snapshotMembers(input);
  const pair = await parseCanonicalUntrustedActivationPair({
    activated: members.activated,
    provisioned: members.provisioned,
  });
  const closure = await parseCanonicalUntrustedRuntimeClosure({
    activated: members.activated,
    closure: members.closure,
    provisioned: members.provisioned,
  });
  return {
    activated: pair.activated,
    activatedBytes: members.activated,
    closure,
    closureBytes: members.closure,
    provisioned: pair.provisioned,
    provisionedBytes: members.provisioned,
  };
}

function snapshotMembers(
  input: DeterministicPublicArchiveMembers,
): DeterministicPublicArchiveMembers {
  const expanded =
    input.activated.byteLength + input.closure.byteLength + input.provisioned.byteLength;
  candidateAssert(
    Number.isSafeInteger(expanded) && expanded <= PUBLIC_V2_MAX_BYTES,
    "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID",
  );
  return {
    activated: copyPublicV2Bytes(input.activated),
    closure: copyPublicV2Bytes(input.closure),
    provisioned: copyPublicV2Bytes(input.provisioned),
  };
}
