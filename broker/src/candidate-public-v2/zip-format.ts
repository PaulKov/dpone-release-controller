import { PUBLIC_V2_MAX_BYTES } from "./canonical";
import { candidateAssert } from "./error";

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const EOCD_SIGNATURE = 0x06054b50;
const VERSION_NEEDED = 20;
const VERSION_MADE_BY = 0x0314;
const DOS_TIME = 0x0000;
const DOS_DATE = 0x0021;
const EXTERNAL_ATTRIBUTES = 0x81a40000;
const LOCAL_HEADER_BYTES = 30;
const CENTRAL_HEADER_BYTES = 46;
const EOCD_BYTES = 22;

export const PUBLIC_ARCHIVE_MEMBER_NAMES = Object.freeze({
  activated: "activation-a1-public-core-v2.json",
  closure: "runtime-closure-public-v2.json",
  provisioned: "activation-a0-public-core-v2.json",
} as const);

export interface DeterministicPublicArchiveMembers {
  readonly activated: Uint8Array;
  readonly closure: Uint8Array;
  readonly provisioned: Uint8Array;
}

interface DeterministicZipMember {
  readonly bytes: Uint8Array;
  readonly name: string;
}

interface MemberMetadata extends DeterministicZipMember {
  readonly crc32: number;
  readonly localOffset: number;
  readonly nameBytes: Uint8Array;
}

interface ParsedMemberMetadata {
  readonly crc32: number;
  readonly localOffset: number;
  readonly name: string;
  readonly nameBytes: Uint8Array;
  readonly size: number;
}

/** Build the exact STORE-only, three-member candidate public archive. */
export function buildDeterministicPublicZip(input: DeterministicPublicArchiveMembers): Uint8Array {
  const members = snapshotMembers(input);
  const expanded = members.reduce((total, member) => total + member.bytes.length, 0);
  candidateAssert(expanded <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID");
  let localBytes = 0;
  const metadata = members.map<MemberMetadata>((member) => {
    const nameBytes = encodeName(member.name);
    const result = {
      ...member,
      crc32: crc32(member.bytes),
      localOffset: localBytes,
      nameBytes,
    };
    localBytes += LOCAL_HEADER_BYTES + nameBytes.length + member.bytes.length;
    return result;
  });
  const centralBytes = metadata.reduce(
    (total, member) => total + CENTRAL_HEADER_BYTES + member.nameBytes.length,
    0,
  );
  const totalBytes = localBytes + centralBytes + EOCD_BYTES;
  candidateAssert(totalBytes <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_ZIP_RAW_SIZE_INVALID");
  const output = new Uint8Array(totalBytes);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const member of metadata) offset = writeLocal(output, view, offset, member);
  candidateAssert(offset === localBytes, "PUBLIC_V2_ZIP_OFFSET_INVALID");
  for (const member of metadata) offset = writeCentral(output, view, offset, member);
  candidateAssert(offset === localBytes + centralBytes, "PUBLIC_V2_ZIP_OFFSET_INVALID");
  writeEocd(view, offset, members.length, centralBytes, localBytes);
  return output;
}

/** Parse and enforce every local, central and EOCD field before returning bytes. */
export function parseDeterministicPublicZip(input: Uint8Array): DeterministicPublicArchiveMembers {
  candidateAssert(
    input.byteLength >= EOCD_BYTES && input.byteLength <= PUBLIC_V2_MAX_BYTES,
    "PUBLIC_V2_ZIP_RAW_SIZE_INVALID",
  );
  const bytes = Uint8Array.from(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocdOffset = bytes.length - EOCD_BYTES;
  requireU32(view, eocdOffset, EOCD_SIGNATURE, "PUBLIC_V2_ZIP_EOCD_INVALID");
  requireU16(view, eocdOffset + 4, 0, "PUBLIC_V2_ZIP_EOCD_INVALID");
  requireU16(view, eocdOffset + 6, 0, "PUBLIC_V2_ZIP_EOCD_INVALID");
  requireU16(view, eocdOffset + 8, 3, "PUBLIC_V2_ZIP_MEMBER_COUNT_INVALID");
  requireU16(view, eocdOffset + 10, 3, "PUBLIC_V2_ZIP_MEMBER_COUNT_INVALID");
  const centralSize = view.getUint32(eocdOffset + 12, true);
  const centralOffset = view.getUint32(eocdOffset + 16, true);
  requireU16(view, eocdOffset + 20, 0, "PUBLIC_V2_ZIP_COMMENT_INVALID");
  candidateAssert(
    centralOffset + centralSize === eocdOffset,
    "PUBLIC_V2_ZIP_CENTRAL_DIRECTORY_INVALID",
  );
  const metadata = parseCentral(bytes, view, centralOffset, centralSize);
  const members = parseLocals(bytes, view, metadata, centralOffset);
  candidateAssert(
    members.reduce((total, member) => total + member.bytes.length, 0) <= PUBLIC_V2_MAX_BYTES,
    "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID",
  );
  const provisioned = requireMember(members, 0);
  const activated = requireMember(members, 1);
  const closure = requireMember(members, 2);
  return {
    activated: activated.bytes,
    closure: closure.bytes,
    provisioned: provisioned.bytes,
  };
}

function parseCentral(
  bytes: Uint8Array,
  view: DataView,
  start: number,
  size: number,
): ParsedMemberMetadata[] {
  let offset = start;
  let expandedTotal = 0;
  const members: ParsedMemberMetadata[] = [];
  for (const expectedName of orderedNames()) {
    assertRange(bytes, offset, CENTRAL_HEADER_BYTES);
    requireU32(view, offset, CENTRAL_SIGNATURE, "PUBLIC_V2_ZIP_CENTRAL_HEADER_INVALID");
    requireU16(view, offset + 4, VERSION_MADE_BY, "PUBLIC_V2_ZIP_METADATA_INVALID");
    validateCommonHeader(view, offset + 6);
    const crc = view.getUint32(offset + 16, true);
    const compressed = view.getUint32(offset + 20, true);
    const expanded = view.getUint32(offset + 24, true);
    candidateAssert(compressed === expanded, "PUBLIC_V2_ZIP_COMPRESSION_INVALID");
    candidateAssert(
      expanded >= 1 && expanded <= PUBLIC_V2_MAX_BYTES,
      "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID",
    );
    expandedTotal += expanded;
    candidateAssert(expandedTotal <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID");
    const nameLength = view.getUint16(offset + 28, true);
    requireU16(view, offset + 30, 0, "PUBLIC_V2_ZIP_EXTRA_INVALID");
    requireU16(view, offset + 32, 0, "PUBLIC_V2_ZIP_COMMENT_INVALID");
    requireU16(view, offset + 34, 0, "PUBLIC_V2_ZIP_DISK_INVALID");
    requireU16(view, offset + 36, 0, "PUBLIC_V2_ZIP_METADATA_INVALID");
    requireU32(view, offset + 38, EXTERNAL_ATTRIBUTES, "PUBLIC_V2_ZIP_METADATA_INVALID");
    const localOffset = view.getUint32(offset + 42, true);
    const nameBytes = slice(bytes, offset + CENTRAL_HEADER_BYTES, nameLength);
    const name = decodeName(nameBytes);
    candidateAssert(name === expectedName, "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID");
    members.push({ crc32: crc, localOffset, name, nameBytes, size: expanded });
    offset += CENTRAL_HEADER_BYTES + nameLength;
  }
  candidateAssert(offset === start + size, "PUBLIC_V2_ZIP_CENTRAL_DIRECTORY_INVALID");
  return members;
}

function parseLocals(
  bytes: Uint8Array,
  view: DataView,
  metadata: readonly ParsedMemberMetadata[],
  centralOffset: number,
): DeterministicZipMember[] {
  let expectedOffset = 0;
  const members: DeterministicZipMember[] = [];
  for (const central of metadata) {
    candidateAssert(central.localOffset === expectedOffset, "PUBLIC_V2_ZIP_LOCAL_OFFSET_INVALID");
    assertRange(bytes, expectedOffset, LOCAL_HEADER_BYTES);
    requireU32(view, expectedOffset, LOCAL_SIGNATURE, "PUBLIC_V2_ZIP_LOCAL_HEADER_INVALID");
    validateCommonHeader(view, expectedOffset + 4);
    requireU32(view, expectedOffset + 14, central.crc32, "PUBLIC_V2_ZIP_CRC_INVALID");
    requireU32(view, expectedOffset + 18, central.size, "PUBLIC_V2_ZIP_SIZE_INVALID");
    requireU32(view, expectedOffset + 22, central.size, "PUBLIC_V2_ZIP_SIZE_INVALID");
    requireU16(view, expectedOffset + 26, central.nameBytes.length, "PUBLIC_V2_ZIP_NAME_INVALID");
    requireU16(view, expectedOffset + 28, 0, "PUBLIC_V2_ZIP_EXTRA_INVALID");
    const nameStart = expectedOffset + LOCAL_HEADER_BYTES;
    const localName = slice(bytes, nameStart, central.nameBytes.length);
    candidateAssert(equalBytes(localName, central.nameBytes), "PUBLIC_V2_ZIP_NAME_MISMATCH");
    const dataStart = nameStart + localName.length;
    const data = slice(bytes, dataStart, central.size);
    candidateAssert(crc32(data) === central.crc32, "PUBLIC_V2_ZIP_CRC_INVALID");
    members.push({ bytes: data, name: central.name });
    expectedOffset = dataStart + data.length;
  }
  candidateAssert(expectedOffset === centralOffset, "PUBLIC_V2_ZIP_LOCAL_LAYOUT_INVALID");
  return members;
}

function writeLocal(
  output: Uint8Array,
  view: DataView,
  offset: number,
  member: MemberMetadata,
): number {
  view.setUint32(offset, LOCAL_SIGNATURE, true);
  writeCommonHeader(view, offset + 4, member);
  view.setUint16(offset + 26, member.nameBytes.length, true);
  view.setUint16(offset + 28, 0, true);
  output.set(member.nameBytes, offset + LOCAL_HEADER_BYTES);
  const dataOffset = offset + LOCAL_HEADER_BYTES + member.nameBytes.length;
  output.set(member.bytes, dataOffset);
  return dataOffset + member.bytes.length;
}

function writeCentral(
  output: Uint8Array,
  view: DataView,
  offset: number,
  member: MemberMetadata,
): number {
  view.setUint32(offset, CENTRAL_SIGNATURE, true);
  view.setUint16(offset + 4, VERSION_MADE_BY, true);
  writeCommonHeader(view, offset + 6, member);
  view.setUint16(offset + 28, member.nameBytes.length, true);
  view.setUint16(offset + 30, 0, true);
  view.setUint16(offset + 32, 0, true);
  view.setUint16(offset + 34, 0, true);
  view.setUint16(offset + 36, 0, true);
  view.setUint32(offset + 38, EXTERNAL_ATTRIBUTES, true);
  view.setUint32(offset + 42, member.localOffset, true);
  output.set(member.nameBytes, offset + CENTRAL_HEADER_BYTES);
  return offset + CENTRAL_HEADER_BYTES + member.nameBytes.length;
}

function writeCommonHeader(view: DataView, offset: number, member: MemberMetadata): void {
  view.setUint16(offset, VERSION_NEEDED, true);
  view.setUint16(offset + 2, 0, true);
  view.setUint16(offset + 4, 0, true);
  view.setUint16(offset + 6, DOS_TIME, true);
  view.setUint16(offset + 8, DOS_DATE, true);
  view.setUint32(offset + 10, member.crc32, true);
  view.setUint32(offset + 14, member.bytes.length, true);
  view.setUint32(offset + 18, member.bytes.length, true);
}

function validateCommonHeader(view: DataView, offset: number): void {
  requireU16(view, offset, VERSION_NEEDED, "PUBLIC_V2_ZIP_METADATA_INVALID");
  requireU16(view, offset + 2, 0, "PUBLIC_V2_ZIP_FLAGS_INVALID");
  requireU16(view, offset + 4, 0, "PUBLIC_V2_ZIP_COMPRESSION_INVALID");
  requireU16(view, offset + 6, DOS_TIME, "PUBLIC_V2_ZIP_METADATA_INVALID");
  requireU16(view, offset + 8, DOS_DATE, "PUBLIC_V2_ZIP_METADATA_INVALID");
}

function writeEocd(
  view: DataView,
  offset: number,
  count: number,
  centralSize: number,
  centralOffset: number,
): void {
  view.setUint32(offset, EOCD_SIGNATURE, true);
  view.setUint16(offset + 4, 0, true);
  view.setUint16(offset + 6, 0, true);
  view.setUint16(offset + 8, count, true);
  view.setUint16(offset + 10, count, true);
  view.setUint32(offset + 12, centralSize, true);
  view.setUint32(offset + 16, centralOffset, true);
  view.setUint16(offset + 20, 0, true);
}

function snapshotMembers(input: DeterministicPublicArchiveMembers): DeterministicZipMember[] {
  const members: readonly DeterministicZipMember[] = [
    { bytes: input.provisioned, name: PUBLIC_ARCHIVE_MEMBER_NAMES.provisioned },
    { bytes: input.activated, name: PUBLIC_ARCHIVE_MEMBER_NAMES.activated },
    { bytes: input.closure, name: PUBLIC_ARCHIVE_MEMBER_NAMES.closure },
  ];
  let expanded = 0;
  for (const member of members) {
    candidateAssert(
      member.bytes.byteLength >= 1 && member.bytes.byteLength <= PUBLIC_V2_MAX_BYTES,
      "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID",
    );
    expanded += member.bytes.byteLength;
    candidateAssert(expanded <= PUBLIC_V2_MAX_BYTES, "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID");
  }
  return members.map((member) => ({ ...member, bytes: Uint8Array.from(member.bytes) }));
}

function orderedNames(): readonly string[] {
  return [
    PUBLIC_ARCHIVE_MEMBER_NAMES.provisioned,
    PUBLIC_ARCHIVE_MEMBER_NAMES.activated,
    PUBLIC_ARCHIVE_MEMBER_NAMES.closure,
  ];
}

function encodeName(name: string): Uint8Array {
  candidateAssert(
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(name),
    "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID",
  );
  return new TextEncoder().encode(name);
}

function decodeName(bytes: Uint8Array): string {
  candidateAssert(
    bytes.every((byte) => byte <= 0x7f),
    "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID",
  );
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function slice(bytes: Uint8Array, start: number, length: number): Uint8Array {
  assertRange(bytes, start, length);
  return bytes.slice(start, start + length);
}

function assertRange(bytes: Uint8Array, start: number, length: number): void {
  candidateAssert(
    Number.isSafeInteger(start) &&
      Number.isSafeInteger(length) &&
      start >= 0 &&
      length >= 0 &&
      start + length <= bytes.length,
    "PUBLIC_V2_ZIP_TRUNCATED",
  );
}

function requireU16(view: DataView, offset: number, expected: number, code: string): void {
  candidateAssert(offset + 2 <= view.byteLength && view.getUint16(offset, true) === expected, code);
}

function requireU32(view: DataView, offset: number, expected: number, code: string): void {
  candidateAssert(offset + 4 <= view.byteLength && view.getUint32(offset, true) === expected, code);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function requireMember(
  members: readonly DeterministicZipMember[],
  index: number,
): DeterministicZipMember {
  const member = members[index];
  candidateAssert(member !== undefined, "PUBLIC_V2_ZIP_MEMBER_COUNT_INVALID");
  return member;
}
