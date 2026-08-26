import { describe, expect, it } from "vitest";

import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
} from "../src/candidate-public-v2/canonical";
import {
  buildUntrustedPublicArchive,
  parseUntrustedPublicArchive,
} from "../src/candidate-public-v2/public-archive";
import {
  RUNTIME_CLOSURE_REQUEST_SCHEMA,
  buildUnpersistedRuntimeClosureCandidate,
  parseRuntimeClosureRequest,
} from "../src/candidate-public-v2/runtime-closure";
import { verifySidecarOpening } from "../src/candidate-public-v2/sidecar";
import { objectField } from "../src/candidate-public-v2/validation";
import {
  buildDeterministicPublicZip,
  parseDeterministicPublicZip,
} from "../src/candidate-public-v2/zip-format";
import {
  buildFullCandidate,
  digest,
  distributionInputs,
  gitSha,
  nonce,
  privatePayload,
  releaseSource,
} from "./candidate-public-v2-fixtures";

describe("candidate public-v2 runtime closure and deterministic ZIP", () => {
  it("allows R to equal or be independent/ahead of reusable baseline C5", async () => {
    const identical = await buildFullCandidate();
    const ahead = await buildFullCandidate(gitSha("f"));
    expect(objectField(identical.closure.document, "release", "test").peeled_commit_sha).toBe(
      gitSha("a"),
    );
    expect(objectField(ahead.closure.document, "release", "test").peeled_commit_sha).toBe(
      gitSha("f"),
    );
    await verifySidecarOpening({
      kind: "RUNTIME_CLOSURE",
      opening: ahead.closure.opening,
      privatePayloadBytes: ahead.closure.privatePayloadBytes,
      publicDocument: ahead.closure.document,
    });
  });

  it("cross-binds baseline policy/workflow content, not R/C5 commit equality", async () => {
    const { activated, provisioned } = await buildFullCandidate();
    await expect(
      buildUnpersistedRuntimeClosureCandidate({
        activated: activated.document,
        distributions: distributionInputs(),
        nonce: nonce(4),
        privatePayload: privatePayload("RUNTIME_CLOSURE"),
        provisioned: provisioned.document,
        release: { ...releaseSource(), policySha256: digest("f") },
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_RELEASE_BASELINE_CONTENT_MISMATCH" });
  });

  it("recomputes runtime request release identity from fixed projects and tag", async () => {
    const { closure } = await buildFullCandidate();
    const request = {
      public_release_id: closure.document.public_release_id ?? null,
      schema: RUNTIME_CLOSURE_REQUEST_SCHEMA,
      schema_version: 2,
      tag: "v1.2.3",
    };
    await expect(parseRuntimeClosureRequest(canonicalPublicV2Bytes(request))).resolves.toEqual(
      request,
    );
    await expect(
      parseRuntimeClosureRequest(
        canonicalPublicV2Bytes({ ...request, public_release_id: digest("f") }),
      ),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_RELEASE_ID_MISMATCH" });
  });

  it("builds and parses one fixed three-member archive deterministically", async () => {
    const first = await buildFullCandidate();
    const second = await buildFullCandidate();
    expect(second.archive.archiveBytes).toEqual(first.archive.archiveBytes);
    expect(second.archive.archiveSha256).toBe(first.archive.archiveSha256);
    const parsed = await parseUntrustedPublicArchive(first.archive.archiveBytes);
    expect(parsed.provisioned.record_id).toBe(first.provisioned.document.record_id);
    expect(parsed.activated.record_id).toBe(first.activated.document.record_id);
    expect(parsed.closure.closure_id).toBe(first.closure.document.closure_id);
    expect(new TextDecoder().decode(parsed.archiveBytes)).not.toContain("must-never-be-public");
  });

  it("rejects duplicate, arbitrary, or reordered fixed ZIP member names", async () => {
    const { archive } = await buildFullCandidate();
    const a0 = new TextEncoder().encode("activation-a0-public-core-v2.json");
    const a1 = new TextEncoder().encode("activation-a1-public-core-v2.json");
    const arbitrary = new TextEncoder().encode("activation-z0-public-core-v2.json");

    const duplicate = replaceOccurrences(archive.archiveBytes, a0, a1);
    expect(() => parseDeterministicPublicZip(duplicate)).toThrowError(
      "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID",
    );
    const invented = replaceOccurrences(archive.archiveBytes, a0, arbitrary);
    expect(() => parseDeterministicPublicZip(invented)).toThrowError(
      "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID",
    );
    const reordered = replaceAtOriginalOccurrences(archive.archiveBytes, a0, a1);
    expect(() => parseDeterministicPublicZip(reordered)).toThrowError(
      "PUBLIC_V2_ZIP_MEMBER_NAME_INVALID",
    );
  });

  it("rejects oversized inputs and hostile central sizes before allocation", async () => {
    expect(() => parseDeterministicPublicZip(new Uint8Array(65_537))).toThrowError(
      "PUBLIC_V2_ZIP_RAW_SIZE_INVALID",
    );
    expect(() =>
      buildDeterministicPublicZip({
        activated: canonicalPublicV2Bytes({ a: 1 }),
        closure: canonicalPublicV2Bytes({ c: 1 }),
        provisioned: new Uint8Array(65_537),
      }),
    ).toThrowError("PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID");

    const { archive } = await buildFullCandidate();
    const hostile = Uint8Array.from(archive.archiveBytes);
    const central = findBytes(hostile, Uint8Array.of(0x50, 0x4b, 0x01, 0x02));
    const view = new DataView(hostile.buffer);
    view.setUint32(central + 20, 0xffff_ffff, true);
    view.setUint32(central + 24, 0xffff_ffff, true);
    expect(() => parseDeterministicPublicZip(hostile)).toThrowError(
      "PUBLIC_V2_ZIP_EXPANDED_SIZE_INVALID",
    );
  });

  it("rejects every ZIP metadata/covert-channel mutation", async () => {
    const { archive } = await buildFullCandidate();
    const central = findBytes(archive.archiveBytes, Uint8Array.of(0x50, 0x4b, 0x01, 0x02));
    const eocd = archive.archiveBytes.length - 22;
    const mutations: readonly [string, (view: DataView) => void, string][] = [
      [
        "archive comment",
        (view) => view.setUint16(eocd + 20, 1, true),
        "PUBLIC_V2_ZIP_COMMENT_INVALID",
      ],
      ["EOCD disk", (view) => view.setUint16(eocd + 4, 1, true), "PUBLIC_V2_ZIP_EOCD_INVALID"],
      [
        "ZIP64 count",
        (view) => view.setUint16(eocd + 8, 0xffff, true),
        "PUBLIC_V2_ZIP_MEMBER_COUNT_INVALID",
      ],
      [
        "ZIP64 size",
        (view) => view.setUint32(eocd + 12, 0xffff_ffff, true),
        "PUBLIC_V2_ZIP_CENTRAL_DIRECTORY_INVALID",
      ],
      ["made-by", (view) => view.setUint16(central + 4, 0, true), "PUBLIC_V2_ZIP_METADATA_INVALID"],
      [
        "central version",
        (view) => view.setUint16(central + 6, 10, true),
        "PUBLIC_V2_ZIP_METADATA_INVALID",
      ],
      [
        "encryption flag",
        (view) => view.setUint16(central + 8, 1, true),
        "PUBLIC_V2_ZIP_FLAGS_INVALID",
      ],
      [
        "descriptor flag",
        (view) => view.setUint16(central + 8, 8, true),
        "PUBLIC_V2_ZIP_FLAGS_INVALID",
      ],
      [
        "compression",
        (view) => view.setUint16(central + 10, 8, true),
        "PUBLIC_V2_ZIP_COMPRESSION_INVALID",
      ],
      [
        "DOS time",
        (view) => view.setUint16(central + 12, 1, true),
        "PUBLIC_V2_ZIP_METADATA_INVALID",
      ],
      [
        "DOS date",
        (view) => view.setUint16(central + 14, 0, true),
        "PUBLIC_V2_ZIP_METADATA_INVALID",
      ],
      [
        "central CRC",
        (view) => view.setUint32(central + 16, view.getUint32(central + 16, true) ^ 1, true),
        "PUBLIC_V2_ZIP_CRC_INVALID",
      ],
      [
        "central extra",
        (view) => view.setUint16(central + 30, 1, true),
        "PUBLIC_V2_ZIP_EXTRA_INVALID",
      ],
      [
        "member comment",
        (view) => view.setUint16(central + 32, 1, true),
        "PUBLIC_V2_ZIP_COMMENT_INVALID",
      ],
      [
        "member disk",
        (view) => view.setUint16(central + 34, 1, true),
        "PUBLIC_V2_ZIP_DISK_INVALID",
      ],
      [
        "internal attrs",
        (view) => view.setUint16(central + 36, 1, true),
        "PUBLIC_V2_ZIP_METADATA_INVALID",
      ],
      [
        "symlink attrs",
        (view) => view.setUint32(central + 38, 0xa1ff_0000, true),
        "PUBLIC_V2_ZIP_METADATA_INVALID",
      ],
      [
        "local offset",
        (view) => view.setUint32(central + 42, 1, true),
        "PUBLIC_V2_ZIP_LOCAL_OFFSET_INVALID",
      ],
      ["local version", (view) => view.setUint16(4, 10, true), "PUBLIC_V2_ZIP_METADATA_INVALID"],
      ["local flags", (view) => view.setUint16(6, 1, true), "PUBLIC_V2_ZIP_FLAGS_INVALID"],
      [
        "local compression",
        (view) => view.setUint16(8, 8, true),
        "PUBLIC_V2_ZIP_COMPRESSION_INVALID",
      ],
      ["local time", (view) => view.setUint16(10, 1, true), "PUBLIC_V2_ZIP_METADATA_INVALID"],
      [
        "local CRC",
        (view) => view.setUint32(14, view.getUint32(14, true) ^ 1, true),
        "PUBLIC_V2_ZIP_CRC_INVALID",
      ],
      ["local size", (view) => view.setUint32(18, 0, true), "PUBLIC_V2_ZIP_SIZE_INVALID"],
      ["local extra", (view) => view.setUint16(28, 1, true), "PUBLIC_V2_ZIP_EXTRA_INVALID"],
    ];
    for (const [label, mutate, code] of mutations) {
      const bytes = Uint8Array.from(archive.archiveBytes);
      mutate(new DataView(bytes.buffer));
      expect(() => parseDeterministicPublicZip(bytes), label).toThrowError(code);
    }
    const trailing = new Uint8Array(archive.archiveBytes.length + 1);
    trailing.set(archive.archiveBytes);
    expect(() => parseDeterministicPublicZip(trailing)).toThrowError("PUBLIC_V2_ZIP_EOCD_INVALID");
  });

  it("rejects a format-valid archive containing a self-ID-tampered core", async () => {
    const { activated, closure, provisioned } = await buildFullCandidate();
    const tampered = canonicalPublicV2Snapshot(provisioned.document);
    tampered.record_id = digest("f");
    const zip = buildDeterministicPublicZip({
      activated: activated.documentBytes,
      closure: closure.documentBytes,
      provisioned: canonicalPublicV2Bytes(tampered),
    });
    await expect(parseUntrustedPublicArchive(zip)).rejects.toMatchObject({
      code: "PUBLIC_V2_A0_ID_MISMATCH",
    });
    await expect(
      buildUntrustedPublicArchive({
        activated: activated.documentBytes,
        closure: closure.documentBytes,
        provisioned: canonicalPublicV2Bytes(tampered),
      }),
    ).rejects.toMatchObject({ code: "PUBLIC_V2_A0_ID_MISMATCH" });
  });
});

function replaceOccurrences(
  input: Uint8Array,
  search: Uint8Array,
  replacement: Uint8Array,
): Uint8Array {
  const output = Uint8Array.from(input);
  for (const offset of findAllBytes(input, search)) output.set(replacement, offset);
  return output;
}

function replaceAtOriginalOccurrences(
  input: Uint8Array,
  first: Uint8Array,
  second: Uint8Array,
): Uint8Array {
  const output = Uint8Array.from(input);
  for (const offset of findAllBytes(input, first)) output.set(second, offset);
  for (const offset of findAllBytes(input, second)) output.set(first, offset);
  return output;
}

function findAllBytes(input: Uint8Array, search: Uint8Array): number[] {
  const offsets: number[] = [];
  for (let offset = 0; offset <= input.length - search.length; offset += 1) {
    if (search.every((byte, index) => input[offset + index] === byte)) offsets.push(offset);
  }
  return offsets;
}

function findBytes(input: Uint8Array, search: Uint8Array): number {
  const offset = findAllBytes(input, search)[0];
  if (offset === undefined) throw new Error("fixture byte sequence missing");
  return offset;
}
