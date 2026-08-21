import { canonicalPublicV2Bytes } from "./canonical";
import { candidateAssert } from "./error";
import { requireDigest } from "./identity";
import type { CandidateJsonObject, CandidateJsonValue } from "./types";
import { TAG, VERSION, exactObject, integerField, literalField, stringField } from "./validation";

export const PUBLIC_PROJECTS = Object.freeze([
  "apache-airflow-providers-dpone",
  "dpone",
  "dpone-airflow-pack",
  "dpone-native-accel",
] as const);

const NORMALIZED_PROJECTS = Object.freeze([
  "apache_airflow_providers_dpone",
  "dpone",
  "dpone_airflow_pack",
  "dpone_native_accel",
] as const);
const MAX_DISTRIBUTION_BYTES = 100_000_000;
const MAX_TOTAL_BYTES = 536_870_912;

export interface DistributionInput {
  readonly filename: string;
  readonly project: (typeof PUBLIC_PROJECTS)[number];
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly version: string;
}

export function buildDistributionRows(
  inputs: readonly DistributionInput[],
  tag: string,
): CandidateJsonValue[] {
  candidateAssert(TAG.test(tag), "PUBLIC_V2_RELEASE_TAG_INVALID");
  const version = tag.slice(1);
  candidateAssert(inputs.length === 8, "PUBLIC_V2_DISTRIBUTIONS_INVALID");
  const rows = inputs.map<CandidateJsonObject>((input) => ({
    filename: input.filename,
    project: input.project,
    sha256: input.sha256,
    size_bytes: input.sizeBytes,
    version: input.version,
  }));
  validateDistributionRows(rows, tag);
  candidateAssert(
    rows.every((row) => row.version === version),
    "PUBLIC_V2_VERSION_MISMATCH",
  );
  return rows;
}

export function validateDistributionRows(value: unknown, tag: string): CandidateJsonValue[] {
  candidateAssert(TAG.test(tag), "PUBLIC_V2_RELEASE_TAG_INVALID");
  candidateAssert(Array.isArray(value) && value.length === 8, "PUBLIC_V2_DISTRIBUTIONS_INVALID");
  const version = tag.slice(1);
  const validatedRows: CandidateJsonValue[] = [];
  let totalBytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const row = exactObject(
      value[index],
      ["filename", "project", "sha256", "size_bytes", "version"],
      "PUBLIC_V2_DISTRIBUTION_INVALID",
    );
    const projectIndex = Math.floor(index / 2);
    const project = PUBLIC_PROJECTS[projectIndex];
    const normalized = NORMALIZED_PROJECTS[projectIndex];
    candidateAssert(
      project !== undefined && normalized !== undefined,
      "PUBLIC_V2_DISTRIBUTION_INVALID",
    );
    literalField(row, "project", project, "PUBLIC_V2_DISTRIBUTION_INVALID");
    stringField(row, "version", "PUBLIC_V2_DISTRIBUTION_INVALID", VERSION);
    candidateAssert(row.version === version, "PUBLIC_V2_VERSION_MISMATCH");
    const suffix = index % 2 === 0 ? `-${version}-py3-none-any.whl` : `-${version}.tar.gz`;
    literalField(row, "filename", `${normalized}${suffix}`, "PUBLIC_V2_FILENAME_INVALID");
    requireDigest(row.sha256, "PUBLIC_V2_DISTRIBUTION_DIGEST_INVALID");
    totalBytes += integerField(
      row,
      "size_bytes",
      1,
      MAX_DISTRIBUTION_BYTES,
      "PUBLIC_V2_DISTRIBUTION_SIZE_INVALID",
    );
    candidateAssert(Number.isSafeInteger(totalBytes), "PUBLIC_V2_DISTRIBUTION_SIZE_INVALID");
    validatedRows.push(row);
  }
  candidateAssert(totalBytes <= MAX_TOTAL_BYTES, "PUBLIC_V2_DISTRIBUTION_TOTAL_SIZE_INVALID");
  canonicalPublicV2Bytes({ distributions: validatedRows });
  return validatedRows;
}
