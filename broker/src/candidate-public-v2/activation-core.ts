import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
  parseCanonicalPublicV2,
} from "./canonical";
import { copyPrivateNonce, copyPublicV2Bytes } from "./bytes";
import { candidateAssert } from "./error";
import { publicV2Id, rawPublicV2Digest, requireDigest } from "./identity";
import {
  ACTIVATED_PUBLIC_CORE_SCHEMA,
  A0_BASE_KEYS,
  A0_KEYS,
  A1_BASE_KEYS,
  A1_KEYS,
  PROVISIONED_PUBLIC_CORE_SCHEMA,
  validateActivatedBase,
  validateProvisionedBase,
  withoutRecordId,
} from "./activation-core-validation";
import { buildUnpersistedSidecarOpeningForOwnedBase, type SidecarOpeningResult } from "./sidecar";
import type { UntrustedActivatedPublicCore, UntrustedProvisionedPublicCore } from "./trust";
import type { CandidateJsonObject, DigestSha256 } from "./types";
import { exactObject, projectObject } from "./validation";

export { ACTIVATED_PUBLIC_CORE_SCHEMA, PROVISIONED_PUBLIC_CORE_SCHEMA };

const A0_DOMAIN = "dpone.activation.public-a0.v2";
const A1_DOMAIN = "dpone.activation.public-a1.v2";
const ACTIVATION_DOMAIN = "dpone.activation.public-authority.v2";

export interface BrokerSourceInput {
  readonly commitSha: string;
  readonly sourceSha256: string;
  readonly treeSha: string;
}

export interface ControllerSourceInput {
  readonly actionBundle: {
    readonly bundleSha256: string;
    readonly commitSha: string;
    readonly metadataBlobSha: string;
  };
  readonly commitSha: string;
  readonly defaultBranchWorkflowBlobSha: string;
  readonly tagObjectSha: string;
  readonly tagRef: string;
  readonly treeSha: string;
  readonly workflowBlobSha: string;
  readonly workflowSha256: string;
}

export interface BaselineSourceInput {
  readonly baselineCommitSha: string;
  readonly baselineTreeSha: string;
  readonly policyBlobSha: string;
  readonly policySha256: string;
  readonly runtimeWorkflowBlobSha: string;
  readonly runtimeWorkflowSha256: string;
}

export interface UnpersistedProvisionedCandidate extends SidecarOpeningResult {
  readonly document: UntrustedProvisionedPublicCore;
  readonly documentBytes: Uint8Array;
}

export interface UnpersistedActivatedCandidate extends SidecarOpeningResult {
  readonly document: UntrustedActivatedPublicCore;
  readonly documentBytes: Uint8Array;
}

export async function buildUnpersistedProvisionedCandidate(input: {
  readonly brokerSource: BrokerSourceInput;
  readonly controllerSource: ControllerSourceInput;
  readonly nonce: Uint8Array;
  readonly privatePayload: CandidateJsonObject;
}): Promise<UnpersistedProvisionedCandidate> {
  const nonce = copyPrivateNonce(input.nonce);
  const privatePayloadBytes = canonicalPublicV2Bytes(input.privatePayload);
  const base = buildProvisionedPublicBase(input);
  const sidecar = await buildUnpersistedSidecarOpeningForOwnedBase({
    kind: "ACTIVATION_A0",
    nonce,
    privatePayloadBytes,
    publicBase: base,
  });
  const provisional = await sealProvisionedPublicCore(base, sidecar.commitment);
  const documentBytes = canonicalPublicV2Bytes(provisional);
  const document = await parseCanonicalUntrustedProvisionedPublicCore(documentBytes);
  return { ...sidecar, document, documentBytes: Uint8Array.from(documentBytes) };
}

function buildProvisionedPublicBase(input: {
  readonly brokerSource: BrokerSourceInput;
  readonly controllerSource: ControllerSourceInput;
}): CandidateJsonObject {
  const base: CandidateJsonObject = {
    broker_source: {
      commit_sha: input.brokerSource.commitSha,
      source_sha256: input.brokerSource.sourceSha256,
      tree_sha: input.brokerSource.treeSha,
    },
    controller_source: {
      action_bundle: {
        bundle_sha256: input.controllerSource.actionBundle.bundleSha256,
        commit_sha: input.controllerSource.actionBundle.commitSha,
        metadata_blob_sha: input.controllerSource.actionBundle.metadataBlobSha,
      },
      commit_sha: input.controllerSource.commitSha,
      default_branch_workflow_blob_sha: input.controllerSource.defaultBranchWorkflowBlobSha,
      tag_object_sha: input.controllerSource.tagObjectSha,
      tag_ref: input.controllerSource.tagRef,
      tree_sha: input.controllerSource.treeSha,
      workflow_blob_sha: input.controllerSource.workflowBlobSha,
      workflow_sha256: input.controllerSource.workflowSha256,
    },
    previous: "GENESIS",
    schema: PROVISIONED_PUBLIC_CORE_SCHEMA,
    schema_version: 2,
    sequence: 0,
  };
  validateProvisionedBase(base);
  return base;
}

async function sealProvisionedPublicCore(
  baseValue: CandidateJsonObject,
  commitmentValue: unknown,
): Promise<CandidateJsonObject> {
  const base = validateProvisionedBase(baseValue);
  const privateSidecarCommitment = requireDigest(
    commitmentValue,
    "PUBLIC_V2_A0_COMMITMENT_INVALID",
  );
  const unsigned: CandidateJsonObject = {
    ...base,
    private_sidecar_commitment: privateSidecarCommitment,
  };
  const record: CandidateJsonObject = {
    ...unsigned,
    record_id: await publicV2Id(A0_DOMAIN, unsigned),
  };
  return record;
}

export async function parseUntrustedProvisionedPublicCore(
  value: unknown,
): Promise<UntrustedProvisionedPublicCore> {
  const record = exactObject(canonicalPublicV2Snapshot(value), A0_KEYS, "PUBLIC_V2_A0_INVALID");
  validateProvisionedBase(projectObject(record, A0_BASE_KEYS, "PUBLIC_V2_A0_INVALID"));
  requireDigest(record.private_sidecar_commitment, "PUBLIC_V2_A0_COMMITMENT_INVALID");
  const recordId = requireDigest(record.record_id, "PUBLIC_V2_A0_RECORD_ID_INVALID");
  const unsigned = withoutRecordId(record);
  candidateAssert(recordId === (await publicV2Id(A0_DOMAIN, unsigned)), "PUBLIC_V2_A0_ID_MISMATCH");
  canonicalPublicV2Bytes(record);
  return record as UntrustedProvisionedPublicCore;
}

export async function parseCanonicalUntrustedProvisionedPublicCore(
  input: Uint8Array,
): Promise<UntrustedProvisionedPublicCore> {
  return parseUntrustedProvisionedPublicCore(parseCanonicalPublicV2(copyPublicV2Bytes(input)));
}

export async function buildUnpersistedActivatedCandidate(input: {
  readonly baselineSource: BaselineSourceInput;
  readonly nonce: Uint8Array;
  readonly privatePayload: CandidateJsonObject;
  readonly provisioned: UntrustedProvisionedPublicCore;
}): Promise<UnpersistedActivatedCandidate> {
  const nonce = copyPrivateNonce(input.nonce);
  const privatePayloadBytes = canonicalPublicV2Bytes(input.privatePayload);
  const provisionedBytes = canonicalPublicV2Bytes(input.provisioned);
  const baselineSource: BaselineSourceInput = {
    baselineCommitSha: input.baselineSource.baselineCommitSha,
    baselineTreeSha: input.baselineSource.baselineTreeSha,
    policyBlobSha: input.baselineSource.policyBlobSha,
    policySha256: input.baselineSource.policySha256,
    runtimeWorkflowBlobSha: input.baselineSource.runtimeWorkflowBlobSha,
    runtimeWorkflowSha256: input.baselineSource.runtimeWorkflowSha256,
  };
  const provisioned = await parseCanonicalUntrustedProvisionedPublicCore(provisionedBytes);
  const base = await buildActivatedPublicBase({ baselineSource, provisioned });
  const sidecar = await buildUnpersistedSidecarOpeningForOwnedBase({
    kind: "ACTIVATION_A1",
    nonce,
    privatePayloadBytes,
    publicBase: base,
  });
  const provisional = await sealActivatedPublicCore(base, sidecar.commitment);
  const documentBytes = canonicalPublicV2Bytes(provisional);
  const document = (
    await parseCanonicalUntrustedActivationPair({
      activated: documentBytes,
      provisioned: provisionedBytes,
    })
  ).activated;
  return { ...sidecar, document, documentBytes: Uint8Array.from(documentBytes) };
}

async function buildActivatedPublicBase(input: {
  readonly baselineSource: BaselineSourceInput;
  readonly provisioned: CandidateJsonObject;
}): Promise<CandidateJsonObject> {
  const provisioned = await parseUntrustedProvisionedPublicCore(input.provisioned);
  const base: CandidateJsonObject = {
    baseline_source: {
      baseline_commit_sha: input.baselineSource.baselineCommitSha,
      baseline_tree_sha: input.baselineSource.baselineTreeSha,
      policy_blob_sha: input.baselineSource.policyBlobSha,
      policy_sha256: input.baselineSource.policySha256,
      runtime_workflow_blob_sha: input.baselineSource.runtimeWorkflowBlobSha,
      runtime_workflow_sha256: input.baselineSource.runtimeWorkflowSha256,
    },
    previous: requireDigest(provisioned.record_id),
    provisioned_record_sha256: await rawPublicV2Digest(provisioned),
    schema: ACTIVATED_PUBLIC_CORE_SCHEMA,
    schema_version: 2,
    sequence: 1,
  };
  validateActivatedBase(base);
  return base;
}

async function sealActivatedPublicCore(
  baseValue: CandidateJsonObject,
  commitmentValue: unknown,
): Promise<CandidateJsonObject> {
  const base = validateActivatedBase(baseValue);
  const unsigned: CandidateJsonObject = {
    ...base,
    private_sidecar_commitment: requireDigest(commitmentValue, "PUBLIC_V2_A1_COMMITMENT_INVALID"),
  };
  const record: CandidateJsonObject = {
    ...unsigned,
    record_id: await publicV2Id(A1_DOMAIN, unsigned),
  };
  return record;
}

export async function parseUntrustedActivatedPublicCore(
  value: unknown,
  provisionedValue?: UntrustedProvisionedPublicCore,
): Promise<UntrustedActivatedPublicCore> {
  const record = exactObject(canonicalPublicV2Snapshot(value), A1_KEYS, "PUBLIC_V2_A1_INVALID");
  const provisionedSnapshot =
    provisionedValue === undefined ? undefined : canonicalPublicV2Snapshot(provisionedValue);
  validateActivatedBase(projectObject(record, A1_BASE_KEYS, "PUBLIC_V2_A1_INVALID"));
  requireDigest(record.private_sidecar_commitment, "PUBLIC_V2_A1_COMMITMENT_INVALID");
  const recordId = requireDigest(record.record_id, "PUBLIC_V2_A1_RECORD_ID_INVALID");
  candidateAssert(
    recordId === (await publicV2Id(A1_DOMAIN, withoutRecordId(record))),
    "PUBLIC_V2_A1_ID_MISMATCH",
  );
  if (provisionedSnapshot !== undefined) {
    const provisioned = await parseUntrustedProvisionedPublicCore(provisionedSnapshot);
    candidateAssert(record.previous === provisioned.record_id, "PUBLIC_V2_A1_PREVIOUS_MISMATCH");
    candidateAssert(
      record.provisioned_record_sha256 === (await rawPublicV2Digest(provisioned)),
      "PUBLIC_V2_A1_PROVISIONED_DIGEST_MISMATCH",
    );
  }
  canonicalPublicV2Bytes(record);
  return record as UntrustedActivatedPublicCore;
}

export async function parseCanonicalUntrustedActivationPair(input: {
  readonly activated: Uint8Array;
  readonly provisioned: Uint8Array;
}): Promise<{
  readonly activated: UntrustedActivatedPublicCore;
  readonly provisioned: UntrustedProvisionedPublicCore;
}> {
  const provisionedBytes = copyPublicV2Bytes(input.provisioned);
  const activatedBytes = copyPublicV2Bytes(input.activated);
  const provisioned = await parseCanonicalUntrustedProvisionedPublicCore(provisionedBytes);
  const activatedObject = parseCanonicalPublicV2(activatedBytes);
  const activated = await parseUntrustedActivatedPublicCore(activatedObject, provisioned);
  return { activated, provisioned };
}

export async function activationBinding(
  provisionedValue: UntrustedProvisionedPublicCore,
  activatedValue: UntrustedActivatedPublicCore,
): Promise<CandidateJsonObject> {
  const provisionedSnapshot = canonicalPublicV2Snapshot(provisionedValue);
  const activatedSnapshot = canonicalPublicV2Snapshot(activatedValue);
  const provisioned = await parseUntrustedProvisionedPublicCore(provisionedSnapshot);
  const activated = await parseUntrustedActivatedPublicCore(activatedSnapshot, provisioned);
  return {
    activated_record_id: requireDigest(activated.record_id),
    activated_record_sha256: await rawPublicV2Digest(activated),
    provisioned_record_id: requireDigest(provisioned.record_id),
    provisioned_record_sha256: await rawPublicV2Digest(provisioned),
  };
}

export async function publicActivationId(
  provisioned: UntrustedProvisionedPublicCore,
  activated: UntrustedActivatedPublicCore,
): Promise<DigestSha256> {
  return publicV2Id(ACTIVATION_DOMAIN, await activationBinding(provisioned, activated));
}
