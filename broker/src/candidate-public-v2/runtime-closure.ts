import {
  activationBinding,
  parseCanonicalUntrustedActivationPair,
  parseUntrustedActivatedPublicCore,
  parseUntrustedProvisionedPublicCore,
  publicActivationId,
} from "./activation-core";
import {
  canonicalPublicV2Bytes,
  canonicalPublicV2Snapshot,
  parseCanonicalPublicV2,
} from "./canonical";
import { copyPrivateNonce, copyPublicV2Bytes } from "./bytes";
import {
  buildDistributionRows,
  validateDistributionRows,
  type DistributionInput,
} from "./distributions";
import { candidateAssert } from "./error";
import { publicV2Id, requireDigest } from "./identity";
import { publicReleaseId as derivePublicReleaseId } from "./release-identity";
import { buildUnpersistedSidecarOpeningForOwnedBase, type SidecarOpeningResult } from "./sidecar";
import type {
  UntrustedActivatedPublicCore,
  UntrustedProvisionedPublicCore,
  UntrustedRuntimeClosure,
} from "./trust";
import type { CandidateJsonObject, CandidateJsonValue } from "./types";
import {
  TAG,
  exactObject,
  gitShaField,
  jsonEqual,
  literalField,
  objectField,
  projectObject,
} from "./validation";

export const RUNTIME_CLOSURE_PUBLIC_SCHEMA = "dpone.release-runtime-closure-public.v2";
export {
  RUNTIME_CLOSURE_REQUEST_SCHEMA,
  parseRuntimeClosureRequest,
} from "./runtime-closure-request";

const AUTHORITY_DOMAIN = "dpone.release.public-authority.v2";
const INVENTORY_DOMAIN = "dpone.release.public-distribution-inventory.v2";
const CANDIDATE_DOMAIN = "dpone.release.public-candidate.v2";
const CLOSURE_DOMAIN = "dpone.release.public-runtime-closure.v2";
const BASE_KEYS = [
  "activation",
  "controller_action",
  "decision",
  "distribution_inventory_id",
  "distributions",
  "public_authority_id",
  "public_candidate_id",
  "public_release_id",
  "release",
  "schema",
  "schema_version",
  "state",
  "status",
] as const;
const CLOSURE_KEYS = [...BASE_KEYS, "closure_id", "private_sidecar_commitment"] as const;

export interface ReleaseSourceInput {
  readonly peeledCommitSha: string;
  readonly policyBlobSha: string;
  readonly policySha256: string;
  readonly runtimeWorkflowBlobSha: string;
  readonly runtimeWorkflowSha256: string;
  readonly tag: string;
  readonly tagObjectSha: string;
}

export interface UnpersistedRuntimeClosureCandidate extends SidecarOpeningResult {
  readonly document: UntrustedRuntimeClosure;
  readonly documentBytes: Uint8Array;
}

export async function buildUnpersistedRuntimeClosureCandidate(input: {
  readonly activated: UntrustedActivatedPublicCore;
  readonly distributions: readonly DistributionInput[];
  readonly nonce: Uint8Array;
  readonly privatePayload: CandidateJsonObject;
  readonly provisioned: UntrustedProvisionedPublicCore;
  readonly release: ReleaseSourceInput;
}): Promise<UnpersistedRuntimeClosureCandidate> {
  const nonce = copyPrivateNonce(input.nonce);
  const privatePayloadBytes = canonicalPublicV2Bytes(input.privatePayload);
  const provisionedBytes = canonicalPublicV2Bytes(input.provisioned);
  const activatedBytes = canonicalPublicV2Bytes(input.activated);
  const release = snapshotReleaseInput(input.release);
  candidateAssert(input.distributions.length === 8, "PUBLIC_V2_DISTRIBUTIONS_INVALID");
  const distributionInputs = input.distributions.map((row) => ({
    filename: row.filename,
    project: row.project,
    sha256: row.sha256,
    sizeBytes: row.sizeBytes,
    version: row.version,
  }));
  const pair = await parseCanonicalUntrustedActivationPair({
    activated: activatedBytes,
    provisioned: provisionedBytes,
  });
  const distributions = buildDistributionRows(distributionInputs, release.tag);
  const base = await buildClosureBase(pair.provisioned, pair.activated, release, distributions);
  const sidecar = await buildUnpersistedSidecarOpeningForOwnedBase({
    kind: "RUNTIME_CLOSURE",
    nonce,
    privatePayloadBytes,
    publicBase: base,
  });
  const unsigned: CandidateJsonObject = {
    ...base,
    private_sidecar_commitment: sidecar.commitment,
  };
  const provisional: CandidateJsonObject = {
    ...unsigned,
    closure_id: await publicV2Id(CLOSURE_DOMAIN, unsigned),
  };
  const documentBytes = canonicalPublicV2Bytes(provisional);
  const document = await parseCanonicalUntrustedRuntimeClosure({
    activated: activatedBytes,
    closure: documentBytes,
    provisioned: provisionedBytes,
  });
  return { ...sidecar, document, documentBytes: Uint8Array.from(documentBytes) };
}

export async function parseCanonicalUntrustedRuntimeClosure(input: {
  readonly activated: Uint8Array;
  readonly closure: Uint8Array;
  readonly provisioned: Uint8Array;
}): Promise<UntrustedRuntimeClosure> {
  const activatedBytes = copyPublicV2Bytes(input.activated);
  const closure = parseCanonicalPublicV2(copyPublicV2Bytes(input.closure));
  const provisionedBytes = copyPublicV2Bytes(input.provisioned);
  const pair = await parseCanonicalUntrustedActivationPair({
    activated: activatedBytes,
    provisioned: provisionedBytes,
  });
  return parseUntrustedRuntimeClosure(closure, pair.provisioned, pair.activated);
}

export async function parseUntrustedRuntimeClosure(
  value: unknown,
  provisionedValue: UntrustedProvisionedPublicCore,
  activatedValue: UntrustedActivatedPublicCore,
): Promise<UntrustedRuntimeClosure> {
  const closure = exactObject(
    canonicalPublicV2Snapshot(value),
    CLOSURE_KEYS,
    "PUBLIC_V2_CLOSURE_INVALID",
  );
  const provisionedSnapshot = canonicalPublicV2Snapshot(provisionedValue);
  const activatedSnapshot = canonicalPublicV2Snapshot(activatedValue);
  const provisioned = await parseUntrustedProvisionedPublicCore(provisionedSnapshot);
  const activated = await parseUntrustedActivatedPublicCore(activatedSnapshot, provisioned);
  await validateClosureBase(
    projectObject(closure, BASE_KEYS, "PUBLIC_V2_CLOSURE_INVALID"),
    provisioned,
    activated,
  );
  requireDigest(closure.private_sidecar_commitment, "PUBLIC_V2_CLOSURE_COMMITMENT_INVALID");
  const closureId = requireDigest(closure.closure_id, "PUBLIC_V2_CLOSURE_ID_INVALID");
  const unsigned = Object.fromEntries(
    Object.entries(closure).filter(([key]) => key !== "closure_id"),
  );
  candidateAssert(
    closureId === (await publicV2Id(CLOSURE_DOMAIN, unsigned)),
    "PUBLIC_V2_CLOSURE_ID_MISMATCH",
  );
  canonicalPublicV2Bytes(closure);
  return closure as UntrustedRuntimeClosure;
}

async function buildClosureBase(
  provisioned: UntrustedProvisionedPublicCore,
  activated: UntrustedActivatedPublicCore,
  releaseInput: ReleaseSourceInput,
  distributions: CandidateJsonValue[],
): Promise<CandidateJsonObject> {
  const release: CandidateJsonObject = {
    peeled_commit_sha: releaseInput.peeledCommitSha,
    policy_blob_sha: releaseInput.policyBlobSha,
    policy_sha256: releaseInput.policySha256,
    runtime_workflow_blob_sha: releaseInput.runtimeWorkflowBlobSha,
    runtime_workflow_sha256: releaseInput.runtimeWorkflowSha256,
    tag: releaseInput.tag,
    tag_object_sha: releaseInput.tagObjectSha,
  };
  const binding = await activationBinding(provisioned, activated);
  const activationId = await publicActivationId(provisioned, activated);
  const publicReleaseId = await derivePublicReleaseId(releaseInput.tag);
  const distributionInventoryId = await publicV2Id(INVENTORY_DOMAIN, { distributions });
  const publicAuthorityId = await publicV2Id(AUTHORITY_DOMAIN, {
    activation_id: activationId,
    peeled_commit_sha: releaseInput.peeledCommitSha,
    policy_sha256: releaseInput.policySha256,
    public_release_id: publicReleaseId,
    tag_object_sha: releaseInput.tagObjectSha,
  });
  const base: CandidateJsonObject = {
    activation: { ...binding, activation_id: activationId },
    controller_action: controllerAction(provisioned),
    decision: "GO",
    distribution_inventory_id: distributionInventoryId,
    distributions,
    public_authority_id: publicAuthorityId,
    public_candidate_id: await publicV2Id(CANDIDATE_DOMAIN, {
      distribution_inventory_id: distributionInventoryId,
      public_authority_id: publicAuthorityId,
    }),
    public_release_id: publicReleaseId,
    release,
    schema: RUNTIME_CLOSURE_PUBLIC_SCHEMA,
    schema_version: 2,
    state: "CLOSED",
    status: "PASS",
  };
  await validateClosureBase(base, provisioned, activated);
  return base;
}

function controllerAction(provisioned: UntrustedProvisionedPublicCore): CandidateJsonObject {
  const controller = objectField(provisioned, "controller_source", "PUBLIC_V2_CONTROLLER_INVALID");
  return canonicalPublicV2Snapshot(
    objectField(controller, "action_bundle", "PUBLIC_V2_CONTROLLER_ACTION_INVALID"),
  );
}

async function validateClosureBase(
  value: unknown,
  provisioned: UntrustedProvisionedPublicCore,
  activated: UntrustedActivatedPublicCore,
): Promise<void> {
  const base = exactObject(value, BASE_KEYS, "PUBLIC_V2_CLOSURE_BASE_INVALID");
  const release = validateRelease(objectField(base, "release", "PUBLIC_V2_RELEASE_INVALID"));
  const tag = release.tag;
  candidateAssert(typeof tag === "string", "PUBLIC_V2_RELEASE_TAG_INVALID");
  const distributions = validateDistributionRows(base.distributions, tag);
  const binding = await activationBinding(provisioned, activated);
  const activationId = await publicActivationId(provisioned, activated);
  candidateAssert(
    jsonEqual(objectField(base, "activation", "PUBLIC_V2_CLOSURE_ACTIVATION_INVALID"), {
      ...binding,
      activation_id: activationId,
    }),
    "PUBLIC_V2_CLOSURE_ACTIVATION_MISMATCH",
  );
  candidateAssert(
    jsonEqual(
      objectField(base, "controller_action", "PUBLIC_V2_CLOSURE_CONTROLLER_ACTION_INVALID"),
      controllerAction(provisioned),
    ),
    "PUBLIC_V2_CLOSURE_CONTROLLER_ACTION_MISMATCH",
  );
  validateReleaseAgainstBaseline(release, activated);
  await validateClosureIds(base, release, distributions, activationId);
  literalField(base, "decision", "GO", "PUBLIC_V2_CLOSURE_BASE_INVALID");
  literalField(base, "schema", RUNTIME_CLOSURE_PUBLIC_SCHEMA, "PUBLIC_V2_CLOSURE_BASE_INVALID");
  literalField(base, "schema_version", 2, "PUBLIC_V2_CLOSURE_BASE_INVALID");
  literalField(base, "state", "CLOSED", "PUBLIC_V2_CLOSURE_BASE_INVALID");
  literalField(base, "status", "PASS", "PUBLIC_V2_CLOSURE_BASE_INVALID");
  canonicalPublicV2Bytes(base);
}

function validateRelease(value: CandidateJsonObject): CandidateJsonObject {
  const release = exactObject(
    value,
    [
      "peeled_commit_sha",
      "policy_blob_sha",
      "policy_sha256",
      "runtime_workflow_blob_sha",
      "runtime_workflow_sha256",
      "tag",
      "tag_object_sha",
    ],
    "PUBLIC_V2_RELEASE_INVALID",
  );
  const peeled = gitShaField(release, "peeled_commit_sha", "PUBLIC_V2_RELEASE_INVALID");
  gitShaField(release, "policy_blob_sha", "PUBLIC_V2_RELEASE_INVALID");
  requireDigest(release.policy_sha256, "PUBLIC_V2_RELEASE_INVALID");
  gitShaField(release, "runtime_workflow_blob_sha", "PUBLIC_V2_RELEASE_INVALID");
  requireDigest(release.runtime_workflow_sha256, "PUBLIC_V2_RELEASE_INVALID");
  const tag = release.tag;
  candidateAssert(typeof tag === "string" && TAG.test(tag), "PUBLIC_V2_RELEASE_TAG_INVALID");
  const tagObject = gitShaField(release, "tag_object_sha", "PUBLIC_V2_RELEASE_INVALID");
  candidateAssert(tagObject !== peeled, "PUBLIC_V2_RELEASE_TAG_NOT_ANNOTATED");
  return release;
}

function validateReleaseAgainstBaseline(
  release: CandidateJsonObject,
  activated: UntrustedActivatedPublicCore,
): void {
  const baseline = objectField(activated, "baseline_source", "PUBLIC_V2_A1_BASELINE_INVALID");
  for (const key of [
    "policy_blob_sha",
    "policy_sha256",
    "runtime_workflow_blob_sha",
    "runtime_workflow_sha256",
  ]) {
    candidateAssert(release[key] === baseline[key], "PUBLIC_V2_RELEASE_BASELINE_CONTENT_MISMATCH");
  }
  // Deliberately no public equality/inequality between R and reusable baseline C5.
}

async function validateClosureIds(
  base: CandidateJsonObject,
  release: CandidateJsonObject,
  distributions: CandidateJsonValue[],
  activationId: string,
): Promise<void> {
  const releaseTag = release.tag;
  candidateAssert(typeof releaseTag === "string", "PUBLIC_V2_RELEASE_TAG_INVALID");
  const publicReleaseId = await derivePublicReleaseId(releaseTag);
  const inventoryId = await publicV2Id(INVENTORY_DOMAIN, { distributions });
  const authorityId = await publicV2Id(AUTHORITY_DOMAIN, {
    activation_id: activationId,
    peeled_commit_sha: release.peeled_commit_sha ?? null,
    policy_sha256: release.policy_sha256 ?? null,
    public_release_id: publicReleaseId,
    tag_object_sha: release.tag_object_sha ?? null,
  });
  candidateAssert(base.public_release_id === publicReleaseId, "PUBLIC_V2_RELEASE_ID_MISMATCH");
  candidateAssert(
    base.distribution_inventory_id === inventoryId,
    "PUBLIC_V2_INVENTORY_ID_MISMATCH",
  );
  candidateAssert(base.public_authority_id === authorityId, "PUBLIC_V2_AUTHORITY_ID_MISMATCH");
  candidateAssert(
    base.public_candidate_id ===
      (await publicV2Id(CANDIDATE_DOMAIN, {
        distribution_inventory_id: inventoryId,
        public_authority_id: authorityId,
      })),
    "PUBLIC_V2_CANDIDATE_ID_MISMATCH",
  );
}

function snapshotReleaseInput(input: ReleaseSourceInput): ReleaseSourceInput {
  return {
    peeledCommitSha: input.peeledCommitSha,
    policyBlobSha: input.policyBlobSha,
    policySha256: input.policySha256,
    runtimeWorkflowBlobSha: input.runtimeWorkflowBlobSha,
    runtimeWorkflowSha256: input.runtimeWorkflowSha256,
    tag: input.tag,
    tagObjectSha: input.tagObjectSha,
  };
}
