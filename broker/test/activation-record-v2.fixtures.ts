import {
  activationComponentJournalSessionId,
  journalFreshUntil,
} from "../src/activation-component-journal-validation";
import { ConfidentialActivationComponentResolver } from "../src/activation-component-resolver";
import {
  activationRecordV2AttemptId,
  activationRecordV2IntentSha256,
  activationRecordV2IssuanceId,
} from "../src/activation-record-v2-evidence";
import {
  buildActivationActivatedRecordV2,
  buildActivationProvisionedRecordV2,
  parseActivationRecordV2Chain,
} from "../src/activation-record-v2-builder";
import { activationRecordV2WormKey } from "../src/activation-record-v2-identity";
import { digestObject } from "../src/canonical";
import type { JsonObject } from "../src/types";
import { fixtureReader, productionResolverFixture } from "./activation-component-resolver.fixtures";
import { compactServiceAuthorityFixture } from "./activation-record-v2-service.fixtures";
import { compactDirectEvidenceFixture } from "./activation-record-v2-direct.fixtures";

const ISSUED_A0 = "2026-08-19T12:00:00.000Z";
const DELEGATED_A0 = "2026-08-19T12:00:02.000Z";
const OBSERVED_A0 = "2026-08-19T12:00:03.000Z";
const SEALED_A0 = "2026-08-19T12:00:04.000Z";
const ISSUED_A1 = "2026-08-19T12:00:07.000Z";
const DELEGATED_A1 = "2026-08-19T12:00:08.000Z";
const OBSERVED_A1 = "2026-08-19T12:00:09.000Z";
const SEALED_A1 = "2026-08-19T12:00:10.000Z";
const RETENTION = "2034-08-20T12:00:00.000Z";

export interface CompactActivationRecordV2Fixture {
  readonly activated: Awaited<ReturnType<typeof buildActivationActivatedRecordV2>>;
  readonly activatedBody: JsonObject;
  readonly fullCloudflareResults: readonly JsonObject[];
  readonly rawComponentBodies: readonly Uint8Array[];
  readonly provisioned: Awaited<ReturnType<typeof buildActivationProvisionedRecordV2>>;
  readonly provisionedBody: JsonObject;
}

/** Build A0/A1 from the checked-in production component and Cloudflare provider fixtures. */
export async function compactActivationRecordV2Fixture(
  worstCase = false,
): Promise<CompactActivationRecordV2Fixture> {
  const source = await productionResolverFixture();
  const resolved = await new ConfidentialActivationComponentResolver(
    fixtureReader(source),
    source.source.source.config,
  ).resolve(source.pointerBytes);
  const workerVersionId = source.source.input.descriptor.workerVersionId;
  const pointer = decodeObject(source.pointerBytes);
  if (worstCase) object(pointer.worm).version_id = longVersion(1);
  const descriptor = source.source.input.descriptor;
  const generation = worstCase ? 2 : 1;
  const predecessor = worstCase ? tagged(801) : null;
  const sessionId = await activationComponentJournalSessionId(
    workerVersionId,
    descriptor.setId,
    descriptor.descriptorId,
    descriptor.descriptorSha256,
    generation,
    generation,
    predecessor,
  );
  const componentAuthority: JsonObject = {
    descriptor: {
      committed_at: descriptor.committedAt,
      descriptor_id: descriptor.descriptorId,
      descriptor_sha256: descriptor.descriptorSha256,
      set_id: descriptor.setId,
      worker_version_id: workerVersionId,
    },
    manifest_pointer: pointer,
    manifest_pointer_sha256: await digestObject(pointer),
    resolved_projection_sha256: resolved.projectionSha256,
    session: {
      fresh_until: journalFreshUntil(descriptor.committedAt),
      generation,
      journal_ordinal: generation,
      predecessor_session_id: predecessor,
      session_id: sessionId,
      state: "SELECTED",
    },
  };
  const a0Intent = await activationRecordV2IntentSha256(componentIntent(componentAuthority), 0);
  const a0Operation = await operation(a0Intent, 0, workerVersionId, ISSUED_A0);
  const a0Service = await compactServiceAuthorityFixture(
    a0Operation,
    0,
    DELEGATED_A0,
    OBSERVED_A0,
    SEALED_A0,
    worstCase,
  );
  const direct = await compactDirectEvidenceFixture(
    source,
    resolved.document,
    a0Operation,
    DELEGATED_A0,
    worstCase,
  );
  const provisionedBody: JsonObject = {
    committed_at: SEALED_A0,
    component_authority: componentAuthority,
    fencing_token: 1,
    observed_at: SEALED_A0,
    operation: a0Operation,
    previous: "GENESIS",
    provider_evidence: direct,
    schema: "dpone.release-broker-provisioned.v2",
    schema_version: 2,
    sequence: 0,
    service_authority: a0Service.compact,
    worker_version_id: workerVersionId,
  };
  const provisioned = await buildActivationProvisionedRecordV2(provisionedBody);
  const provisionedWorm = {
    digest: provisioned.recordSha256,
    key: activationRecordV2WormKey(workerVersionId, 0, provisioned.recordSha256),
    retention_until: RETENTION,
    version_id: worstCase ? longVersion(70) : "4_z-activation-record-v2-a0",
  };
  const provisionedPointer: JsonObject = {
    component_set_id: descriptor.setId,
    manifest_pointer_sha256: componentAuthority.manifest_pointer_sha256 ?? null,
    record_id: provisioned.recordId,
    record_sha256: provisioned.recordSha256,
    resolved_projection_sha256: resolved.projectionSha256,
    worker_version_id: workerVersionId,
    worm: provisionedWorm,
  };
  const promotion = promotionFixture(workerVersionId, worstCase);
  const target = targetFixture();
  const approvals = approvalsFixture();
  const a1Intent = await activationRecordV2IntentSha256(
    { approvals, promotion, provisioned: provisionedPointer, target },
    1,
  );
  const a1Operation = await operation(a1Intent, 1, workerVersionId, ISSUED_A1);
  const a1Service = await compactServiceAuthorityFixture(
    a1Operation,
    1,
    DELEGATED_A1,
    OBSERVED_A1,
    SEALED_A1,
    worstCase,
  );
  const activatedBody: JsonObject = {
    approvals,
    committed_at: SEALED_A1,
    fencing_token: 2,
    observed_at: SEALED_A1,
    operation: a1Operation,
    previous: provisioned.recordId,
    promotion,
    provisioned: provisionedPointer,
    schema: "dpone.release-broker-activated.v2",
    schema_version: 2,
    sequence: 1,
    service_authority: a1Service.compact,
    target,
    worker_version_id: workerVersionId,
  };
  const activated = await buildActivationActivatedRecordV2(activatedBody);
  await parseActivationRecordV2Chain(provisioned.canonicalBytes, activated.canonicalBytes);
  return {
    activated,
    activatedBody,
    fullCloudflareResults: [a0Service.fullResult, a1Service.fullResult],
    provisioned,
    provisionedBody,
    rawComponentBodies: source.componentSnapshot.versions.map(({ canonicalBytes: bytes }) =>
      Uint8Array.from(bytes),
    ),
  };
}

async function operation(
  intentSha256: string,
  sequence: 0 | 1,
  workerVersionId: string,
  issuedAt: string,
): Promise<JsonObject> {
  const attemptId = await activationRecordV2AttemptId(intentSha256, sequence, workerVersionId);
  const issuanceId = await activationRecordV2IssuanceId(attemptId, 1);
  return {
    attempt_id: attemptId,
    fresh_until: new Date(Date.parse(issuedAt) + 60_000).toISOString(),
    internal_request_id: `activation-${issuanceId.slice(7)}`,
    intent_sha256: intentSha256,
    issuance_id: issuanceId,
    issuance_ordinal: 1,
    issued_at: issuedAt,
  };
}

function componentIntent(authority: JsonObject): JsonObject {
  const descriptor = object(authority.descriptor);
  const session = object(authority.session);
  return {
    descriptor_id: descriptor.descriptor_id ?? null,
    descriptor_sha256: descriptor.descriptor_sha256 ?? null,
    manifest_pointer: authority.manifest_pointer ?? null,
    manifest_pointer_sha256: authority.manifest_pointer_sha256 ?? null,
    resolved_projection_sha256: authority.resolved_projection_sha256 ?? null,
    selected_session_id: session.session_id ?? null,
    set_id: descriptor.set_id ?? null,
    worker_version_id: descriptor.worker_version_id ?? null,
  };
}

function approvalsFixture(): JsonObject {
  return {
    adr_sha256: tagged(1001),
    feature_design_sha256: tagged(1002),
    final_diff_sha256: tagged(1003),
    independent_review_receipt_id: tagged(1004),
    owner_approval_receipt_id: tagged(1005),
  };
}

function promotionFixture(workerVersionId: string, worstCase: boolean): JsonObject {
  const reportSha256 = tagged(1102);
  return {
    completed_at: "2026-08-19T12:00:06.000Z",
    deployment_id: "00000000-0000-0000-0000-000000001101",
    promotion_report_record_id: tagged(1101),
    promotion_report_record_sha256: reportSha256,
    promotion_report_worm: {
      digest: reportSha256,
      key: worstCase
        ? `receipts/v1/deployment-observations/${"k".repeat(450)}.json`
        : "receipts/v1/deployment-observations/compact-v2-promotion.json",
      retention_until: RETENTION,
      version_id: worstCase ? longVersion(71) : "4_z-promotion-report-v2",
    },
    provider_observation_sha256: tagged(1103),
    started_at: "2026-08-19T12:00:05.000Z",
    worker_version_id: workerVersionId,
  };
}

function targetFixture(): JsonObject {
  const commitSha = "e".repeat(40);
  return {
    commit_sha: commitSha,
    policy_blob_sha: "f".repeat(40),
    policy_path: ".agents/policy/github-branch-protection.yml",
    policy_sha256: tagged(1201),
    repository: "PaulKov/dpone",
    repository_id: 1_255_975_556,
    runtime_oidc_rehearsal: {
      check_run_id: "1202",
      evidence_sha256: tagged(1203),
      jti_sha256: tagged(1204),
      repository_id: 1_255_975_556,
      workflow_sha: commitSha,
    },
    runtime_workflow_blob_sha: "a".repeat(40),
    runtime_workflow_path: ".github/workflows/runtime-image.yml",
    runtime_workflow_sha256: tagged(1205),
    tree_sha: "b".repeat(40),
  };
}

function decodeObject(bytes: Uint8Array): JsonObject {
  return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown);
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("compact v2 fixture object missing");
  }
  return value as JsonObject;
}

function tagged(index: number): string {
  return `sha256:${index.toString(16).padStart(64, "0")}`;
}

function longVersion(index: number): string {
  const prefix = `v${index}_`;
  return prefix + "x".repeat(512 - prefix.length);
}
