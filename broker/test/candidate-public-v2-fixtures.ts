import {
  buildUnpersistedActivatedCandidate,
  buildUnpersistedProvisionedCandidate,
  type BaselineSourceInput,
  type BrokerSourceInput,
  type ControllerSourceInput,
} from "../src/candidate-public-v2/activation-core";
import { buildUnpersistedActivationProofCandidate } from "../src/candidate-public-v2/activation-proof";
import { PUBLIC_PROJECTS, type DistributionInput } from "../src/candidate-public-v2/distributions";
import { buildUntrustedPublicArchive } from "../src/candidate-public-v2/public-archive";
import {
  buildUnpersistedRuntimeClosureCandidate,
  type ReleaseSourceInput,
} from "../src/candidate-public-v2/runtime-closure";
import { PRIVATE_PAYLOAD_SCHEMAS } from "../src/candidate-public-v2/sidecar";
import type { CandidateJsonObject, SidecarKind } from "../src/candidate-public-v2/types";

export const gitSha = (unit: string): string => unit.repeat(40);
export const digest = (unit: string): string => `sha256:${unit.repeat(64)}`;
export const nonce = (unit: number): Uint8Array => new Uint8Array(32).fill(unit);

export const BROKER_SOURCE: BrokerSourceInput = Object.freeze({
  commitSha: gitSha("1"),
  sourceSha256: digest("1"),
  treeSha: gitSha("2"),
});

export const CONTROLLER_SOURCE: ControllerSourceInput = Object.freeze({
  actionBundle: Object.freeze({
    bundleSha256: digest("2"),
    commitSha: gitSha("3"),
    metadataBlobSha: gitSha("4"),
  }),
  commitSha: gitSha("5"),
  defaultBranchWorkflowBlobSha: gitSha("6"),
  tagObjectSha: gitSha("7"),
  tagRef: "refs/tags/v1.2.3",
  treeSha: gitSha("8"),
  workflowBlobSha: gitSha("9"),
  workflowSha256: digest("3"),
});

export const BASELINE_SOURCE: BaselineSourceInput = Object.freeze({
  baselineCommitSha: gitSha("a"),
  baselineTreeSha: gitSha("b"),
  policyBlobSha: gitSha("c"),
  policySha256: digest("4"),
  runtimeWorkflowBlobSha: gitSha("d"),
  runtimeWorkflowSha256: digest("5"),
});

export function privatePayload(kind: SidecarKind): CandidateJsonObject {
  return {
    private_canary: `must-never-be-public-${kind}`,
    schema: PRIVATE_PAYLOAD_SCHEMAS[kind],
  };
}

export function distributionInputs(): DistributionInput[] {
  const version = "1.2.3";
  const normalized = [
    "apache_airflow_providers_dpone",
    "dpone",
    "dpone_airflow_pack",
    "dpone_native_accel",
  ];
  return PUBLIC_PROJECTS.flatMap((project, index) => {
    const stem = normalized[index];
    if (stem === undefined) throw new Error("fixture project index");
    return [
      {
        filename: `${stem}-${version}-py3-none-any.whl`,
        project,
        sha256: digest(String(index + 6)),
        sizeBytes: 1_000 + index,
        version,
      },
      {
        filename: `${stem}-${version}.tar.gz`,
        project,
        sha256: digest(String(index + 6)),
        sizeBytes: 2_000 + index,
        version,
      },
    ];
  });
}

export function releaseSource(
  peeledCommitSha = BASELINE_SOURCE.baselineCommitSha,
): ReleaseSourceInput {
  return {
    peeledCommitSha,
    policyBlobSha: BASELINE_SOURCE.policyBlobSha,
    policySha256: BASELINE_SOURCE.policySha256,
    runtimeWorkflowBlobSha: BASELINE_SOURCE.runtimeWorkflowBlobSha,
    runtimeWorkflowSha256: BASELINE_SOURCE.runtimeWorkflowSha256,
    tag: "v1.2.3",
    tagObjectSha: gitSha("e"),
  };
}

export async function buildFullCandidate(peeledCommitSha = BASELINE_SOURCE.baselineCommitSha) {
  const provisioned = await buildUnpersistedProvisionedCandidate({
    brokerSource: BROKER_SOURCE,
    controllerSource: CONTROLLER_SOURCE,
    nonce: nonce(1),
    privatePayload: privatePayload("ACTIVATION_A0"),
  });
  const activated = await buildUnpersistedActivatedCandidate({
    baselineSource: BASELINE_SOURCE,
    nonce: nonce(2),
    privatePayload: privatePayload("ACTIVATION_A1"),
    provisioned: provisioned.document,
  });
  const proof = await buildUnpersistedActivationProofCandidate({
    activated: activated.document,
    clock: { nowMs: () => 1_700_000_000_999 },
    nonce: nonce(3),
    privatePayload: privatePayload("ACTIVATION_PROOF"),
    provisioned: provisioned.document,
  });
  const closure = await buildUnpersistedRuntimeClosureCandidate({
    activated: activated.document,
    distributions: distributionInputs(),
    nonce: nonce(4),
    privatePayload: privatePayload("RUNTIME_CLOSURE"),
    provisioned: provisioned.document,
    release: releaseSource(peeledCommitSha),
  });
  const archive = await buildUntrustedPublicArchive({
    activated: activated.documentBytes,
    closure: closure.documentBytes,
    provisioned: provisioned.documentBytes,
  });
  return { activated, archive, closure, proof, provisioned };
}
