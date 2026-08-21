import type { ActivationRegistry } from "./activation-registry";
import type { AuthReplayLedger } from "./auth-replay-ledger";
import type { GlobalActivatedAuthorityHead } from "./global-activated-authority-head";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
declare const JSON_OBJECT_TYPE: unique symbol;

/** Structural JSON mapping distinguished from arrays without adding runtime data. */
export interface JsonObject extends Record<string, JsonValue> {
  readonly [JSON_OBJECT_TYPE]?: never;
}

export interface LiveConfigEnv {
  ATTESTATION_MUTATOR?: Fetcher;
  CANDIDATE_READER?: Fetcher;
  CLOSED_PROJECTOR?: Fetcher;
  CLOUDFLARE_DEPLOYMENT_OBSERVER?: Fetcher;
  CONTROLLER_RUN_READER?: Fetcher;
  GOVERNANCE_READER?: Fetcher;
  GLOBAL_ACTIVATED_AUTHORITY_HEAD?: DurableObjectNamespace<GlobalActivatedAuthorityHead>;
  PYPI_DEPLOYMENT_GATE?: Fetcher;
  PYPI_READER?: Fetcher;
  RELEASE_MUTATOR?: Fetcher;
  RUNTIME_DEPLOYMENT_GATE?: Fetcher;
  TENANT_SCANNER?: Fetcher;
  WORM_MIRROR?: Fetcher;
  WORM_VERSION_OBSERVER?: Fetcher;
  CF_VERSION_METADATA?: WorkerVersionMetadata;
  CF_ACCOUNT_ID?: string;
  CLOUDFLARE_OBSERVER_RPC_AUTH_KEY?: string;
  BROKER_SERVICE_NAME?: string;
  OPERATING_MODE: string;
  WORM_RPC_AUTH_KEY?: string;
  ADMIN_MTLS_CERT_SHA256?: string;
  ADMIN_ACCESS_AUDIENCE?: string;
  ADMIN_ACCESS_GROUP?: string;
  ADMIN_ACCESS_IDENTITY?: string;
  ADMIN_ACCESS_ISSUER?: string;
  ADMIN_ACCESS_SUBJECT_ID?: string;
  ADMIN_ACCESS_APPLICATION_ID?: string;
  ADMIN_ACCESS_POLICY_ID?: string;
  ADMIN_HOSTNAME?: string;
  AUTH_REPLAY_LEDGER?: DurableObjectNamespace<AuthReplayLedger>;
}

export interface Env extends LiveConfigEnv {
  ACTIVATION_REGISTRY: DurableObjectNamespace<ActivationRegistry>;
  AUTH_REPLAY_LEDGER: DurableObjectNamespace<AuthReplayLedger>;
  GLOBAL_ACTIVATED_AUTHORITY_HEAD: DurableObjectNamespace<GlobalActivatedAuthorityHead>;
  RELEASE_LEDGERS: DurableObjectNamespace;
}

/** Stable admin/account commitments required for confidential A0 semantic validation. */
export interface ActivationAdminSemanticTrust {
  readonly cloudflareAccountId: string;
  readonly adminAccessApplicationId: string;
  readonly adminAccessAudience: string;
  readonly adminAccessGroup: string;
  readonly adminAccessIdentity: string;
  readonly adminAccessIssuer: string;
  readonly adminAccessPolicyId: string;
  readonly adminAccessSubjectId: string;
  readonly adminHostname: string;
  readonly adminMtlsCertSha256: string;
}

/** Historical ingress identity added to the stable semantic trust projection. */
export interface ActivationComponentSemanticTrust extends ActivationAdminSemanticTrust {
  readonly workerVersionId: string;
  readonly workerServiceIdentity: string;
}

export interface TrustedRuntimeConfig extends ActivationComponentSemanticTrust {
  readonly cloudflareObserverRpcAuthKey: string;
  readonly wormRpcAuthKey: string;
}

export interface AuthenticatedWorkflow {
  readonly actorId: string;
  readonly audience: string;
  readonly checkRunId: string;
  readonly environment: string;
  readonly expiresAt: number;
  readonly issuedAt: number;
  readonly jti: string;
  readonly notBefore: number;
  readonly ref: string;
  readonly repository: string;
  readonly repositoryId: number;
  readonly repositoryOwnerId: string;
  readonly runAttempt: number;
  readonly runId: string;
  readonly sha: string;
  readonly subject: string;
  readonly workflowRef: string;
  readonly workflowSha: string;
}

export interface OidcRouteTrust {
  readonly allowedActorIds: ReadonlySet<string>;
  readonly audience: string;
  readonly environment: string;
  readonly eventName: "push" | "workflow_dispatch";
  readonly ref: string;
  readonly refType: "tag";
  readonly repository: string;
  readonly repositoryId: number;
  readonly repositoryOwnerId: string;
  readonly repositoryVisibility: "public";
  readonly workflowPath: string;
  readonly workflowSha: string;
}

export interface ActivationWorm {
  readonly digest: string;
  readonly key: string;
  readonly retentionUntil: string;
  readonly versionId: string;
}

export interface ActivationRecordView {
  readonly digest: string;
  readonly envelope: JsonObject;
  readonly recordId: string;
  readonly sequence: 0 | 1;
  readonly worm: ActivationWorm;
}

export interface ActivationSnapshot {
  readonly activated: ActivationRecordView | null;
  readonly provisioned: ActivationRecordView;
}

export interface ControllerActivationTrust {
  readonly controllerActionBundleSha256: string;
  readonly controllerActionCommitSha: string;
  readonly controllerActionMetadataBlobSha: string;
  readonly controllerActorIds: ReadonlySet<string>;
  readonly controllerDefaultBranchWorkflowBlobSha: string;
  readonly controllerWorkflowBlobSha: string;
  readonly controllerWorkflowId: number;
  readonly controllerRef: string;
  readonly controllerRefType: "tag";
  readonly controllerTagObjectSha: string;
  readonly controllerWorkflowRef: string;
  readonly controllerWorkflowSha: string;
  readonly controllerRunReaderApp: GitHubAppPin;
  readonly provisionedDigest: string;
  readonly provisionedRecordId: string;
  readonly privateServices: {
    readonly attestationMutator: PrivateServicePin;
    readonly candidateReader: PrivateServicePin;
    readonly closedProjector: PrivateServicePin;
    readonly cloudflareDeploymentObserver: PrivateServicePin;
    readonly controllerRunReader: PrivateServicePin;
    readonly governanceReader: PrivateServicePin;
    readonly pypiDeploymentGate: PrivateServicePin;
    readonly pypiReader: PrivateServicePin;
    readonly releaseMutator: PrivateServicePin;
    readonly runtimeDeploymentGate: PrivateServicePin;
    readonly tenantScanner: PrivateServicePin;
    readonly wormMirror: PrivateServicePin;
    readonly wormVersionObserver: PrivateServicePin;
  };
  readonly repositoryOwnerId: string;
  readonly workerVersionId: string;
}

export interface GitHubAppPin {
  readonly appId: string;
  readonly appSlug: string;
  readonly installationId: string;
}

export interface PrivateServicePin {
  readonly serviceIdentity: string;
  readonly serviceName: string;
  readonly versionId: string;
}

export interface ActivationTrust extends ControllerActivationTrust {
  readonly activatedDigest: string;
  readonly activatedRecordId: string;
  readonly runtimeActorIds: ReadonlySet<string>;
  readonly targetBranchRulesetEvidenceSha256: string;
  readonly targetBranchRulesetId: string;
  readonly targetBranchRulesetProjectionSha256: string;
  readonly targetDefaultBranchRef: string;
  readonly targetPolicyBlobSha: string;
  readonly targetPolicySha256: string;
  readonly targetPolicyCommitSha: string;
  readonly targetRuntimeWorkflowBlobSha: string;
  readonly targetRuntimeWorkflowSha256: string;
}

export interface ReleaseBinding {
  readonly attemptId: string;
  readonly candidateArtifactDigest: string;
  readonly candidateArtifactId: number;
  readonly candidateId: string;
  readonly candidateInventorySha256: string;
  readonly candidateManifestDigest: string;
  readonly candidateRunAttempt: number;
  readonly candidateRunId: number;
  readonly controllerRepoId: number;
  readonly controllerWorkflowId: number;
  readonly controllerWorkflowSha: string;
  readonly peeledCommitSha: string;
  readonly policySha256: string;
  readonly releaseAuthorityId: string;
  readonly releaseIdentityId: string;
  readonly runAttempt: number;
  readonly runId: number;
  readonly tag: string;
  readonly tagObjectSha: string;
  readonly tagRef: string;
  readonly targetRepoId: number;
}

export interface InternalRequest<TBody extends JsonObject = JsonObject> {
  readonly auth: AuthenticatedWorkflow;
  readonly binding: ReleaseBinding;
  readonly body: TBody;
  readonly requestId: string;
  readonly route: string;
}

export interface MirrorResult {
  readonly digest: string;
  readonly identicalVersionIds: readonly string[];
  readonly inventoryDigest: string;
  readonly key: string;
  readonly retentionUntil: string;
  readonly versionId: string;
}

export interface Clock {
  now(): number;
}

export const systemClock: Clock = {
  now: () => Date.now(),
};
