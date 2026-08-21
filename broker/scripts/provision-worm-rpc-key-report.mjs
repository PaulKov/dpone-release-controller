import { basename } from "node:path";

import { ACCOUNT_ID, SERVICE_NAMES, VERSION } from "./provision-worm-rpc-key-constants.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export function initialCeremonyState() {
  assertProviderMutationReleased("worm-authority-apply");
  return {
    completed_uploads: [],
    initial_absence_observations: [],
    provider_version_observations: [],
    recovery_observations: [],
    version_ids: { cloudflareObserver: null, ingress: null, observer: null, worm: null },
  };
}

export function ceremonyReport(
  options,
  state,
  fingerprint,
  observerRpcFingerprint,
  evidenceRpcFingerprint,
  principalDigests,
  restrictions,
  bootstrapProvenance,
  expectedCallerServiceIdentity,
  expectedCloudflareObserverServiceIdentity,
  expectedB2ObserverServiceIdentity,
  status,
) {
  assertProviderMutationReleased("worm-authority-apply");
  return {
    admin_access_principal_digests: principalDigests,
    applied: options.apply,
    bootstrap_provenance: bootstrapProvenance,
    cloudflare_evidence_rpc_key_fingerprint: evidenceRpcFingerprint,
    cloudflare_observer_config: basename(options.cloudflareObserverConfig),
    cloudflare_observer_expected_ingress_service_identity: expectedCallerServiceIdentity,
    cloudflare_observer_rpc_key_fingerprint: observerRpcFingerprint,
    cloudflare_observer_version_id: state.version_ids.cloudflareObserver,
    completed_uploads: [...state.completed_uploads],
    credential_restrictions: restrictions,
    initial_absence_observations: [...state.initial_absence_observations],
    ingress_config: basename(options.ingressConfig),
    ingress_upload_mode: "final-code-version-upload",
    ingress_version_id: state.version_ids.ingress,
    observer_config: basename(options.observerConfig),
    observer_version_id: state.version_ids.observer,
    private_provider_preflight_required: true,
    provider_version_observations: [...state.provider_version_observations],
    recovery_observations: [...state.recovery_observations],
    recovery_mode: options.recover,
    rpc_key_fingerprint: fingerprint,
    runtime_format: "base64url-256-bit",
    schema: "dpone.release-authority-version-ceremony.v1",
    schema_version: 1,
    status,
    version_message: options.versionMessage,
    version_tag: options.versionTag,
    worm_config: basename(options.wormConfig),
    worm_expected_b2_observer_service_identity: expectedB2ObserverServiceIdentity,
    worm_expected_caller_service_identity: expectedCallerServiceIdentity,
    worm_expected_cloudflare_observer_service_identity: expectedCloudflareObserverServiceIdentity,
    worm_version_id: state.version_ids.worm,
  };
}

export function callerIdentity(config, versionId) {
  assertProviderMutationReleased("worm-authority-apply");
  return serviceIdentity(config, versionId, SERVICE_NAMES.ingress);
}

export function serviceIdentity(config, versionId, expectedServiceName) {
  assertProviderMutationReleased("worm-authority-apply");
  const accountId = config.account_id;
  if (
    typeof accountId !== "string" ||
    !ACCOUNT_ID.test(accountId) ||
    config.name !== expectedServiceName ||
    !VERSION.test(versionId)
  ) {
    throw new Error("reviewed Worker account/version identity is invalid");
  }
  return `cloudflare-worker:${accountId}/${expectedServiceName}@${versionId}`;
}
