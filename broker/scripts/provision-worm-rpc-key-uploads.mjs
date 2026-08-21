import { ROLE_ORDER, SERVICE_NAMES } from "./provision-worm-rpc-key-constants.mjs";
import { ceremonyVariableOverrides } from "./provision-worm-rpc-key-inputs.mjs";
import {
  discoverRecoverableVersion,
  requeryVersion,
  uploadFinalVersion,
} from "./provision-worm-rpc-key-provider.mjs";
import {
  callerIdentity,
  ceremonyReport,
  serviceIdentity,
} from "./provision-worm-rpc-key-report.mjs";

export function emitRecoveredTerminal({
  bootstrapProvenance,
  evidenceRpcFingerprint,
  execute,
  expectedSecrets,
  fingerprint,
  observerRpcFingerprint,
  options,
  principalDigests,
  reservation,
  restrictions,
  roleConfigs,
  serviceIdentities,
  state,
  writeOutput,
}) {
  state.provider_version_observations = ROLE_ORDER.map((role) =>
    requeryVersion(
      options[role + "Config"],
      state.version_ids[role],
      role,
      options,
      roleConfigs[role],
      expectedSecrets[role],
      ceremonyVariableOverrides(
        role,
        serviceIdentities.expectedCallerServiceIdentity,
        serviceIdentities.expectedCloudflareObserverServiceIdentity,
        serviceIdentities.expectedB2ObserverServiceIdentity,
      ),
      execute,
    ),
  );
  const report = ceremonyReport(
    options,
    state,
    fingerprint,
    observerRpcFingerprint,
    evidenceRpcFingerprint,
    principalDigests,
    restrictions,
    bootstrapProvenance,
    serviceIdentities.expectedCallerServiceIdentity,
    serviceIdentities.expectedCloudflareObserverServiceIdentity,
    serviceIdentities.expectedB2ObserverServiceIdentity,
    "READY_FOR_PRIVATE_PREFLIGHT",
  );
  const output =
    JSON.stringify({
      ...report,
      result: options.result,
      result_sha256: reservation.previousEntrySha256,
      terminal_requery_confirmed: true,
    }) + "\n";
  writeOutput(output);
  return output;
}

export function completeAuthorityUploads({
  adminPrincipals,
  cloudflareCredential,
  cloudflareObserverConfig,
  encodedEvidenceRpcKey,
  encodedObserverRpcKey,
  encodedRpcKey,
  ensureDurableAbsence,
  execute,
  expectedSecrets,
  ingressConfig,
  observer,
  observerConfig,
  options,
  persistHold,
  roleConfigs,
  serviceIdentities,
  state,
  wormConfig,
  writer,
}) {
  if (!state.completed_uploads.includes("ingress")) {
    const mayRecover = ensureDurableAbsence("ingress", options.ingressConfig, 0);
    const recovered = mayRecover
      ? discoverRecoverableVersion(
          options.ingressConfig,
          "ingress",
          options,
          ingressConfig.config,
          expectedSecrets.ingress,
          {},
          execute,
        )
      : null;
    if (recovered !== null) state.recovery_observations.push(recovered.observation);
    state.version_ids.ingress =
      recovered?.versionId ??
      uploadFinalVersion(
        options.ingressConfig,
        {
          ADMIN_ACCESS_GROUP: adminPrincipals.accessGroup,
          ADMIN_ACCESS_IDENTITY: adminPrincipals.accessIdentity,
          ADMIN_ACCESS_SUBJECT_ID: adminPrincipals.accessSubjectId,
          CLOUDFLARE_OBSERVER_RPC_AUTH_KEY: encodedObserverRpcKey,
          WORM_RPC_AUTH_KEY: encodedRpcKey,
        },
        [],
        options,
        "ingress",
        execute,
      );
    state.completed_uploads.push("ingress");
  }
  serviceIdentities.expectedCallerServiceIdentity = callerIdentity(
    ingressConfig.config,
    state.version_ids.ingress,
  );
  persistHold();

  if (!state.completed_uploads.includes("observer")) {
    const mayRecover = ensureDurableAbsence("observer", options.observerConfig, 1);
    const recovered = mayRecover
      ? discoverRecoverableVersion(
          options.observerConfig,
          "observer",
          options,
          observerConfig.config,
          ["B2_APPLICATION_KEY", "B2_KEY_ID"],
          {},
          execute,
        )
      : null;
    if (recovered !== null) state.recovery_observations.push(recovered.observation);
    state.version_ids.observer =
      recovered?.versionId ??
      uploadFinalVersion(
        options.observerConfig,
        {
          B2_APPLICATION_KEY: observer.applicationKey,
          B2_KEY_ID: observer.keyId,
        },
        [],
        options,
        "observer",
        execute,
      );
    state.completed_uploads.push("observer");
  }
  serviceIdentities.expectedB2ObserverServiceIdentity = serviceIdentity(
    observerConfig.config,
    state.version_ids.observer,
    SERVICE_NAMES.observer,
  );
  persistHold();

  if (!state.completed_uploads.includes("cloudflareObserver")) {
    const mayRecover = ensureDurableAbsence(
      "cloudflareObserver",
      options.cloudflareObserverConfig,
      2,
    );
    const overrides = ceremonyVariableOverrides(
      "cloudflareObserver",
      serviceIdentities.expectedCallerServiceIdentity,
      null,
      null,
    );
    const recovered = mayRecover
      ? discoverRecoverableVersion(
          options.cloudflareObserverConfig,
          "cloudflareObserver",
          options,
          cloudflareObserverConfig.config,
          expectedSecrets.cloudflareObserver,
          overrides,
          execute,
        )
      : null;
    if (recovered !== null) state.recovery_observations.push(recovered.observation);
    state.version_ids.cloudflareObserver =
      recovered?.versionId ??
      uploadFinalVersion(
        options.cloudflareObserverConfig,
        {
          CLOUDFLARE_API_TOKEN: cloudflareCredential.token,
          CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: encodedEvidenceRpcKey,
          CLOUDFLARE_OBSERVER_RPC_AUTH_KEY: encodedObserverRpcKey,
        },
        [
          "--var",
          `EXPECTED_INGRESS_SERVICE_IDENTITY:${serviceIdentities.expectedCallerServiceIdentity}`,
        ],
        options,
        "Cloudflare observer",
        execute,
      );
    state.completed_uploads.push("cloudflareObserver");
  }
  serviceIdentities.expectedCloudflareObserverServiceIdentity = serviceIdentity(
    cloudflareObserverConfig.config,
    state.version_ids.cloudflareObserver,
    SERVICE_NAMES.cloudflareObserver,
  );
  persistHold();

  if (!state.completed_uploads.includes("worm")) {
    const mayRecover = ensureDurableAbsence("worm", options.wormConfig, 3);
    const overrides = ceremonyVariableOverrides(
      "worm",
      serviceIdentities.expectedCallerServiceIdentity,
      serviceIdentities.expectedCloudflareObserverServiceIdentity,
      serviceIdentities.expectedB2ObserverServiceIdentity,
    );
    const recovered = mayRecover
      ? discoverRecoverableVersion(
          options.wormConfig,
          "worm",
          options,
          wormConfig.config,
          expectedSecrets.worm,
          overrides,
          execute,
        )
      : null;
    if (recovered !== null) state.recovery_observations.push(recovered.observation);
    state.version_ids.worm =
      recovered?.versionId ??
      uploadFinalVersion(
        options.wormConfig,
        {
          B2_APPLICATION_KEY: writer.applicationKey,
          B2_KEY_ID: writer.keyId,
          CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: encodedEvidenceRpcKey,
          WORM_RPC_AUTH_KEY: encodedRpcKey,
        },
        [
          "--var",
          `WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY:${serviceIdentities.expectedB2ObserverServiceIdentity}`,
          "--var",
          `WORM_EXPECTED_CALLER_SERVICE_IDENTITY:${serviceIdentities.expectedCallerServiceIdentity}`,
          "--var",
          `WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY:${serviceIdentities.expectedCloudflareObserverServiceIdentity}`,
        ],
        options,
        "WORM",
        execute,
      );
    state.completed_uploads.push("worm");
  }
  persistHold();

  state.provider_version_observations = [];
  persistHold();
  for (const role of ROLE_ORDER) {
    state.provider_version_observations.push(
      requeryVersion(
        options[`${role}Config`],
        state.version_ids[role],
        role,
        options,
        roleConfigs[role],
        expectedSecrets[role],
        ceremonyVariableOverrides(
          role,
          serviceIdentities.expectedCallerServiceIdentity,
          serviceIdentities.expectedCloudflareObserverServiceIdentity,
          serviceIdentities.expectedB2ObserverServiceIdentity,
        ),
        execute,
      ),
    );
    persistHold();
  }
}
