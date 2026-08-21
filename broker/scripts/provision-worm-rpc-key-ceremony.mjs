import { spawnSync } from "node:child_process";
import { closeSync } from "node:fs";

import { loadLiveWorkerConfig } from "./live-worker-config.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";
import { readTokenDocument as readCloudflareTokenDocument } from "./provision-cloudflare-deployment-observer-token.mjs";
import { parseArguments } from "./provision-worm-rpc-key-arguments.mjs";
import { SERVICE_NAMES } from "./provision-worm-rpc-key-constants.mjs";
import { taggedSha256 } from "./provision-worm-rpc-key-crypto.mjs";
import {
  adminPrincipalDigests,
  authoritySecretNames,
  readAdminPrincipalDocument,
  readB2SecretDocument,
  readCloudflareObserverRestriction,
  readPrivateFile,
  readRestrictionEvidence,
  validateAuthorityNetworkCrossBind,
  validateB2Config,
  validateCloudflareObserverConfig,
} from "./provision-worm-rpc-key-inputs.mjs";
import {
  appendJournalEntry,
  reserveResult,
  restoreRecoveredState,
} from "./provision-worm-rpc-key-journal.mjs";
import { requireUnusedVersionTag } from "./provision-worm-rpc-key-provider.mjs";
import {
  callerIdentity,
  ceremonyReport,
  initialCeremonyState,
  serviceIdentity,
} from "./provision-worm-rpc-key-report.mjs";
import {
  completeAuthorityUploads,
  emitRecoveredTerminal,
} from "./provision-worm-rpc-key-uploads.mjs";
import {
  validateBootstrapProvenance,
  validateInspectedConfig,
} from "./provision-worm-rpc-key-validation.mjs";

/**
 * Create one closed, undeployed final authority set.
 *
 * The ingress receives the WORM and ingress-to-observer RPC keys plus the
 * three Access principal secrets. The B2 observer remains read-only. The
 * Cloudflare observer receives the provider token and two separated RPC
 * keys. The WORM writer receives only its B2 writer credential plus WORM and
 * observer-to-WORM keys. Uploads are effect-ordered ingress -> B2 observer ->
 * Cloudflare observer -> WORM; immutable identities form a finite DAG without placeholder pins.
 */
export function runCeremonyCommand() {
  assertProviderMutationReleased("worm-authority-apply");
  const arguments_ = Object.freeze(process.argv.slice(2));
  const options = parseArguments(arguments_);
  if (!options.apply) return runCeremonyDryValidation(options);
  return runCeremony(options);
}

export function runCeremony(options) {
  assertProviderMutationReleased("worm-authority-apply");
  return runCeremonyEngine(options, {
    loadLiveWorkerConfig,
    now: Date.now,
    spawnSync,
    writeOutput: (value) => process.stdout.write(value),
  });
}

export function runCeremonyEngine(options, dependencies) {
  assertProviderMutationReleased("worm-authority-apply");
  return executeCeremony(options, dependencies);
}

/** Validate local ceremony inputs without provider calls or a durable result journal. */
function runCeremonyDryValidation(options) {
  if (options.apply) throw new Error("dry ceremony validation rejects apply options");
  return executeCeremony(options, {
    now: Date.now,
    writeOutput: (value) => process.stdout.write(value),
  });
}

function executeCeremony(options, dependencies) {
  const execute = options.apply
    ? requireEffectPort(dependencies, "spawnSync", "ceremony")
    : undefined;
  const inspectConfig = options.apply
    ? requireEffectPort(dependencies, "loadLiveWorkerConfig", "ceremony")
    : undefined;
  const now = requireEffectPort(dependencies, "now", "ceremony");
  const writeOutput = requireEffectPort(dependencies, "writeOutput", "ceremony");
  const rpcBytes = readPrivateFile(options.input, 32, 32, "WORM RPC key");
  const observerRpcBytes = readPrivateFile(
    options.cloudflareObserverRpcKey,
    32,
    32,
    "Cloudflare observer RPC key",
  );
  const evidenceRpcBytes = readPrivateFile(
    options.cloudflareEvidenceRpcKey,
    32,
    32,
    "Cloudflare evidence RPC key",
  );
  const cloudflareCredential = readCloudflareTokenDocument(options.cloudflareObserverToken);
  const adminPrincipals = readAdminPrincipalDocument(options.adminAccessPrincipals);
  const writer = readB2SecretDocument(options.writerSecret, "writer");
  const observer = readB2SecretDocument(options.observerSecret, "observer");
  let resultHandle = null;
  const state = initialCeremonyState();
  let journalSequence = 0;
  let previousJournalEntrySha256 = null;
  let finalJournalEntrySha256 = null;
  let recoveredAbsenceCount = 0;
  try {
    if (writer.keyId === observer.keyId || writer.applicationKey === observer.applicationKey) {
      throw new Error("B2 writer and observer credentials must be distinct");
    }
    if (
      rpcBytes.equals(observerRpcBytes) ||
      rpcBytes.equals(evidenceRpcBytes) ||
      observerRpcBytes.equals(evidenceRpcBytes)
    ) {
      throw new Error("authority RPC keys must be cryptographically separated");
    }
    const fingerprint = taggedSha256(rpcBytes);
    const observerRpcFingerprint = taggedSha256(observerRpcBytes);
    const evidenceRpcFingerprint = taggedSha256(evidenceRpcBytes);
    const encodedRpcKey = rpcBytes.toString("base64url");
    const encodedObserverRpcKey = observerRpcBytes.toString("base64url");
    const encodedEvidenceRpcKey = evidenceRpcBytes.toString("base64url");
    const writerRestriction = readRestrictionEvidence(
      options.writerRestrictionEvidence,
      "writer",
      writer.keyIdSha256,
    );
    const observerRestriction = readRestrictionEvidence(
      options.observerRestrictionEvidence,
      "observer",
      observer.keyIdSha256,
    );
    const restrictions = {
      cloudflare_observer: readCloudflareObserverRestriction(
        options,
        cloudflareCredential.token,
        now(),
      ),
      observer: observerRestriction,
      private_provider_requery_required: true,
      writer: writerRestriction,
    };
    const principalDigests = adminPrincipalDigests(adminPrincipals);
    let bootstrapProvenance = null;
    const serviceIdentities = {
      expectedB2ObserverServiceIdentity: null,
      expectedCallerServiceIdentity: null,
      expectedCloudflareObserverServiceIdentity: null,
    };

    if (options.apply) {
      const ingressConfig = inspectConfig(options.ingressConfig);
      const observerConfig = inspectConfig(options.observerConfig);
      const cloudflareObserverConfig = inspectConfig(options.cloudflareObserverConfig);
      const wormConfig = inspectConfig(options.wormConfig);
      validateInspectedConfig(ingressConfig, SERVICE_NAMES.ingress);
      validateInspectedConfig(observerConfig, SERVICE_NAMES.observer);
      validateInspectedConfig(cloudflareObserverConfig, SERVICE_NAMES.cloudflareObserver);
      validateInspectedConfig(wormConfig, SERVICE_NAMES.worm);
      validateB2Config(observerConfig.config, observerRestriction, "observer");
      validateB2Config(wormConfig.config, writerRestriction, "writer");
      validateCloudflareObserverConfig(
        cloudflareObserverConfig.config,
        restrictions.cloudflare_observer,
      );
      validateAuthorityNetworkCrossBind(ingressConfig.config, cloudflareObserverConfig.config);
      bootstrapProvenance = validateBootstrapProvenance(
        options.bootstrapReport,
        ingressConfig,
        observerConfig,
        cloudflareObserverConfig,
        wormConfig,
      );
      const reservation = reserveResult(
        options.result,
        options.recover,
        dependencies.afterJournalOpen,
      );
      resultHandle = reservation.handle;
      if (reservation.entries.length > 0) {
        restoreRecoveredState(
          reservation.entries,
          options,
          state,
          fingerprint,
          observerRpcFingerprint,
          evidenceRpcFingerprint,
          principalDigests,
          restrictions,
          bootstrapProvenance,
        );
        journalSequence = reservation.nextSequence;
        previousJournalEntrySha256 = reservation.previousEntrySha256;
        recoveredAbsenceCount = state.initial_absence_observations.length;
        serviceIdentities.expectedCallerServiceIdentity =
          state.version_ids.ingress === null
            ? null
            : callerIdentity(ingressConfig.config, state.version_ids.ingress);
        serviceIdentities.expectedCloudflareObserverServiceIdentity =
          state.version_ids.cloudflareObserver === null
            ? null
            : serviceIdentity(
                cloudflareObserverConfig.config,
                state.version_ids.cloudflareObserver,
                SERVICE_NAMES.cloudflareObserver,
              );
        serviceIdentities.expectedB2ObserverServiceIdentity =
          state.version_ids.observer === null
            ? null
            : serviceIdentity(
                observerConfig.config,
                state.version_ids.observer,
                SERVICE_NAMES.observer,
              );
      }
      const roleConfigs = {
        cloudflareObserver: cloudflareObserverConfig.config,
        ingress: ingressConfig.config,
        observer: observerConfig.config,
        worm: wormConfig.config,
      };
      const expectedSecrets = authoritySecretNames();
      if (reservation.terminal) {
        return emitRecoveredTerminal({
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
        });
      }
      persistHold();

      completeAuthorityUploads({
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
      });
    }

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
      options.apply ? "READY_FOR_PRIVATE_PREFLIGHT" : "VALIDATED",
    );
    if (resultHandle !== null) finalJournalEntrySha256 = persist(report);
    const output = `${JSON.stringify({
      ...report,
      result: options.result,
      result_sha256: finalJournalEntrySha256,
    })}\n`;
    writeOutput(output);
    return output;

    function persistHold() {
      if (resultHandle === null) return;
      persist(
        ceremonyReport(
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
          "HOLD",
        ),
      );
    }

    function ensureDurableAbsence(role, configPath, roleIndex) {
      if (state.initial_absence_observations.length === roleIndex) {
        state.initial_absence_observations.push(
          requireUnusedVersionTag(configPath, role, options, state.completed_uploads, execute),
        );
        persistHold();
      }
      return options.recover && roleIndex < recoveredAbsenceCount;
    }

    function persist(report) {
      const entry = {
        ...report,
        journal_sequence: journalSequence,
        previous_entry_sha256: previousJournalEntrySha256,
      };
      const digest = appendJournalEntry(resultHandle, entry, dependencies.journalIo);
      previousJournalEntrySha256 = digest;
      journalSequence += 1;
      return digest;
    }
  } finally {
    adminPrincipals.bytes.fill(0);
    cloudflareCredential.bytes.fill(0);
    evidenceRpcBytes.fill(0);
    observerRpcBytes.fill(0);
    rpcBytes.fill(0);
    writer.bytes.fill(0);
    observer.bytes.fill(0);
    if (resultHandle !== null) closeSync(resultHandle);
  }
}

function requireEffectPort(dependencies, name, boundary) {
  const value = dependencies?.[name];
  if (typeof value !== "function") throw new Error(`${boundary} effect port missing: ${name}`);
  return value;
}
