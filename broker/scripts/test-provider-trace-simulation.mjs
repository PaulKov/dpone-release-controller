const VERSION = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WORM_ROLES = Object.freeze(["ingress", "observer", "cloudflareObserver", "worm"]);
const PAIRED_AUTHORITIES = new Set([
  "dpone-release-authority-broker",
  "dpone-release-cloudflare-deployment-observer",
  "dpone-release-worm-mirror",
  "dpone-release-worm-version-observer",
]);

/**
 * Pure, data-only model of quarantined provider workflows.
 *
 * Inputs must be primitive JSON text. The model has no callback, filesystem,
 * subprocess, network, clock or provider-client capability.
 */
export function simulateVersionUpload(input) {
  const value = parseSimulationInput(input);
  requireVersionMetadata(value);
  if (PAIRED_AUTHORITIES.has(value.workerName)) {
    throw new Error("paired authority version requires the authority ceremony model");
  }
  return {
    operation: "VERSION_UPLOAD",
    trace: [
      "versions",
      "upload",
      "--strict",
      "--message",
      value.message,
      "--tag",
      value.tag,
      "--config",
      value.config,
    ],
  };
}

export function simulateVersionDeployment(input) {
  const value = parseSimulationInput(input);
  if (
    !VERSION.test(value.stable ?? "") ||
    !VERSION.test(value.candidate ?? "") ||
    value.stable === value.candidate ||
    !["stage", "promote", "rollback"].includes(value.operation)
  ) {
    throw new Error("deployment simulation input invalid");
  }
  const allocations =
    value.operation === "stage"
      ? [`${value.stable}@100%`, `${value.candidate}@0%`]
      : [`${value.operation === "promote" ? value.candidate : value.stable}@100%`];
  return {
    operation: "VERSION_DEPLOY",
    trace: [
      "versions",
      "deploy",
      ...allocations,
      "--yes",
      "--message",
      value.message,
      "--config",
      value.config,
    ],
  };
}

export function simulateGithubAppKeyProvision(input) {
  const value = parseSimulationInput(input);
  if (
    !/^sha256:[0-9a-f]{64}$/u.test(value.expectedFingerprint ?? "") ||
    value.actualFingerprint !== value.expectedFingerprint ||
    !VERSION.test(value.versionId ?? "") ||
    typeof value.config !== "string" ||
    typeof value.workerName !== "string"
  ) {
    throw new Error("GitHub App key simulation identity mismatch");
  }
  return {
    applied: true,
    fingerprint: value.actualFingerprint,
    operation: "VERSION_SECRET_PUT",
    secretName: "GITHUB_APP_PRIVATE_KEY",
    versionId: value.versionId,
    workerName: value.workerName,
  };
}

export function simulateCloudflareObserverTokenVerification(input) {
  const value = parseSimulationInput(input);
  const restriction = value.restriction;
  const providerPolicy = value.providerPolicy;
  const acceptedAtMs = Date.parse(value.acceptedAt);
  const observedAtMs = Date.parse(providerPolicy?.observed_at);
  if (
    restriction === null ||
    typeof restriction !== "object" ||
    providerPolicy === null ||
    typeof providerPolicy !== "object" ||
    !/^[0-9a-f]{32}$/u.test(restriction.account_id ?? "") ||
    !/^[0-9a-f]{32}$/u.test(restriction.zone_id ?? "") ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.tokenFingerprintSha256 ?? "") ||
    restriction.token_fingerprint_sha256 !== value.tokenFingerprintSha256 ||
    providerPolicy.account_id !== restriction.account_id ||
    providerPolicy.zone_id !== restriction.zone_id ||
    providerPolicy.token_fingerprint_sha256 !== value.tokenFingerprintSha256 ||
    JSON.stringify(providerPolicy.grants) !== JSON.stringify(restriction.grants) ||
    !/^sha256:[0-9a-f]{64}$/u.test(providerPolicy.provider_observation_sha256 ?? "") ||
    !Number.isFinite(acceptedAtMs) ||
    !Number.isFinite(observedAtMs) ||
    observedAtMs > acceptedAtMs ||
    acceptedAtMs - observedAtMs > 60_000
  ) {
    throw new Error("Cloudflare token provider policy simulation mismatch");
  }
  return {
    providerMutationPerformed: false,
    status: "READY_FOR_PAIRED_CEREMONY",
    tokenFingerprintSha256: value.tokenFingerprintSha256,
  };
}

export function simulateBootstrap(input) {
  const value = parseSimulationInput(input);
  const workers = requireExactRoles(value.workers, value.expectedRoles, "bootstrap");
  if (workers.at(-1)?.role !== "ingress") {
    throw new Error("bootstrap ingress must be the final deployment");
  }
  const versions = new Set();
  for (const worker of workers) {
    if (!VERSION.test(worker.versionId ?? "") || versions.has(worker.versionId)) {
      throw new Error("bootstrap immutable version identity invalid");
    }
    versions.add(worker.versionId);
    if (!Array.isArray(worker.secretNames) || worker.secretNames.length !== 0) {
      throw new Error("bootstrap version retained a secret");
    }
    if (worker.requeriedVersionId !== worker.versionId) {
      throw new Error("bootstrap provider requery mismatch");
    }
  }
  const denied = [...(value.deniedPaths ?? [])];
  if (
    value.livenessVersionId !== workers.at(-1).versionId ||
    denied.length < 1 ||
    new Set(denied).size !== denied.length
  ) {
    throw new Error("bootstrap deny smoke mismatch");
  }
  return {
    applied: true,
    bootstrapSecretAbsent: true,
    completedRoles: workers.map(({ role }) => role),
    deniedPaths: denied,
    ingressVersionId: workers.at(-1).versionId,
  };
}

export function simulateWormCeremony(input) {
  const value = parseSimulationInput(input);
  const events = value.events;
  if (!Array.isArray(events)) throw new Error("WORM simulation events missing");
  const completed = [];
  const absence = new Set();
  const versionIds = Object.fromEntries(WORM_ROLES.map((role) => [role, null]));
  const uploadCounts = Object.fromEntries(WORM_ROLES.map((role) => [role, 0]));
  const requeryOrder = [];
  let terminal = false;

  for (const event of events) {
    requireRole(event.role, event.kind);
    if (terminal) throw new Error("WORM event follows terminal state");
    if (event.kind === "ABSENCE") {
      requireNextRole(event.role, completed);
      if (absence.has(event.role)) throw new Error("duplicate WORM absence observation");
      if (
        !Number.isSafeInteger(event.listedVersionCount) ||
        event.listedVersionCount < 0 ||
        event.listedVersionCount >= 10 ||
        event.matchingVersionCount !== 0
      ) {
        throw new Error("WORM absence window is saturated or ambiguous");
      }
      absence.add(event.role);
      continue;
    }
    if (event.kind === "UPLOAD" || event.kind === "RECOVER_EXACT") {
      requireNextRole(event.role, completed);
      if (!absence.has(event.role) || !VERSION.test(event.versionId ?? "")) {
        throw new Error("WORM effect lacks durable absence or immutable identity");
      }
      if (event.kind === "RECOVER_EXACT" && event.matchingVersionCount !== 1) {
        throw new Error("WORM recovery version is ambiguous");
      }
      if (event.kind === "UPLOAD") uploadCounts[event.role] += 1;
      versionIds[event.role] = event.versionId;
      completed.push(event.role);
      continue;
    }
    if (event.kind === "REQUERY") {
      if (
        completed.length !== WORM_ROLES.length ||
        event.versionId !== versionIds[event.role] ||
        WORM_ROLES[requeryOrder.length] !== event.role
      ) {
        throw new Error("WORM terminal provider requery mismatch");
      }
      requeryOrder.push(event.role);
      continue;
    }
    if (event.kind === "TERMINAL") {
      if (requeryOrder.length !== WORM_ROLES.length || event.role !== "worm") {
        throw new Error("WORM terminal state lacks complete requery");
      }
      terminal = true;
      continue;
    }
    throw new Error("unknown WORM simulation event");
  }
  if (!terminal) throw new Error("WORM simulation did not reach terminal state");
  const accountId = value.accountId;
  if (!/^[0-9a-f]{32}$/u.test(accountId ?? "")) throw new Error("WORM account identity invalid");
  return {
    completedUploads: completed,
    expectedB2ObserverServiceIdentity: `cloudflare-worker:${accountId}/${value.observerWorkerName}@${versionIds.observer}`,
    requeryOrder,
    uploadCounts,
    versionIds,
  };
}

export function parseSimulationInput(source) {
  if (typeof source !== "string") {
    throw new Error("simulation input must be primitive JSON text");
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("simulation input must be exact JSON text");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("simulation input root must be one JSON object");
  }
  return value;
}

function requireVersionMetadata(value) {
  if (
    typeof value.config !== "string" ||
    typeof value.message !== "string" ||
    typeof value.tag !== "string" ||
    typeof value.workerName !== "string"
  ) {
    throw new Error("version upload simulation metadata missing");
  }
}

function requireExactRoles(workers, expectedRoles, name) {
  if (!Array.isArray(workers) || !Array.isArray(expectedRoles)) {
    throw new Error(`${name} role inventory missing`);
  }
  if (JSON.stringify(workers.map(({ role }) => role)) !== JSON.stringify(expectedRoles)) {
    throw new Error(`${name} role inventory mismatch`);
  }
  return workers;
}

function requireRole(role, kind) {
  if (!WORM_ROLES.includes(role)) throw new Error(`unknown WORM ${kind} role`);
}

function requireNextRole(role, completed) {
  if (WORM_ROLES[completed.length] !== role) throw new Error("WORM effect order mismatch");
}
