import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, statSync } from "node:fs";

import { provisionAuthorityKeysForTest as provisionAuthorityKeys } from "./test-worm-rpc-key-engine.mjs";
import { canonicalWorkerVersionResourceProjectionBytes } from "./worker-version-resources.mjs";
import { runBootstrapReportTopologyNegatives } from "./test-worm-rpc-key-bootstrap-negatives.mjs";
import {
  canonicalBootstrapReport,
  cloudflarePolicyEvidence,
  cloudflareRestrictionEvidence,
  restrictionEvidence,
  versionResources,
} from "./test-worm-rpc-key-evidence-fixtures.mjs";
import {
  ACCOUNT_ID,
  CLOUDFLARE_TOKEN,
  EVIDENCE_RPC_KEY,
  OBSERVER,
  OBSERVER_RPC_KEY,
  ROLES,
  RPC_KEY,
  VERSION_IDS,
  WRITER,
  argumentsFor,
  canonicalBytes,
  cloneJson,
  configs,
  dependencies,
  exactRead,
  parseJournal,
  paths,
  root,
  taggedSha256,
  temporaryDirectory,
  writePrivate,
} from "./test-worm-rpc-key-fixtures.mjs";
import { assertB2ObserverCeremonyPin } from "./test-worm-rpc-key-observer-pin.mjs";
import { runProvisioningFailureScenarios } from "./test-worm-rpc-key-provisioning-failure-scenarios.mjs";

/** Exercise dry validation, fail-closed provenance, and the exact four-version ceremony. */
export function runProvisioningScenarios() {
  writeCeremonyInputs();
  assertDryValidation();

  const bootstrapReport = canonicalBootstrapReport();
  writePrivate(paths.bootstrap, canonicalBytes(bootstrapReport));
  runBootstrapReportTopologyNegatives(bootstrapReport);
  assertProvenanceFailures(bootstrapReport);
  assertSuccessfulProvisioning();
  runProvisioningFailureScenarios();
}

function writeCeremonyInputs() {
  writePrivate(
    paths.adminPrincipals,
    canonicalBytes({
      access_group: "release-authority-admins",
      access_identity: "release-admin@example.test",
      access_subject_id: "123e4567-e89b-42d3-a456-426614174099",
    }),
  );
  writePrivate(paths.cloudflareEvidenceRpc, EVIDENCE_RPC_KEY);
  writePrivate(paths.cloudflareObserverRpc, OBSERVER_RPC_KEY);
  writePrivate(paths.cloudflareObserverToken, canonicalBytes({ api_token: CLOUDFLARE_TOKEN }));
  writePrivate(
    paths.cloudflareObserverRestriction,
    canonicalBytes(cloudflareRestrictionEvidence()),
  );
  writePrivate(paths.cloudflareObserverPolicy, canonicalBytes(cloudflarePolicyEvidence()));
  writePrivate(paths.rpc, RPC_KEY);
  writePrivate(paths.writerSecret, canonicalBytes(WRITER));
  writePrivate(paths.observerSecret, canonicalBytes(OBSERVER));
  writePrivate(paths.writerEvidence, canonicalBytes(restrictionEvidence("writer", WRITER.key_id)));
  writePrivate(
    paths.observerEvidence,
    canonicalBytes(restrictionEvidence("observer", OBSERVER.key_id)),
  );
}

function assertDryValidation() {
  const dry = spawnSync(process.execPath, argumentsFor(false), {
    cwd: root.pathname,
    encoding: "utf8",
    maxBuffer: 65_536,
  });
  assert.equal(dry.status, 0, dry.stderr);
  const report = JSON.parse(dry.stdout);
  assert.equal(report.status, "VALIDATED");
  assert.equal(report.applied, false);
  assert.equal(report.rpc_key_fingerprint, taggedSha256(RPC_KEY));
  assert.deepEqual(report.completed_uploads, []);
  assert.equal(report.ingress_version_id, null);
  assert.equal(report.observer_version_id, null);
  assert.equal(report.worm_version_id, null);
  assert.equal(report.result, null);
  assert.equal(report.result_sha256, null);
  assert.equal(dry.stdout.includes(WRITER.application_key), false);
  assert.equal(dry.stdout.includes(OBSERVER.application_key), false);
}

function assertProvenanceFailures(bootstrapReport) {
  let effectsBeforeProvenanceFailure = 0;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, `${temporaryDirectory}/drift-hold.json`).slice(1), {
        ...dependencies(),
        readFileSync: (path) =>
          path === configs.ingress.live.pathname
            ? Buffer.from("drifted ingress config\n", "utf8")
            : exactRead(path),
        spawnSync: () => {
          effectsBeforeProvenanceFailure += 1;
          throw new Error("effect must not start before provenance validation");
        },
      }),
    /current final Worker bytes differ from bootstrap provenance/u,
  );
  assert.equal(effectsBeforeProvenanceFailure, 0);

  const finalMainBootstrap = cloneJson(bootstrapReport);
  finalMainBootstrap.provider_observations.find(
    (item) => item.name === configs.ingress.name,
  ).bootstrap_main = "src/index.ts";
  writePrivate(paths.bootstrap, canonicalBytes(finalMainBootstrap));
  assert.throws(
    () =>
      provisionAuthorityKeys(
        argumentsFor(true, `${temporaryDirectory}/final-main-hold.json`).slice(1),
        {
          ...dependencies(),
          spawnSync: () => {
            throw new Error("effect must not start with final main disguised as bootstrap");
          },
        },
      ),
    /current final Worker bytes differ from bootstrap provenance/u,
  );

  const retainedBootstrapSecret = cloneJson(bootstrapReport);
  const retainedIngress = retainedBootstrapSecret.provider_observations.find(
    (item) => item.name === configs.ingress.name,
  );
  retainedIngress.binding_projection.secret_names = ["WORM_RPC_AUTH_KEY"];
  retainedIngress.binding_projection_sha256 = taggedSha256(
    canonicalWorkerVersionResourceProjectionBytes(retainedIngress.binding_projection),
  );
  writePrivate(paths.bootstrap, canonicalBytes(retainedBootstrapSecret));
  assert.throws(
    () =>
      provisionAuthorityKeys(
        argumentsFor(true, `${temporaryDirectory}/retained-bootstrap-secret-hold.json`).slice(1),
        {
          ...dependencies(),
          spawnSync: () => {
            throw new Error("effect must not start with retained bootstrap secret");
          },
        },
      ),
    /does not prove exact credential-free provider versions/u,
  );
  writePrivate(paths.bootstrap, canonicalBytes(bootstrapReport));

  chmodSync(paths.bootstrap, 0o644);
  assert.throws(
    () =>
      provisionAuthorityKeys(
        argumentsFor(true, `${temporaryDirectory}/public-hold.json`).slice(1),
        {
          ...dependencies(),
          spawnSync: () => {
            throw new Error("effect must not start with a public bootstrap report");
          },
        },
      ),
    /bootstrap report must be an exact mode-0600 regular file/u,
  );
  chmodSync(paths.bootstrap, 0o600);
}

function assertSuccessfulProvisioning() {
  const calls = [];
  const secretsPaths = [];
  const output = [];
  let uploadIndex = 0;
  provisionAuthorityKeys(argumentsFor(true, paths.result).slice(1), {
    ...dependencies(),
    spawnSync: (executable, arguments_) => {
      const command = arguments_.slice(1, 3).join(" ");
      if (command === "versions list") return { status: 0, stdout: "[]" };
      if (command === "versions upload") {
        const role = ROLES[uploadIndex];
        const versionId = VERSION_IDS[role];
        const secretsPath = arguments_[arguments_.indexOf("--secrets-file") + 1];
        const secrets = JSON.parse(readFileSync(secretsPath, "utf8"));
        assert.equal(statSync(secretsPath).mode & 0o777, 0o600);
        secretsPaths.push(secretsPath);
        calls.push({ arguments_, executable, role, secrets });
        uploadIndex += 1;
        return { status: 0, stdout: `Worker Version ID: ${versionId}\n` };
      }
      assert.equal(command, "versions view");
      const versionId = arguments_[3];
      const role = Object.entries(VERSION_IDS).find(([, value]) => value === versionId)?.[0];
      assert.ok(role !== undefined);
      return {
        status: 0,
        stdout: JSON.stringify({
          annotations: {
            "workers/message": "reviewed authority key ceremony",
            "workers/tag": "authority-keys-test-v1",
          },
          id: versionId,
          metadata: { created_on: "2026-08-19T10:00:00.000Z" },
          resources: versionResources(role),
        }),
      };
    },
    writeOutput: (value) => output.push(value),
  });

  assert.deepEqual(
    calls.map(({ role }) => role),
    ROLES,
  );
  assert.deepEqual(calls[0].secrets, {
    ADMIN_ACCESS_GROUP: "release-authority-admins",
    ADMIN_ACCESS_IDENTITY: "release-admin@example.test",
    ADMIN_ACCESS_SUBJECT_ID: "123e4567-e89b-42d3-a456-426614174099",
    CLOUDFLARE_OBSERVER_RPC_AUTH_KEY: OBSERVER_RPC_KEY.toString("base64url"),
    WORM_RPC_AUTH_KEY: RPC_KEY.toString("base64url"),
  });
  assert.deepEqual(calls[1].secrets, {
    B2_APPLICATION_KEY: OBSERVER.application_key,
    B2_KEY_ID: OBSERVER.key_id,
  });
  assert.deepEqual(calls[2].secrets, {
    CLOUDFLARE_API_TOKEN: CLOUDFLARE_TOKEN,
    CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: EVIDENCE_RPC_KEY.toString("base64url"),
    CLOUDFLARE_OBSERVER_RPC_AUTH_KEY: OBSERVER_RPC_KEY.toString("base64url"),
  });
  assert.deepEqual(calls[3].secrets, {
    B2_APPLICATION_KEY: WRITER.application_key,
    B2_KEY_ID: WRITER.key_id,
    CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY: EVIDENCE_RPC_KEY.toString("base64url"),
    WORM_RPC_AUTH_KEY: RPC_KEY.toString("base64url"),
  });
  assert.equal(calls[0].arguments_.includes("B2_APPLICATION_KEY"), false);
  assert.equal(calls[1].arguments_.includes("WORM_RPC_AUTH_KEY"), false);
  assert.equal(
    calls[3].arguments_.includes(
      `WORM_EXPECTED_CALLER_SERVICE_IDENTITY:cloudflare-worker:${ACCOUNT_ID}/` +
        `dpone-release-authority-broker@${VERSION_IDS.ingress}`,
    ),
    true,
  );
  assert.equal(
    calls[2].arguments_.includes(
      `EXPECTED_INGRESS_SERVICE_IDENTITY:cloudflare-worker:${ACCOUNT_ID}/` +
        `dpone-release-authority-broker@${VERSION_IDS.ingress}`,
    ),
    true,
  );
  assert.equal(
    calls[3].arguments_.includes(
      `WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY:cloudflare-worker:${ACCOUNT_ID}/` +
        `dpone-release-cloudflare-deployment-observer@${VERSION_IDS.cloudflareObserver}`,
    ),
    true,
  );
  for (const call of calls) assert.equal(call.arguments_.includes("deploy"), false);
  assert.equal(new Set(secretsPaths).size, ROLES.length);
  for (const path of secretsPaths) assert.equal(existsSync(path), false);

  assertSuccessfulReport(JSON.parse(output[0]), output[0], calls);
}

function assertSuccessfulReport(applied, output, calls) {
  assert.equal(applied.status, "READY_FOR_PRIVATE_PREFLIGHT");
  assert.deepEqual(applied.completed_uploads, ROLES);
  assert.equal(applied.provider_version_observations.length, ROLES.length);
  assert.equal(applied.cloudflare_observer_version_id, VERSION_IDS.cloudflareObserver);
  assert.equal(applied.ingress_version_id, VERSION_IDS.ingress);
  assert.equal(applied.observer_version_id, VERSION_IDS.observer);
  assert.equal(applied.worm_version_id, VERSION_IDS.worm);
  assert.equal(applied.credential_restrictions.private_provider_requery_required, true);
  assert.deepEqual(applied.credential_restrictions.writer.capabilities, ["writeFiles"]);
  assert.equal(applied.result, paths.result);
  assert.match(applied.result_sha256, /^sha256:[0-9a-f]{64}$/u);
  assertB2ObserverCeremonyPin(calls, applied);
  assert.equal(output.includes(WRITER.application_key), false);
  assert.equal(output.includes(OBSERVER.application_key), false);
  assert.equal(output.includes(CLOUDFLARE_TOKEN), false);
  assert.equal(output.includes("release-admin@example.test"), false);
  assert.equal(statSync(paths.result).mode & 0o777, 0o600);

  const resultBytes = readFileSync(paths.result);
  const entries = parseJournal(resultBytes);
  const report = entries.at(-1);
  assert.equal(report.status, "READY_FOR_PRIVATE_PREFLIGHT");
  assert.equal(report.private_provider_preflight_required, true);
  assert.deepEqual(
    entries.map((entry) => entry.journal_sequence),
    entries.map((_entry, index) => index),
  );
  for (let index = 1; index < entries.length; index += 1) {
    assert.equal(
      entries[index].previous_entry_sha256,
      taggedSha256(canonicalBytes(entries[index - 1])),
    );
  }
  assert.equal(resultBytes.includes(Buffer.from(WRITER.application_key)), false);
  assert.equal(resultBytes.includes(Buffer.from(OBSERVER.application_key)), false);
  assert.equal(resultBytes.includes(Buffer.from(CLOUDFLARE_TOKEN)), false);
  assert.equal(resultBytes.includes(Buffer.from("release-admin@example.test")), false);
}
