import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { main } from "./provision-cloudflare-deployment-observer-token.mjs";
import { PROVIDER_MUTATION_HOLD_CODE } from "./provider-mutation-hold.mjs";
import { simulateCloudflareObserverTokenVerification } from "./test-provider-trace-simulation.mjs";

const directory = mkdtempSync(join(tmpdir(), "dpone-cloudflare-token-test-"));
const credential = join(directory, "credential.json");
const restriction = join(directory, "restriction.json");
const token = "cloudflare_read_only_token_abcdefghijklmnopqrstuvwxyz";
const tokenFingerprint = taggedSha256(Buffer.from(token, "utf8"));
const accountId = "00000000000000000000000000000000";
const zoneId = "3b3a32acb9d30739d5c081662dfe0797";

try {
  writePrivate(credential, { api_token: token });
  writePrivate(restriction, restrictionDocument());

  let dependencyReads = 0;
  const explodingDependencies = new Proxy(
    {},
    {
      get() {
        dependencyReads += 1;
        throw new Error("token verifier read caller dependency injection");
      },
    },
  );
  assert.throws(
    () => withArguments(baseArguments(), () => main(explodingDependencies)),
    (error) => error?.code === PROVIDER_MUTATION_HOLD_CODE,
  );
  assert.equal(dependencyReads, 0);

  const simulation = providerPolicySimulation();
  assert.deepEqual(simulateCloudflareObserverTokenVerification(JSON.stringify(simulation)), {
    providerMutationPerformed: false,
    status: "READY_FOR_PAIRED_CEREMONY",
    tokenFingerprintSha256: tokenFingerprint,
  });
  simulation.providerPolicy.observed_at = "2026-08-19T11:58:00.000Z";
  assert.throws(
    () => simulateCloudflareObserverTokenVerification(JSON.stringify(simulation)),
    /provider policy simulation mismatch/u,
  );

  chmodSync(credential, 0o644);
  assert.throws(
    () => withArguments(baseArguments(), () => main()),
    (error) => error?.code === PROVIDER_MUTATION_HOLD_CODE,
  );
} finally {
  rmSync(directory, { force: true, recursive: true });
}

function baseArguments() {
  return ["--credential", credential, "--restriction-evidence", restriction];
}

function restrictionDocument() {
  return {
    account_id: accountId,
    grants: [
      { permission: "Workers Scripts Read", resource_scope: `account:${accountId}` },
      { permission: "Workers Routes Read", resource_scope: `zone:${zoneId}` },
    ],
    schema: "dpone.cloudflare-deployment-observer-token-restriction-evidence.v1",
    schema_version: 1,
    token_fingerprint_sha256: tokenFingerprint,
    zone_id: zoneId,
  };
}

function providerPolicySimulation() {
  return {
    acceptedAt: "2026-08-19T12:00:30.000Z",
    providerPolicy: {
      account_id: accountId,
      grants: restrictionDocument().grants,
      observed_at: "2026-08-19T12:00:00.000Z",
      provider_observation_sha256: taggedSha256(Buffer.from("provider-policy", "utf8")),
      token_fingerprint_sha256: tokenFingerprint,
      zone_id: zoneId,
    },
    restriction: restrictionDocument(),
    tokenFingerprintSha256: tokenFingerprint,
  };
}

function withArguments(arguments_, operation) {
  const original = process.argv;
  process.argv = [...original.slice(0, 2), ...arguments_];
  try {
    return operation();
  } finally {
    process.argv = original;
  }
}

function writePrivate(path, value) {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
