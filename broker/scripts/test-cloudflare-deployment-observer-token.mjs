import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { main } from "./provision-cloudflare-deployment-observer-token.mjs";

const directory = mkdtempSync(join(tmpdir(), "dpone-cloudflare-token-test-"));
const credential = join(directory, "credential.json");
const restriction = join(directory, "restriction.json");
const providerPolicy = join(directory, "provider-policy.json");
const result = join(directory, "result.json");
const token = "cloudflare_read_only_token_abcdefghijklmnopqrstuvwxyz";
const tokenFingerprint = taggedSha256(Buffer.from(token, "utf8"));
const accountId = "00000000000000000000000000000000";
const zoneId = "3b3a32acb9d30739d5c081662dfe0797";
const now = () => Date.parse("2026-08-19T12:00:30.000Z");

try {
  writePrivate(credential, { api_token: token });
  writePrivate(restriction, restrictionDocument());
  writePrivate(providerPolicy, providerPolicyDocument());

  let dryOutput = "";
  main(baseArguments(), { writeOutput: (value) => (dryOutput += value) });
  assert.equal(JSON.parse(dryOutput).status, "DRY_RUN_VALIDATED");
  assert.equal(dryOutput.includes(token), false);

  let providerCalls = 0;
  let verifiedOutput = "";
  main(
    [
      ...baseArguments(),
      "--provider-policy-evidence",
      providerPolicy,
      "--result",
      result,
      "--verify",
    ],
    {
      now,
      spawnSync: () => {
        providerCalls += 1;
        throw new Error("verification must not invoke a provider mutation");
      },
      writeOutput: (value) => (verifiedOutput += value),
    },
  );
  assert.equal(providerCalls, 0);
  assert.equal(JSON.parse(verifiedOutput).status, "READY_FOR_PAIRED_CEREMONY");
  assert.equal(JSON.parse(verifiedOutput).provider_mutation_performed, false);
  assert.equal(verifiedOutput.includes(token), false);
  assert.equal(JSON.parse(readFileSync(result, "utf8")).provider_mutation_performed, false);

  assert.throws(
    () =>
      main(
        [
          ...baseArguments(),
          "--provider-policy-evidence",
          providerPolicy,
          "--result",
          result,
          "--verify",
        ],
        { now },
      ),
    /one-use/u,
  );

  const stale = providerPolicyDocument();
  stale.observed_at = "2026-08-19T11:58:00.000Z";
  const stalePath = join(directory, "stale-policy.json");
  const staleResult = join(directory, "stale-result.json");
  writePrivate(stalePath, stale);
  assert.throws(
    () =>
      main(
        [
          ...baseArguments(),
          "--provider-policy-evidence",
          stalePath,
          "--result",
          staleResult,
          "--verify",
        ],
        { now },
      ),
    /provider policy evidence contract mismatch/u,
  );

  chmodSync(credential, 0o644);
  assert.throws(() => main(baseArguments()), /mode-0600/u);
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

function providerPolicyDocument() {
  return {
    account_id: accountId,
    grants: restrictionDocument().grants,
    observed_at: "2026-08-19T12:00:00.000Z",
    provider_observation_sha256: taggedSha256(Buffer.from("provider-policy", "utf8")),
    schema: "dpone.cloudflare-api-token-policy-observation.v1",
    schema_version: 1,
    token_fingerprint_sha256: tokenFingerprint,
    zone_id: zoneId,
  };
}

function writePrivate(path, value) {
  writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
