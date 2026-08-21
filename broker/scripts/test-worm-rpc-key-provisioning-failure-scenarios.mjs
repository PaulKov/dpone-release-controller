import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";

import { provisionAuthorityKeysForTest as provisionAuthorityKeys } from "./test-worm-rpc-key-engine.mjs";
import {
  ROLES,
  VERSION_IDS,
  WRITER,
  argumentsFor,
  dependencies,
  parseJournal,
  temporaryDirectory,
} from "./test-worm-rpc-key-fixtures.mjs";
import { versionResources } from "./test-worm-rpc-key-evidence-fixtures.mjs";

/** Exercise terminal HOLD behavior after otherwise valid provisioning effects. */
export function runProvisioningFailureScenarios() {
  runInheritedSecretScenario();
  runPartialUploadScenario();
}

function runInheritedSecretScenario() {
  const inheritedSecretPath = `${temporaryDirectory}/inherited-secret-hold.jsonl`;
  let inheritedUploadIndex = 0;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, inheritedSecretPath).slice(1), {
        ...dependencies(),
        spawnSync: (_executable, arguments_) => {
          if (arguments_[2] === "list") return { status: 0, stdout: "[]" };
          if (arguments_[2] === "upload") {
            const role = ROLES[inheritedUploadIndex];
            inheritedUploadIndex += 1;
            return { status: 0, stdout: `Worker Version ID: ${VERSION_IDS[role]}\n` };
          }
          const versionId = arguments_[3];
          const role = Object.entries(VERSION_IDS).find(([, value]) => value === versionId)?.[0];
          assert.ok(role !== undefined);
          const resources = versionResources(role);
          if (role === "ingress") {
            resources.bindings.push({ name: "INHERITED_SECRET", type: "secret_text" });
          }
          return {
            status: 0,
            stdout: JSON.stringify({
              annotations: {
                "workers/message": "reviewed authority key ceremony",
                "workers/tag": "authority-keys-test-v1",
              },
              id: versionId,
              metadata: { created_on: "2026-08-19T10:00:00.000Z" },
              resources,
            }),
          };
        },
      }),
    /binding projection differs from reviewed config\/secrets/u,
  );
  const inheritedHold = parseJournal(readFileSync(inheritedSecretPath)).at(-1);
  assert.equal(inheritedHold.status, "HOLD");
  assert.deepEqual(inheritedHold.completed_uploads, ROLES);
  assert.deepEqual(inheritedHold.provider_version_observations, []);
}

function runPartialUploadScenario() {
  const partialPath = `${temporaryDirectory}/partial-hold.json`;
  let partialUploads = 0;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, partialPath).slice(1), {
        ...dependencies(),
        spawnSync: (_executable, arguments_) => {
          if (arguments_[2] === "list") return { status: 0, stdout: "[]" };
          if (arguments_[2] !== "upload") throw new Error("unexpected requery before uploads");
          partialUploads += 1;
          if (partialUploads === 2) return { status: 1, stderr: "secret-value-forbidden" };
          return { status: 0, stdout: `Worker Version ID: ${VERSION_IDS.ingress}\n` };
        },
      }),
    /immutable final observer version upload failed/u,
  );
  const partialBytes = readFileSync(partialPath);
  const partial = parseJournal(partialBytes).at(-1);
  assert.equal(partial.status, "HOLD");
  assert.deepEqual(partial.completed_uploads, ["ingress"]);
  assert.equal(partial.ingress_version_id, VERSION_IDS.ingress);
  assert.equal(partial.observer_version_id, null);
  assert.equal(partialBytes.includes(Buffer.from("secret-value-forbidden")), false);
  assert.equal(partialBytes.includes(Buffer.from(WRITER.application_key)), false);
}
