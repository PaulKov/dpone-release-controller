import { strict as assert } from "node:assert";
import { writeSync } from "node:fs";

import { provisionAuthorityKeysForTest as provisionAuthorityKeys } from "./test-worm-rpc-key-engine.mjs";
import {
  ROLES,
  VERSION_IDS,
  argumentsFor,
  configs,
  dependencies,
} from "./test-worm-rpc-key-fixtures.mjs";
import { versionResources } from "./test-worm-rpc-key-evidence-fixtures.mjs";

export function createVersionProvider() {
  const versions = { cloudflareObserver: [], ingress: [], observer: [], worm: [] };
  const uploadCounts = { cloudflareObserver: 0, ingress: 0, observer: 0, worm: 0 };
  return {
    addVersion,
    spawnSync: (_executable, arguments_) => {
      const command = arguments_.slice(1, 3).join(" ");
      const configPath = arguments_[arguments_.indexOf("--config") + 1];
      const role = Object.entries(configs).find(
        ([, value]) => value.live.pathname === configPath,
      )?.[0];
      assert.ok(role !== undefined);
      if (command === "versions list") {
        return { status: 0, stdout: JSON.stringify(versions[role]) };
      }
      if (command === "versions upload") {
        uploadCounts[role] += 1;
        assert.equal(uploadCounts[role], 1, `duplicate ${role} provider effect`);
        addVersion(role, VERSION_IDS[role]);
        return { status: 0, stdout: `Worker Version ID: ${VERSION_IDS[role]}\n` };
      }
      assert.equal(command, "versions view");
      const versionId = arguments_[3];
      assert.equal(
        versions[role].some((item) => item.id === versionId),
        true,
      );
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
    uploadCounts,
  };

  function addVersion(role, versionId, tag = "authority-keys-test-v1") {
    versions[role].push({
      annotations: {
        "workers/message": "reviewed authority key ceremony",
        "workers/tag": tag,
      },
      id: versionId,
      metadata: { created_on: "2026-08-19T10:00:00.000Z" },
    });
  }
}

export function crashBetweenAbsenceListAndPersist(role, resultPath, provider) {
  const roleIndex = ROLES.indexOf(role);
  let crashed = false;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, resultPath).slice(1), {
        ...dependencies(),
        journalIo: {
          writeSync: (handle, bytes, offset, length, position) => {
            const entry = JSON.parse(bytes.toString("utf8"));
            if (
              !crashed &&
              entry.initial_absence_observations.length === roleIndex + 1 &&
              entry.completed_uploads.length === roleIndex
            ) {
              crashed = true;
              writeSync(handle, bytes, offset, Math.max(1, Math.floor(length / 2)), position);
              throw new Error(`simulated crash before ${role} absence persistence`);
            }
            return writeSync(handle, bytes, offset, length, position);
          },
        },
        spawnSync: provider.spawnSync,
      }),
    new RegExp(`simulated crash before ${role} absence persistence`, "u"),
  );
  assert.equal(crashed, true);
}

export function crashBetweenAbsencePersistAndUpload(role, resultPath, provider) {
  let crashed = false;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, resultPath).slice(1), {
        ...dependencies(),
        spawnSync: (executable, arguments_) => {
          const command = arguments_.slice(1, 3).join(" ");
          const configPath = arguments_[arguments_.indexOf("--config") + 1];
          const callRole = Object.entries(configs).find(
            ([, value]) => value.live.pathname === configPath,
          )?.[0];
          if (!crashed && command === "versions upload" && callRole === role) {
            crashed = true;
            throw new Error(`simulated crash before ${role} provider effect`);
          }
          return provider.spawnSync(executable, arguments_);
        },
      }),
    new RegExp(`simulated crash before ${role} provider effect`, "u"),
  );
  assert.equal(crashed, true);
}

export function crashAfterProviderEffect(role, resultPath, provider) {
  const roleIndex = ROLES.indexOf(role);
  const completed = JSON.stringify(ROLES.slice(0, roleIndex + 1));
  let crashed = false;
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, resultPath).slice(1), {
        ...dependencies(),
        journalIo: {
          writeSync: (handle, bytes, offset, length, position) => {
            const source = bytes.toString("utf8");
            if (!crashed && source.includes(`"completed_uploads":${completed}`)) {
              crashed = true;
              writeSync(handle, bytes, offset, Math.max(1, Math.floor(length / 2)), position);
              throw new Error(`simulated crash after ${role} provider effect`);
            }
            return writeSync(handle, bytes, offset, length, position);
          },
        },
        spawnSync: provider.spawnSync,
      }),
    new RegExp(`simulated crash after ${role} provider effect`, "u"),
  );
  assert.equal(crashed, true);
}
