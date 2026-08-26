import { strict as assert } from "node:assert";
import { closeSync, openSync, readFileSync, renameSync, writeFileSync, writeSync } from "node:fs";

import { appendJournalEntry } from "./provision-worm-rpc-key.mjs";
import { provisionAuthorityKeysForTest as provisionAuthorityKeys } from "./test-worm-rpc-key-engine.mjs";
import {
  ACCOUNT_ID,
  ROLES,
  VERSION_IDS,
  argumentsFor,
  dependencies,
  expectTerminalJournal,
  temporaryDirectory,
  uploadCounts,
  writePrivate,
} from "./test-worm-rpc-key-fixtures.mjs";
import {
  crashAfterProviderEffect,
  crashBetweenAbsenceListAndPersist,
  crashBetweenAbsencePersistAndUpload,
  createVersionProvider,
} from "./test-worm-rpc-key-recovery-fixtures.mjs";

/** Exercise every recovery boundary without repeating a provider effect. */
export function runRecoveryScenarios() {
  runProviderEffectRecovery();
  runAbsenceBoundaryRecovery();
  runTerminalRecovery();
  runRenamedJournalRejection();
  runSaturatedWindowRejection();
  runAmbiguousRecoveryRejection();
  runRecoveryIdentityRejection();
  runInvalidChainRejection();
  runPartialJournalAppend();
}

function runProviderEffectRecovery() {
  for (const crashedRole of ROLES) {
    const recoveryPath = `${temporaryDirectory}/recover-${crashedRole}.jsonl`;
    const provider = createVersionProvider();
    crashAfterProviderEffect(crashedRole, recoveryPath, provider);
    const crashedBytes = readFileSync(recoveryPath);
    assert.notEqual(crashedBytes.at(-1), 0x0a);
    assert.equal(crashedBytes.subarray(crashedBytes.lastIndexOf(0x0a) + 1).includes(0x0a), false);

    const output = [];
    provisionAuthorityKeys([...argumentsFor(true, recoveryPath).slice(1), "--recover"], {
      ...dependencies(),
      spawnSync: provider.spawnSync,
      writeOutput: (value) => output.push(value),
    });
    const recovered = JSON.parse(output[0]);
    assert.equal(recovered.status, "READY_FOR_PRIVATE_PREFLIGHT");
    assert.equal(recovered.recovery_mode, true);
    assert.deepEqual(recovered.completed_uploads, ROLES);
    assert.equal(
      recovered.recovery_observations.some(
        (item) =>
          item.outcome === "RECOVERED_EXACT_EFFECT" &&
          item.version_observation.role === crashedRole,
      ),
      true,
    );
    assertB2ObserverIdentity(recovered);
    assert.deepEqual(provider.uploadCounts, uploadCounts(1));
    assert.equal(readFileSync(recoveryPath).at(-1), 0x0a);
  }
}

function runAbsenceBoundaryRecovery() {
  for (const boundaryRole of ROLES) {
    const boundaryPath = `${temporaryDirectory}/recover-list-persist-${boundaryRole}.jsonl`;
    const boundaryProvider = createVersionProvider();
    crashBetweenAbsenceListAndPersist(boundaryRole, boundaryPath, boundaryProvider);
    provisionAuthorityKeys([...argumentsFor(true, boundaryPath).slice(1), "--recover"], {
      ...dependencies(),
      spawnSync: boundaryProvider.spawnSync,
    });
    assert.deepEqual(boundaryProvider.uploadCounts, uploadCounts(1));

    const preUploadPath = `${temporaryDirectory}/recover-pre-upload-${boundaryRole}.jsonl`;
    const preUploadProvider = createVersionProvider();
    crashBetweenAbsencePersistAndUpload(boundaryRole, preUploadPath, preUploadProvider);
    provisionAuthorityKeys([...argumentsFor(true, preUploadPath).slice(1), "--recover"], {
      ...dependencies(),
      spawnSync: preUploadProvider.spawnSync,
    });
    assert.deepEqual(preUploadProvider.uploadCounts, uploadCounts(1));
  }
}

function runTerminalRecovery() {
  const terminalPath = `${temporaryDirectory}/recover-terminal.jsonl`;
  const provider = createVersionProvider();
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, terminalPath).slice(1), {
        ...dependencies(),
        spawnSync: provider.spawnSync,
        writeOutput: () => {
          throw new Error("simulated crash after terminal fsync before stdout");
        },
      }),
    /simulated crash after terminal fsync before stdout/u,
  );
  const terminalBytes = readFileSync(terminalPath);
  expectTerminalJournal(terminalBytes);
  const output = [];
  provisionAuthorityKeys([...argumentsFor(true, terminalPath).slice(1), "--recover"], {
    ...dependencies(),
    spawnSync: provider.spawnSync,
    writeOutput: (value) => output.push(value),
  });
  const recovered = JSON.parse(output[0]);
  assert.equal(recovered.status, "READY_FOR_PRIVATE_PREFLIGHT");
  assert.equal(recovered.terminal_requery_confirmed, true);
  assertB2ObserverIdentity(recovered);
  assert.deepEqual(provider.uploadCounts, uploadCounts(1));
  assert.deepEqual(readFileSync(terminalPath), terminalBytes);
}

function runRenamedJournalRejection() {
  const sourcePath = `${temporaryDirectory}/recover-terminal.jsonl`;
  const renamedPath = `${temporaryDirectory}/recover-renamed.jsonl`;
  const displacedPath = `${temporaryDirectory}/recover-renamed.displaced.jsonl`;
  const terminalBytes = readFileSync(sourcePath);
  writeFileSync(renamedPath, terminalBytes, { flag: "wx", mode: 0o600 });
  const provider = createVersionProvider();
  assert.throws(
    () =>
      provisionAuthorityKeys([...argumentsFor(true, renamedPath).slice(1), "--recover"], {
        ...dependencies(),
        afterJournalOpen: ({ path }) => {
          renameSync(path, displacedPath);
          writeFileSync(path, terminalBytes, { flag: "wx", mode: 0o600 });
        },
        spawnSync: provider.spawnSync,
      }),
    /recovery journal read is not byte-exact/u,
  );
  assert.deepEqual(provider.uploadCounts, uploadCounts(0));
}

function runSaturatedWindowRejection() {
  const resultPath = `${temporaryDirectory}/saturated-window.jsonl`;
  const provider = createVersionProvider();
  for (let index = 0; index < 10; index += 1) {
    provider.addVersion(
      "ingress",
      `123e4567-e89b-42d3-a456-4266141750${index.toString().padStart(2, "0")}`,
      `other-tag-${index}`,
    );
  }
  assert.throws(
    () =>
      provisionAuthorityKeys(argumentsFor(true, resultPath).slice(1), {
        ...dependencies(),
        spawnSync: provider.spawnSync,
      }),
    /absence window is saturated/u,
  );
  assert.deepEqual(provider.uploadCounts, uploadCounts(0));
}

function runAmbiguousRecoveryRejection() {
  const resultPath = `${temporaryDirectory}/recover-ambiguous.jsonl`;
  const provider = createVersionProvider();
  crashAfterProviderEffect("ingress", resultPath, provider);
  provider.addVersion("ingress", "123e4567-e89b-42d3-a456-426614174099");
  assert.throws(
    () =>
      provisionAuthorityKeys([...argumentsFor(true, resultPath).slice(1), "--recover"], {
        ...dependencies(),
        spawnSync: provider.spawnSync,
      }),
    /recovery version is ambiguous/u,
  );
  assert.deepEqual(provider.uploadCounts, roleCounts(1));
}

function runRecoveryIdentityRejection() {
  const resultPath = `${temporaryDirectory}/recover-identity.jsonl`;
  const provider = createVersionProvider();
  crashAfterProviderEffect("ingress", resultPath, provider);
  const wrongRpcPath = `${temporaryDirectory}/wrong-worm-rpc.key`;
  writePrivate(wrongRpcPath, Buffer.alloc(32, 0xff));
  const arguments_ = [...argumentsFor(true, resultPath).slice(1), "--recover"];
  arguments_[arguments_.indexOf("--input") + 1] = wrongRpcPath;
  assert.throws(
    () =>
      provisionAuthorityKeys(arguments_, {
        ...dependencies(),
        spawnSync: provider.spawnSync,
      }),
    /recovery identity\/state mismatch/u,
  );
  assert.deepEqual(provider.uploadCounts, roleCounts(1));
}

function runInvalidChainRejection() {
  const resultPath = `${temporaryDirectory}/recover-invalid-chain.jsonl`;
  const provider = createVersionProvider();
  crashAfterProviderEffect("ingress", resultPath, provider);
  const invalidBytes = readFileSync(resultPath);
  const completePrefix = invalidBytes.subarray(0, invalidBytes.lastIndexOf(0x0a) + 1);
  writeFileSync(resultPath, Buffer.concat([completePrefix, Buffer.from('{"bad":true}\n')]), {
    mode: 0o600,
  });
  assert.throws(
    () =>
      provisionAuthorityKeys([...argumentsFor(true, resultPath).slice(1), "--recover"], {
        ...dependencies(),
        spawnSync: provider.spawnSync,
      }),
    /journal chain is invalid/u,
  );
  assert.deepEqual(provider.uploadCounts, roleCounts(1));
}

function runPartialJournalAppend() {
  const resultPath = `${temporaryDirectory}/crash-journal.jsonl`;
  const handle = openSync(resultPath, "ax", 0o600);
  const complete = { journal_sequence: 0, schema: "test.journal.v1", status: "HOLD" };
  appendJournalEntry(handle, complete);
  let partialWrites = 0;
  assert.throws(
    () =>
      appendJournalEntry(
        handle,
        { journal_sequence: 1, schema: "test.journal.v1", status: "READY" },
        {
          writeSync: (file, bytes, offset, length, position) => {
            partialWrites += 1;
            if (partialWrites > 1) throw new Error("simulated process crash during append");
            return writeSync(file, bytes, offset, Math.floor(length / 2), position);
          },
        },
      ),
    /simulated process crash/u,
  );
  closeSync(handle);
  const bytes = readFileSync(resultPath);
  const firstNewline = bytes.indexOf(0x0a);
  assert.notEqual(firstNewline, -1);
  assert.deepEqual(JSON.parse(bytes.subarray(0, firstNewline).toString("utf8")), complete);
  assert.equal(bytes.subarray(firstNewline + 1).includes(0x0a), false);
}

function assertB2ObserverIdentity(report) {
  assert.equal(
    report.worm_expected_b2_observer_service_identity,
    `cloudflare-worker:${ACCOUNT_ID}/dpone-release-worm-version-observer@${VERSION_IDS.observer}`,
  );
}

function roleCounts(ingress) {
  return { cloudflareObserver: 0, ingress, observer: 0, worm: 0 };
}
