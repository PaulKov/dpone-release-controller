import { strict as assert } from "node:assert";

import { provisionAuthorityKeysForTest as provisionAuthorityKeys } from "./test-worm-rpc-key-engine.mjs";
import {
  argumentsFor,
  canonicalBytes,
  cloneJson,
  dependencies,
  paths,
  temporaryDirectory,
  writePrivate,
} from "./test-worm-rpc-key-fixtures.mjs";

/** Prove a partial, extended, or reordered lifecycle report fails pre-effect. */
export function runBootstrapReportTopologyNegatives(canonicalReport) {
  const missing = cloneJson(canonicalReport);
  const missingName = "dpone-release-attestation-mutator";
  missing.plan.workers = missing.plan.workers.filter(({ name }) => name !== missingName);
  missing.provider_observations = missing.provider_observations.filter(
    ({ name }) => name !== missingName,
  );
  expectTopologyRejection(missing, "missing-private");

  const extra = cloneJson(canonicalReport);
  const extraWorker = cloneJson(
    extra.plan.workers.find(({ name }) => name === "dpone-release-attestation-mutator"),
  );
  const extraObservation = cloneJson(
    extra.provider_observations.find(({ name }) => name === "dpone-release-attestation-mutator"),
  );
  extraWorker.name = "dpone-release-unreviewed-extra";
  extraObservation.name = extraWorker.name;
  extra.plan.workers.push(extraWorker);
  extra.provider_observations.push(extraObservation);
  expectTopologyRejection(extra, "extra-private");

  const swapped = cloneJson(canonicalReport);
  [swapped.plan.workers[0], swapped.plan.workers[1]] = [
    swapped.plan.workers[1],
    swapped.plan.workers[0],
  ];
  [swapped.provider_observations[0], swapped.provider_observations[1]] = [
    swapped.provider_observations[1],
    swapped.provider_observations[0],
  ];
  expectTopologyRejection(swapped, "name-order-swap");

  writePrivate(paths.bootstrap, canonicalBytes(canonicalReport));
}

function expectTopologyRejection(report, label) {
  writePrivate(paths.bootstrap, canonicalBytes(report));
  let effects = 0;
  assert.throws(
    () =>
      provisionAuthorityKeys(
        argumentsFor(true, `${temporaryDirectory}/${label}-hold.json`).slice(1),
        {
          ...dependencies(),
          spawnSync: () => {
            effects += 1;
            throw new Error("effect must not start for invalid bootstrap topology");
          },
        },
      ),
    /bootstrap report does not prove exact credential-free provider versions/u,
  );
  assert.equal(effects, 0);
}
