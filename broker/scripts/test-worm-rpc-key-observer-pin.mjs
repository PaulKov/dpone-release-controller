import { strict as assert } from "node:assert";

import { ACCOUNT_ID, VERSION_IDS } from "./test-worm-rpc-key-fixtures.mjs";

/** Prove the final WORM version pins the exact immutable B2 reader. */
export function assertB2ObserverCeremonyPin(calls, report) {
  const expectedIdentity =
    `cloudflare-worker:${ACCOUNT_ID}/dpone-release-worm-version-observer@` + VERSION_IDS.observer;
  assert.equal(
    calls[3].arguments_.includes(`WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY:${expectedIdentity}`),
    true,
  );
  assert.equal(report.worm_expected_b2_observer_service_identity, expectedIdentity);
}
