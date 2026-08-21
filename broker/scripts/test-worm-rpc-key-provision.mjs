import { strict as assert } from "node:assert";

import { provisionAuthorityKeysForTest } from "./test-worm-rpc-key-engine.mjs";

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const ROLES = Object.freeze(["ingress", "observer", "cloudflareObserver", "worm"]);
const VERSION_IDS = Object.freeze({
  cloudflareObserver: "123e4567-e89b-42d3-a456-426614174003",
  ingress: "123e4567-e89b-42d3-a456-426614174000",
  observer: "123e4567-e89b-42d3-a456-426614174001",
  worm: "123e4567-e89b-42d3-a456-426614174002",
});

const applied = provisionAuthorityKeysForTest(descriptor(baseEvents()));
assert.deepEqual(applied.completedUploads, ROLES);
assert.deepEqual(applied.requeryOrder, ROLES);
assert.deepEqual(applied.uploadCounts, roleCounts(1));
assert.equal(
  applied.expectedB2ObserverServiceIdentity,
  `cloudflare-worker:${ACCOUNT_ID}/dpone-release-worm-version-observer@${VERSION_IDS.observer}`,
);

for (const recoveredRole of ROLES) {
  const recoveredEvents = baseEvents().map((event) =>
    event.kind === "UPLOAD" && event.role === recoveredRole
      ? { ...event, kind: "RECOVER_EXACT", matchingVersionCount: 1 }
      : event,
  );
  const recovered = provisionAuthorityKeysForTest(descriptor(recoveredEvents));
  assert.deepEqual(recovered.completedUploads, ROLES);
  assert.equal(recovered.uploadCounts[recoveredRole], 0);
  for (const role of ROLES.filter((item) => item !== recoveredRole)) {
    assert.equal(recovered.uploadCounts[role], 1);
  }
  assert.equal(
    recovered.expectedB2ObserverServiceIdentity,
    applied.expectedB2ObserverServiceIdentity,
  );
}

assert.throws(
  () =>
    provisionAuthorityKeysForTest(
      descriptor(
        baseEvents().map((event) =>
          event.kind === "ABSENCE" && event.role === "ingress"
            ? { ...event, listedVersionCount: 10 }
            : event,
        ),
      ),
    ),
  /saturated/u,
);
assert.throws(
  () =>
    provisionAuthorityKeysForTest(
      descriptor(
        baseEvents().map((event) =>
          event.kind === "UPLOAD" && event.role === "ingress"
            ? { ...event, kind: "RECOVER_EXACT", matchingVersionCount: 2 }
            : event,
        ),
      ),
    ),
  /ambiguous/u,
);
assert.throws(
  () =>
    provisionAuthorityKeysForTest(
      descriptor(
        baseEvents().filter((event) => !(event.kind === "ABSENCE" && event.role === "observer")),
      ),
    ),
  /durable absence/u,
);
assert.throws(
  () =>
    provisionAuthorityKeysForTest(
      descriptor([
        ...baseEvents().slice(0, 2),
        ...baseEvents().slice(4, 6),
        ...baseEvents().slice(2, 4),
        ...baseEvents().slice(6),
      ]),
    ),
  /effect order/u,
);
assert.throws(
  () => provisionAuthorityKeysForTest({ events: baseEvents() }),
  /primitive JSON text/u,
);

process.stdout.write("WORM authority declarative ceremony/recovery semantics: PASS\n");

function descriptor(events) {
  return JSON.stringify({
    accountId: ACCOUNT_ID,
    events,
    observerWorkerName: "dpone-release-worm-version-observer",
  });
}

function baseEvents() {
  const events = [];
  for (const role of ROLES) {
    events.push({ kind: "ABSENCE", listedVersionCount: 0, matchingVersionCount: 0, role });
    events.push({ kind: "UPLOAD", role, versionId: VERSION_IDS[role] });
  }
  for (const role of ROLES) {
    events.push({ kind: "REQUERY", role, versionId: VERSION_IDS[role] });
  }
  events.push({ kind: "TERMINAL", role: "worm" });
  return events;
}

function roleCounts(value) {
  return { cloudflareObserver: value, ingress: value, observer: value, worm: value };
}
