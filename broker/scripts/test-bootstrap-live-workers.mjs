import { strict as assert } from "node:assert";
import { simulateBootstrap } from "./test-provider-trace-simulation.mjs";

const version = (index) => `123e4567-e89b-4${index}d3-a456-42661417400${index}`;
const roles = ["private", "worm", "private-observer", "ingress"];
const workers = roles.map((role, index) => ({
  requeriedVersionId: version(index),
  role,
  secretNames: [],
  versionId: version(index),
}));
const deniedPaths = [
  "/readyz",
  "/v1/admin/activation/provision",
  "/v1/providers/github/candidate",
  "/v1/receipts/append",
  "/v1/runtime/closure",
  "/v1/webhooks/github/deployment-protection-rule",
];

const report = simulateBootstrap(
  JSON.stringify({
    deniedPaths,
    expectedRoles: roles,
    livenessVersionId: workers.at(-1).versionId,
    workers,
  }),
);
assert.equal(report.applied, true);
assert.equal(report.bootstrapSecretAbsent, true);
assert.deepEqual(report.completedRoles, roles);
assert.deepEqual(report.deniedPaths, deniedPaths);

assert.throws(
  () =>
    simulateBootstrap(
      JSON.stringify({
        deniedPaths,
        expectedRoles: roles,
        livenessVersionId: workers.at(-1).versionId,
        workers: workers.map((worker, index) =>
          index === 1 ? { ...worker, secretNames: ["WORM_RPC_AUTH_KEY"] } : worker,
        ),
      }),
    ),
  /retained a secret/u,
);
assert.throws(
  () =>
    simulateBootstrap(
      JSON.stringify({
        deniedPaths,
        expectedRoles: roles,
        livenessVersionId: workers.at(-1).versionId,
        workers: workers.map((worker, index) =>
          index === 2 ? { ...worker, requeriedVersionId: version(9) } : worker,
        ),
      }),
    ),
  /requery mismatch/u,
);
assert.throws(
  () =>
    simulateBootstrap(
      JSON.stringify({
        deniedPaths,
        expectedRoles: roles,
        livenessVersionId: workers.at(-1).versionId,
        workers: [...workers].reverse(),
      }),
    ),
  /role inventory/u,
);

let proxyTraps = 0;
const proxy = new Proxy(
  {},
  {
    get() {
      proxyTraps += 1;
      throw new Error("simulation read an object Proxy");
    },
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error("simulation inspected an object Proxy");
    },
  },
);
assert.throws(() => simulateBootstrap(proxy), /primitive JSON text/u);
assert.equal(proxyTraps, 0);

let getterReads = 0;
const accessor = {};
Object.defineProperty(accessor, "workers", {
  get() {
    getterReads += 1;
    throw new Error("simulation invoked an accessor");
  },
});
assert.throws(() => simulateBootstrap(accessor), /primitive JSON text/u);
assert.equal(getterReads, 0);

process.stdout.write("bootstrap live-worker declarative semantics: PASS\n");
