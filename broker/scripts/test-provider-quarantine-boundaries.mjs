import { strict as assert } from "node:assert";

import {
  PROVIDER_MUTATION_BOUNDARIES,
  PROVIDER_MUTATION_ENTRYPOINTS,
} from "./provider-mutation-hold.mjs";
import { assertProviderBoundarySources } from "./provider-quarantine-policy.mjs";

/** Reject callable aliases and data re-exports without changing pinned export names. */
export function runProviderBoundaryExportRegressions(effectSources) {
  assertMutationFails(
    effectSources,
    "bootstrap-live-workers-common.mjs",
    (source) =>
      source.replace("export function taggedSha256(value) {", "function taggedSha256(value) {") +
      "\nexport { taggedSha256 };\n",
    /source-local export alias/u,
  );
  assertMutationFails(
    effectSources,
    "bootstrap-live-workers-common.mjs",
    (source) =>
      source.replace(
        "export function taggedSha256(value) {",
        "function taggedSha256Target(value) {",
      ) + "\nexport const taggedSha256 = taggedSha256Target;\n",
    /effect data export inventory drift|unsupported callable binding/u,
  );
  assertMutationFails(
    effectSources,
    "bootstrap-live-workers-common.mjs",
    (source) =>
      source.replace(
        /export function taggedSha256\(value\) \{[\s\S]*?^\}/mu,
        "export class taggedSha256 {}",
      ),
    /unsupported callable class/u,
  );
  assertMutationFails(
    effectSources,
    "worker-version-resource-provider.mjs",
    (source) =>
      source.replace(
        /export function projectWorkerVersionResources\([\s\S]*?^\}/mu,
        "export const projectWorkerVersionResources = null;",
      ),
    /effect data export inventory drift|callable exports differ/u,
  );
  for (const initializer of [
    "resolve",
    "Object.freeze",
    "process.exit",
    "true ? function hiddenEffect() {} : 65_536",
    "false || (() => {})",
    "(65_536, () => {})",
    'taggedSha256("call-produced")',
  ]) {
    assertMutationFails(
      effectSources,
      "bootstrap-live-workers-common.mjs",
      (source) =>
        source.replace(
          "export const MAX_SMOKE_BYTES = 65_536;",
          `export const MAX_SMOKE_BYTES = ${initializer};`,
        ),
      /effect data initializer AST drift/u,
    );
  }
  assertMutationFails(
    effectSources,
    "bootstrap-live-workers-common.mjs",
    (source) =>
      source.replace("export const MAX_SMOKE_BYTES = 65_536;", "const localBytes = 65_536;") +
      "\nexport { localBytes as MAX_SMOKE_BYTES };\n",
    /effect data export inventory drift|source-local export alias/u,
  );
}

function assertMutationFails(effectSources, filename, mutate, pattern) {
  const sources = new Map(effectSources);
  sources.set(filename, mutate(sources.get(filename)));
  assert.throws(
    () =>
      assertProviderBoundarySources(
        PROVIDER_MUTATION_BOUNDARIES,
        PROVIDER_MUTATION_ENTRYPOINTS,
        sources,
      ),
    pattern,
  );
}
