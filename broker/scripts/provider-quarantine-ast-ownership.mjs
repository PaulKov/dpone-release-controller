import { reachable } from "./provider-quarantine-ast-graph.mjs";

/** Enforce exact ownership after the complete production call graph is materialized. */
export function assertCapabilityOwnership(
  modules,
  graph,
  guarded,
  localOwners,
  localOwnerDigests,
  effectModules,
) {
  for (const module of modules.values()) {
    for (const exported of module.exportedFunctionKeys) {
      if (!guarded.has(exported)) {
        assertNoDangerousReachability(
          exported,
          graph,
          guarded,
          localOwners,
          localOwnerDigests,
          effectModules,
        );
      }
    }
    if (!guarded.has(module.moduleKey)) {
      assertNoDangerousReachability(
        module.moduleKey,
        graph,
        guarded,
        localOwners,
        localOwnerDigests,
        effectModules,
      );
    }
  }
  assertEveryCapabilityHasOwner(graph, guarded, localOwners);
  assertPinnedLocalCapabilityCalls(modules, localOwners);
}

export function normalizedAstDigest(node, createHash) {
  const canonical = JSON.stringify(node, (key, value) =>
    ["comments", "end", "loc", "range", "raw", "start", "tokens"].includes(key) ? undefined : value,
  );
  return createHash("sha256").update(canonical).digest("hex");
}

function assertNoDangerousReachability(
  start,
  graph,
  guarded,
  localOwners,
  localOwnerDigests,
  effectModules,
) {
  for (const key of reachable(start, graph, guarded)) {
    if (Object.hasOwn(localOwners, key)) {
      assertRestrictedOwnerReachability(
        start,
        key,
        localOwners[key],
        localOwnerDigests,
        effectModules,
      );
      continue;
    }
    if (key !== start && guarded.has(key)) continue;
    const capabilities = graph.get(key)?.capabilities ?? new Set();
    if (capabilities.size > 0) {
      throw new Error(
        `unguarded production capability reachable: ${start} -> ${key}: ${[...capabilities].join(
          ",",
        )}`,
      );
    }
  }
}

function assertRestrictedOwnerReachability(
  start,
  owner,
  capabilities,
  localOwnerDigests,
  effectModules,
) {
  const restricted = capabilities.some(
    (capability) =>
      !capability.startsWith("injected-reference:") &&
      !capability.startsWith("injected-call:") &&
      capability !== "native-entry-dispatch:process.argv[1]",
  );
  if (!restricted) return;
  const [startModule] = start.split("#");
  if (
    effectModules.has(startModule) ||
    (start !== owner && !Object.hasOwn(localOwnerDigests, start))
  ) {
    throw new Error(`restricted local capability reachable before HOLD: ${start} -> ${owner}`);
  }
}

function assertEveryCapabilityHasOwner(graph, guarded, localOwners) {
  const owned = new Set(Object.keys(localOwners));
  for (const owner of guarded) {
    for (const key of reachable(owner, graph, new Set())) owned.add(key);
  }
  for (const [key, node] of graph) {
    if (node.capabilities.size > 0 && !owned.has(key)) {
      throw new Error(`production capability has no guarded owner: ${key}`);
    }
  }
}

function assertPinnedLocalCapabilityCalls(modules, localOwners) {
  for (const [key, expected] of Object.entries(localOwners)) {
    const [filename] = key.split("#");
    const node = modules.get(filename)?.nodes.get(key);
    if (
      node === undefined ||
      JSON.stringify([...node.capabilities].sort()) !== JSON.stringify([...expected].sort())
    ) {
      throw new Error(`local capability owner inventory drift: ${key}`);
    }
  }
}
