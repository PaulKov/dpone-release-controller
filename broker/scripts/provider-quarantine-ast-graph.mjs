/** Combine exact module nodes without inventing edges. */
export function combineGraphs(modules) {
  const graph = new Map();
  for (const module of modules.values())
    for (const [key, value] of module.nodes) graph.set(key, value);
  return graph;
}

/** Materialize only re-export chains that terminate at a parsed function node. */
export function materializeCallableExportAliases(modules, graph) {
  const aliases = new Map();
  for (const module of modules.values()) {
    for (const [alias, target] of module.exportAliases) {
      if (aliases.has(alias)) throw new Error(`duplicate production re-export alias: ${alias}`);
      aliases.set(alias, target);
    }
  }
  for (const [alias, target] of aliases) {
    if (!resolvesToFunction(alias, target, aliases, graph)) continue;
    graph.set(alias, {
      aliasTarget: target,
      capabilities: new Set(),
      capabilityCalls: [],
      edges: new Set([target]),
      key: alias,
    });
    modules.get(alias.split("#")[0]).exportedFunctionKeys.add(alias);
  }
}

/** Traverse the exact production function graph, stopping only at guarded descendants. */
export function reachable(start, graph, guarded) {
  const seen = new Set();
  const pending = [start];
  while (pending.length > 0) {
    const key = pending.pop();
    if (seen.has(key)) continue;
    seen.add(key);
    if (key !== start && guarded.has(key)) continue;
    for (const edge of graph.get(key)?.edges ?? []) pending.push(edge);
  }
  return seen;
}

function resolvesToFunction(alias, target, aliases, graph) {
  const seen = new Set([alias]);
  let current = target;
  while (aliases.has(current)) {
    if (seen.has(current)) throw new Error(`production re-export cycle: ${alias}`);
    seen.add(current);
    current = aliases.get(current);
  }
  return graph.has(current);
}
