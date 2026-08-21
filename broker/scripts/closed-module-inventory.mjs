/** Verify an exact, reachable same-family module closure without weakening semantic checks. */
export function assertClosedModuleInventory({ actual, boundary, inventory, root, sources }) {
  const expected = sortedUnique(inventory, "module inventory");
  const discovered = sortedUnique(actual, "discovered module inventory");
  if (JSON.stringify(expected) !== JSON.stringify(discovered)) {
    throw new Error("closed module inventory has missing or extra files");
  }
  if (!expected.includes(root)) throw new Error("closed module inventory root is absent");
  if (!(sources instanceof Map) || sources.size !== expected.length) {
    throw new Error("closed module inventory source map mismatch");
  }

  const edges = new Map();
  for (const filename of expected) {
    const source = sources.get(filename);
    if (typeof source !== "string") throw new Error(`closed module source missing: ${filename}`);
    const imports = relativeModuleImports(source);
    for (const imported of imports) {
      boundary.lastIndex = 0;
      if (boundary.test(imported) && !expected.includes(imported)) {
        throw new Error(`closed module import escapes inventory: ${filename} -> ${imported}`);
      }
    }
    edges.set(
      filename,
      imports.filter((imported) => expected.includes(imported)),
    );
  }

  const reachable = new Set();
  const pending = [root];
  while (pending.length > 0) {
    const filename = pending.pop();
    if (filename === undefined || reachable.has(filename)) continue;
    reachable.add(filename);
    pending.push(...(edges.get(filename) ?? []));
  }
  const unreachable = expected.filter((filename) => !reachable.has(filename));
  if (unreachable.length > 0) {
    throw new Error(
      `closed module inventory contains unreachable files: ${unreachable.join(", ")}`,
    );
  }
  return expected;
}

export function relativeModuleImports(source) {
  const imports = [];
  const pattern = /(?:from\s+|import\s*(?:\(\s*)?)["']\.\/([^"']+\.mjs)["']/gu;
  for (const match of source.matchAll(pattern)) {
    if (match[1] !== undefined) imports.push(match[1]);
  }
  return [...new Set(imports)].sort(asciiCompare);
}

function sortedUnique(values, name) {
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    throw new Error(`${name} must contain filenames`);
  }
  const sorted = [...values].sort(asciiCompare);
  if (new Set(sorted).size !== sorted.length) throw new Error(`${name} contains duplicates`);
  return sorted;
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
