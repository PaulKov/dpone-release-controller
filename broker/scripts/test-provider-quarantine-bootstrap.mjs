import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLOSURE = Object.freeze([
  "provider-quarantine-ast-boundaries.mjs",
  "provider-quarantine-ast-capabilities.mjs",
  "provider-quarantine-ast-classifier.mjs",
  "provider-quarantine-ast-core.mjs",
  "provider-quarantine-ast-effects.mjs",
  "provider-quarantine-ast-graph.mjs",
  "provider-quarantine-ast-lexical.mjs",
  "provider-quarantine-ast-ownership.mjs",
  "provider-quarantine-ast-simulations.mjs",
  "provider-quarantine-ast-utils.mjs",
  "provider-quarantine-effect-data.mjs",
  "provider-quarantine-inventory.mjs",
  "provider-quarantine-policy.mjs",
  "provider-quarantine-production-exports.mjs",
  "provider-quarantine-production-imports.mjs",
  "provider-quarantine-reviewed-data-flows-a.mjs",
  "provider-quarantine-reviewed-data-flows-b.mjs",
  "provider-quarantine-reviewed-node-digests-a.mjs",
  "provider-quarantine-reviewed-node-digests-b.mjs",
  "provider-quarantine-simulation-program.mjs",
  "provider-quarantine-simulation-purity.mjs",
]);

/** Prove changed or linked policy bytes fail before their top-level code can execute. */
export function runPreImportBootstrapRegressions(projectRoot) {
  const scratch = materializeBootstrapScratch(projectRoot);
  try {
    const marker = join(scratch, "executed");
    const policy = join(scratch, "scripts", "provider-quarantine-policy.mjs");
    writeFileSync(
      policy,
      readFileSync(policy, "utf8") +
        `\nprocess.getBuiltinModule("node:fs").writeFileSync(${JSON.stringify(marker)}, "x");\n`,
      "utf8",
    );
    const result = executeBootstrap(scratch);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /pre-import quarantine byte drift/u);
    assert.throws(() => readFileSync(marker), /ENOENT/u);
  } finally {
    rmSync(scratch, { force: true, recursive: true });
  }

  const linkedScratch = materializeBootstrapScratch(projectRoot, true);
  try {
    const result = executeBootstrap(linkedScratch);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /regular non-symlink/u);
  } finally {
    rmSync(linkedScratch, { force: true, recursive: true });
  }
}

function materializeBootstrapScratch(projectRoot, linkPolicy = false) {
  const scratch = mkdtempSync(join(tmpdir(), "dpone-quarantine-bootstrap-"));
  const scripts = join(scratch, "scripts");
  mkdirSync(scripts);
  for (const filename of [".node-version", "package.json", "pnpm-lock.yaml"]) {
    writeFileSync(join(scratch, filename), readFileSync(join(projectRoot, filename)));
  }
  writeFileSync(
    join(scripts, "verify-provider-quarantine.mjs"),
    readFileSync(join(projectRoot, "scripts", "verify-provider-quarantine.mjs")),
  );
  for (const filename of CLOSURE) {
    const source = join(projectRoot, "scripts", filename);
    const target = join(scripts, filename);
    if (linkPolicy && filename === "provider-quarantine-policy.mjs") symlinkSync(source, target);
    else writeFileSync(target, readFileSync(source));
  }
  return scratch;
}

function executeBootstrap(projectRoot) {
  return spawnSync(
    process.execPath,
    [join(projectRoot, "scripts", "verify-provider-quarantine.mjs")],
    {
      cwd: projectRoot,
      encoding: "utf8",
    },
  );
}
