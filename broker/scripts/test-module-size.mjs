import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  assessModules,
  countSourceLines,
  formatViolations,
  scanModules,
} from "./check-module-size.mjs";

const moduleOf = (path, physical, nonblank = physical) => ({
  path,
  source: [
    ...Array.from({ length: nonblank }, () => "const value = 1;"),
    ...Array.from({ length: physical - nonblank }, () => "   "),
  ].join("\n"),
});

assert.deepEqual(countSourceLines("one\n \n\t\ntwo\n"), { nonblank: 2, physical: 4 });
assert.equal(assessModules([moduleOf("pass-physical.ts", 400, 350)]).length, 0);
assert.equal(assessModules([moduleOf("fail-physical.ts", 401, 350)])[0]?.physical, 401);
assert.equal(assessModules([moduleOf("fail-nonblank.ts", 351, 351)])[0]?.nonblank, 351);
assert.equal(assessModules([moduleOf("pass-nonblank.ts", 350, 350)]).length, 0);

const ordered = assessModules([moduleOf("test/z.ts", 401, 1), moduleOf("scripts/a.mjs", 401, 1)]);
assert.deepEqual(
  ordered.map(({ path }) => path),
  ["scripts/a.mjs", "test/z.ts"],
);
assert.equal(
  formatViolations(ordered),
  [
    "module size gate failed (2)",
    "scripts/a.mjs: physical=401/400 nonblank=1/350",
    "test/z.ts: physical=401/400 nonblank=1/350",
  ].join("\n"),
);

const fixtureRoot = await mkdtemp(join(tmpdir(), "module-size-gate-"));
try {
  for (const root of ["src", "scripts", "test"]) await mkdir(join(fixtureRoot, root));
  await writeFile(join(fixtureRoot, "src", "z.ts"), "z\n", "utf8");
  await writeFile(join(fixtureRoot, "src", "a.ts"), "a\n", "utf8");
  await writeFile(join(fixtureRoot, "scripts", "ignored.txt"), "ignored\n", "utf8");
  const scanned = await scanModules(fixtureRoot);
  assert.deepEqual(
    scanned.map(({ path }) => path),
    ["src/a.ts", "src/z.ts"],
  );

  await writeFile(join(fixtureRoot, "test", "invalid.ts"), Uint8Array.of(0xff));
  await assert.rejects(scanModules(fixtureRoot), /invalid UTF-8 module: test\/invalid\.ts/u);
  await rm(join(fixtureRoot, "test", "invalid.ts"));

  await symlink(join(fixtureRoot, "src", "a.ts"), join(fixtureRoot, "test", "linked.ts"));
  await assert.rejects(scanModules(fixtureRoot), /symbolic link rejected: test\/linked\.ts/u);
} finally {
  await rm(fixtureRoot, { force: true, recursive: true });
}

process.stdout.write("module size gate synthetic boundaries: PASS\n");
