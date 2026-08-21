import { strict as assert } from "node:assert";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { runPublicationPrivacyGate } from "./check-publication-privacy.mjs";
import { LIVE_WORKERS } from "./live-worker-topology.mjs";
import {
  assertNoCredentialMaterial,
  assertPublishableDocument,
  assertPublishableLiveConfig,
} from "./publication-privacy-policy.mjs";
import { PUBLICATION_REVIEW_TEMPLATE_HEADER, parseReviewedJsonc } from "./reviewed-jsonc.mjs";

const filename = "wrangler.candidate-reader.live.jsonc";
const source = readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
const config = parseReviewedJsonc(source, filename);

assert.doesNotThrow(() => assertPublishableLiveConfig(filename, source, config));

assert.throws(
  () =>
    assertPublishableLiveConfig(filename, source, {
      ...config,
      account_id: "a".repeat(32),
    }),
  /real or unclassified account ID/u,
);

assert.throws(
  () =>
    assertPublishableLiveConfig(filename, source, {
      ...config,
      vars: { ...config.vars, UNCLASSIFIED_PROVIDER_ID: "9000000000000099" },
    }),
  /unclassified identifier field/u,
);

assert.throws(
  () => parseReviewedJsonc(`// arbitrary comment\n{}\n`, "unreviewed.jsonc"),
  /comments are forbidden/u,
);
assert.deepEqual(
  parseReviewedJsonc(`${PUBLICATION_REVIEW_TEMPLATE_HEADER}\n{}\n`, "review-template.jsonc"),
  {},
);

assert.throws(
  () => assertPublishableDocument("architecture.md", "No checked-in live Wrangler config exists."),
  /stale live-config claim/u,
);
assert.throws(
  () =>
    assertNoCredentialMaterial(
      "leaked.pem",
      "-----BEGIN PRIVATE KEY-----\n" +
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n".repeat(4) +
        "-----END PRIVATE KEY-----\n",
    ),
  /probable credential material/u,
);

const projectRoot = resolve(new URL("..", import.meta.url).pathname);
const scratchRoot = mkdtempSync(`${tmpdir()}/dpone-publication-privacy-`);
try {
  for (const filename of Object.keys(LIVE_WORKERS)) {
    copyFileSync(resolve(projectRoot, filename), resolve(scratchRoot, filename));
  }
  mkdirSync(resolve(scratchRoot, "nested"));
  writeFileSync(resolve(scratchRoot, ".node-version"), "24.19.0\n", "utf8");
  writeFileSync(resolve(scratchRoot, ".prettierignore"), "coverage\n", "utf8");
  writeFileSync(resolve(scratchRoot, "nested/safe.js"), "export const safe = true;\n", "utf8");
  writeFileSync(resolve(scratchRoot, "nested/safe.py"), "SAFE = True\n", "utf8");
  assert.deepEqual(runPublicationPrivacyGate(scratchRoot), {
    files: Object.keys(LIVE_WORKERS).length + 4,
    scanned: Object.keys(LIVE_WORKERS).length + 4,
    templates: Object.keys(LIVE_WORKERS).length,
  });

  const githubToken = "gh" + "p_" + "A".repeat(30);
  assertScratchFailure("nested/leak.js", `const token = "${githubToken}";\n`, /credential/u);
  assertScratchFailure(
    "nested/leak.py",
    `ISSUER = "https://${"dpone" + ".cloudflareaccess.com"}"\n`,
    /publication identifier/u,
  );
  assertScratchFailure(".npmrc", `_authToken=${"x".repeat(32)}\n`, /credential/u);
  assertScratchFailure(".unknown-review-file", "plain text\n", /unclassified/u);
  assertScratchFailure("nested/unclassified.bin", "plain text\n", /unclassified/u);
  assertScratchFailure("nested/invalid.js", Buffer.from([0xc3, 0x28]), /exact UTF-8/u);
  mkdirSync(resolve(scratchRoot, "nested/dist"));
  assertScratchFailure("nested/dist/leak.js", `const token = "${githubToken}";\n`, /credential/u);
  rmSync(resolve(scratchRoot, "nested/dist"), { recursive: true });

  const symlinkPath = resolve(scratchRoot, "nested/link.js");
  symlinkSync(resolve(scratchRoot, "nested/safe.js"), symlinkPath);
  assert.throws(() => runPublicationPrivacyGate(scratchRoot), /symbolic link/u);
  rmSync(symlinkPath);

  const skippedSymlink = resolve(scratchRoot, "node_modules");
  symlinkSync(resolve(scratchRoot, "nested"), skippedSymlink);
  assert.throws(() => runPublicationPrivacyGate(scratchRoot), /cache exclusion/u);
  rmSync(skippedSymlink);
} finally {
  rmSync(scratchRoot, { force: true, recursive: true });
}

process.stdout.write("publication privacy regressions: PASS\n");

function assertScratchFailure(relativePath, contents, pattern) {
  const path = resolve(scratchRoot, relativePath);
  writeFileSync(path, contents);
  assert.throws(() => runPublicationPrivacyGate(scratchRoot), pattern);
  rmSync(path);
}
