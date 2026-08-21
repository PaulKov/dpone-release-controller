import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";

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

process.stdout.write("publication privacy regressions: PASS\n");
