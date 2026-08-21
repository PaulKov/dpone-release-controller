import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { LIVE_WORKERS } from "./live-worker-topology.mjs";
import {
  assertNoCredentialMaterial,
  assertPublishableDocument,
  assertPublishableLiveConfig,
  isForbiddenSecretArtifact,
} from "./publication-privacy-policy.mjs";
import { parseReviewedJsonc } from "./reviewed-jsonc.mjs";

const PROJECT_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const SKIPPED_DIRECTORIES = new Set([".wrangler", "coverage", "dist", "node_modules"]);
const SCANNED_EXTENSIONS = new Set([
  ".cjs",
  ".json",
  ".jsonc",
  ".md",
  ".mjs",
  ".ts",
  ".yaml",
  ".yml",
]);

export function runPublicationPrivacyGate(projectRoot = PROJECT_ROOT) {
  const expectedTemplates = Object.keys(LIVE_WORKERS).sort(asciiCompare);
  const actualTemplates = readdirSync(projectRoot)
    .filter((name) => /^wrangler(?:\.[a-z0-9-]+)?\.live\.jsonc$/u.test(name))
    .sort(asciiCompare);
  if (JSON.stringify(actualTemplates) !== JSON.stringify(expectedTemplates)) {
    throw new Error("publishable live review-template inventory drift");
  }
  for (const filename of expectedTemplates) {
    const path = resolve(projectRoot, filename);
    const source = readFileSync(path, "utf8");
    assertPublishableLiveConfig(filename, source, parseReviewedJsonc(source, filename));
  }

  const files = listRegularFiles(projectRoot);
  for (const path of files) {
    const displayPath = relative(projectRoot, path).split(sep).join("/");
    if (isForbiddenSecretArtifact(displayPath)) {
      throw new Error(`secret-bearing artifact must not be published: ${displayPath}`);
    }
    if (!SCANNED_EXTENSIONS.has(extname(path)) && ![".gitignore", ".npmrc"].includes(displayPath)) {
      continue;
    }
    const source = readFileSync(path, "utf8");
    assertNoCredentialMaterial(displayPath, source);
    if (displayPath === "README.md" || displayPath.startsWith("docs/")) {
      assertPublishableDocument(displayPath, source);
    }
  }
  return { files: files.length, templates: expectedTemplates.length };
}

function listRegularFiles(root) {
  const files = [];
  visit(root, files);
  return files.sort(asciiCompare);
}

function visit(directory, files) {
  for (const name of readdirSync(directory).sort(asciiCompare)) {
    if (SKIPPED_DIRECTORIES.has(name)) continue;
    const path = resolve(directory, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink())
      throw new Error(`publication tree contains a symbolic link: ${path}`);
    if (stat.isDirectory()) visit(path, files);
    else if (stat.isFile()) files.push(path);
    else throw new Error(`publication tree contains a non-regular entry: ${path}`);
  }
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = runPublicationPrivacyGate();
    process.stdout.write(
      `publication privacy gate: ${result.templates} review templates / ${result.files} files PASS\n`,
    );
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
