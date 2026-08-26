import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

/**
 * Read only regular, non-symlink files contained directly in one reviewed
 * scripts directory. This is part of the small provider-quarantine TCB.
 */
export function readRegularContainedScripts(rootUrl, filenames) {
  if (!(rootUrl instanceof URL) || !Array.isArray(filenames)) {
    throw new TypeError("provider quarantine script reader requires a URL and filename array");
  }
  const rootInput = fileURLToPath(rootUrl);
  const root = realpathSync(rootInput);
  const rootMetadata = lstatSync(rootInput);
  if (!rootMetadata.isDirectory()) {
    throw new Error("provider quarantine scripts root must be a directory");
  }
  const sources = new Map();
  for (const filename of filenames) {
    if (typeof filename !== "string" || filename.length === 0 || basename(filename) !== filename) {
      throw new Error("provider quarantine script filename escapes the reviewed directory");
    }
    const path = join(root, filename);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`provider quarantine script must be a regular non-symlink file: ${filename}`);
    }
    const resolved = realpathSync(path);
    if (dirname(resolved) !== root) {
      throw new Error(`provider quarantine script escapes the reviewed directory: ${filename}`);
    }
    const bytes = readFileSync(resolved);
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw new Error(`provider quarantine script is not exact UTF-8: ${filename}`);
    }
    if (source.startsWith("\uFEFF")) {
      throw new Error(`provider quarantine script begins with a forbidden BOM: ${filename}`);
    }
    sources.set(filename, source);
  }
  return sources;
}
