import { lstat, readFile, readdir } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

export const MODULE_SIZE_LIMITS = Object.freeze({ nonblank: 350, physical: 400 });
export const SCAN_ROOTS = Object.freeze(["src", "scripts", "test"]);
const MODULE_EXTENSIONS = Object.freeze([".mjs", ".ts"]);

export function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function countSourceLines(source) {
  const lines = source === "" ? [] : source.replace(/\r\n?/gu, "\n").split("\n");
  if (lines.at(-1) === "") lines.pop();
  return {
    nonblank: lines.reduce((count, line) => count + (line.trim() === "" ? 0 : 1), 0),
    physical: lines.length,
  };
}

export function assessModules(modules, limits = MODULE_SIZE_LIMITS) {
  return [...modules]
    .map((module) => ({ ...module, ...countSourceLines(module.source) }))
    .filter((module) => module.physical > limits.physical || module.nonblank > limits.nonblank)
    .sort((left, right) => asciiCompare(left.path, right.path));
}

export async function scanModules(projectRoot, roots = SCAN_ROOTS) {
  const absoluteProjectRoot = resolve(projectRoot);
  const seen = new Set();
  const modules = [];
  for (const root of [...roots].sort(asciiCompare)) {
    const absoluteRoot = resolve(absoluteProjectRoot, root);
    if (!isWithin(absoluteProjectRoot, absoluteRoot)) {
      throw new Error(`scan root escapes project: ${root}`);
    }
    await visit(absoluteRoot, absoluteProjectRoot, seen, modules);
  }
  return modules.sort((left, right) => asciiCompare(left.path, right.path));
}

export function formatViolations(violations, limits = MODULE_SIZE_LIMITS) {
  const rows = violations.map(
    ({ path, physical, nonblank }) =>
      `${path}: physical=${physical}/${limits.physical} nonblank=${nonblank}/${limits.nonblank}`,
  );
  return [`module size gate failed (${rows.length})`, ...rows].join("\n");
}

export async function runModuleSizeGate(projectRoot) {
  const modules = await scanModules(projectRoot);
  const violations = assessModules(modules);
  if (violations.length > 0) throw new Error(formatViolations(violations));
  return modules.length;
}

async function visit(directory, projectRoot, seen, modules) {
  const directoryStat = await lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error(`scan root is not a regular directory: ${displayPath(projectRoot, directory)}`);
  }
  const entries = await readdir(directory);
  entries.sort(asciiCompare);
  for (const name of entries) {
    const absolutePath = resolve(directory, name);
    const path = displayPath(projectRoot, absolutePath);
    if (seen.has(path)) throw new Error(`duplicate module path: ${path}`);
    const stat = await lstat(absolutePath);
    if (stat.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
    if (stat.isDirectory()) {
      await visit(absolutePath, projectRoot, seen, modules);
      continue;
    }
    if (!stat.isFile()) throw new Error(`non-regular path rejected: ${path}`);
    if (!MODULE_EXTENSIONS.some((extension) => name.endsWith(extension))) continue;
    seen.add(path);
    const bytes = await readFile(absolutePath);
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new Error(`invalid UTF-8 module: ${path}`);
    }
    modules.push({ path, source });
  }
}

function displayPath(projectRoot, absolutePath) {
  return relative(projectRoot, absolutePath).split(sep).join("/");
}

function isWithin(parent, child) {
  const path = relative(parent, child);
  return path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

const invokedPath =
  process.argv[1] === undefined ? null : pathToFileURL(resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
  const projectRoot = fileURLToPath(new URL("../", import.meta.url));
  try {
    const count = await runModuleSizeGate(projectRoot);
    process.stdout.write(`module size gate: ${count} modules PASS\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
