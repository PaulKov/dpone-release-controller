import { regionEntries } from "./provider-quarantine-ast-utils.mjs";

const wordSet = (source) => new Set(source.split(" "));

const READ_ONLY_FS_CALLS = wordSet(
  "access accessSync existsSync fstat fstatSync glob globSync lstat lstatSync opendir opendirSync read readFile readFileSync readSync readdir readdirSync readlink readlinkSync readv readvSync realpath realpathSync stat statSync statfs statfsSync",
);
const NETWORK_MODULES = /^(?:node:)?(?:dgram|dns|http|http2|https|net|quic|tls)(?:\/|$)/u;
const EXECUTION_MODULES = /^(?:node:)?(?:cluster|module|vm|worker_threads)(?:\/|$)/u;

export const GLOBAL_EFFECT_CONSTRUCTORS = wordSet(
  "BroadcastChannel EventSource Function SharedWorker WebSocket Worker XMLHttpRequest",
);
export const GLOBAL_EFFECT_ROOTS = new Set(["Bun", "Deno", "global", "self", "window"]);
export const PROCESS_LOADER_METHODS = wordSet(
  "_linkedBinding binding dlopen getBuiltinModule mainModule require",
);

/** Classify every imported capability; filesystem reads are review-scoped, never globally safe. */
export function importedCapability({ imported, source }) {
  if (source === "node:child_process" || source === "child_process") {
    return `child-process:${imported}`;
  }
  if (source === "node:fs" || source === "fs" || source.includes("fs/promises")) {
    if (imported === "constants") return "filesystem-read:constants";
    return READ_ONLY_FS_CALLS.has(imported)
      ? `filesystem-read:${imported}`
      : `filesystem-capability:${imported}`;
  }
  if (
    (source === "node:module" || source === "module") &&
    ["createRequire", "default"].includes(imported)
  ) {
    return `module-loader:${imported}`;
  }
  if (NETWORK_MODULES.test(source)) return `network-module:${source}:${imported}`;
  if (EXECUTION_MODULES.test(source)) return `execution-module:${source}:${imported}`;
  return null;
}

export function firstOrigin(origins, prefix) {
  return [...origins].find((origin) => origin.startsWith(prefix));
}

/** Permit exact verifier data reads/output, never provider/network/write/dynamic effects. */
export function isReviewedLocalCapability(capability) {
  return (
    capability.startsWith("injected-reference:") ||
    capability.startsWith("injected-call:") ||
    capability.startsWith("filesystem-read:") ||
    capability.startsWith("intrinsic-reference:") ||
    capability.startsWith("intrinsic-prototype-reference:") ||
    capability === "native-entry-dispatch:process.argv[1]" ||
    [
      "ambient-call:ambient:process.stderr.write",
      "ambient-call:ambient:process.stdout.write",
      "ambient-computed-reference:ambient:process.argv",
      "ambient-reference:ambient:process.argv.?",
      "ambient-reference:ambient:process.argv.length",
      "ambient-reference:ambient:process.exitCode",
    ].includes(capability)
  );
}

/** Reject all mutation syntax and unpinned member access in provider module scope. */
export function assertEffectModuleScope(filename, program, skipped) {
  const reviewedMembers = reviewedModuleMembers(program);
  for (const { node } of regionEntries(program, skipped)) {
    if (
      node.type === "AssignmentExpression" ||
      node.type === "UpdateExpression" ||
      (node.type === "UnaryExpression" && node.operator === "delete")
    ) {
      throw new Error(`provider effect module mutates state before HOLD: ${filename}`);
    }
    if (node.type === "MemberExpression" && !reviewedMembers.has(node) && !isImportMetaUrl(node)) {
      throw new Error(`provider effect module reads an unpinned member before HOLD: ${filename}`);
    }
  }
}

function reviewedModuleMembers(program) {
  const members = new WeakSet();
  for (const statement of program.body) {
    const declaration = statement.type === "ExportNamedDeclaration" ? statement.declaration : null;
    if (declaration?.type === "VariableDeclaration") {
      for (const item of declaration.declarations) addMembers(item.init, members);
    }
    if (isNativeEntryStatement(statement)) addMembers(statement.test, members);
  }
  return members;
}

function addMembers(root, members) {
  for (const { node } of regionEntries(root)) {
    if (node.type === "MemberExpression") members.add(node);
  }
}

function isNativeEntryStatement(statement) {
  const expression = statement.consequent?.body?.[0]?.expression;
  const invocation = expression?.type === "AwaitExpression" ? expression.argument : expression;
  return (
    statement.type === "IfStatement" &&
    statement.alternate === null &&
    statement.consequent.type === "BlockStatement" &&
    statement.consequent.body.length === 1 &&
    invocation?.type === "CallExpression" &&
    invocation.optional !== true &&
    invocation.callee.type === "Identifier" &&
    invocation.callee.name === "main" &&
    invocation.arguments.length === 0 &&
    isNativeEntryTest(statement.test)
  );
}

function isNativeEntryTest(test) {
  return (
    test.type === "LogicalExpression" &&
    test.operator === "&&" &&
    test.left.type === "BinaryExpression" &&
    test.left.operator === "!==" &&
    isProcessArgvOne(test.left.left) &&
    test.left.right.type === "Identifier" &&
    test.left.right.name === "undefined" &&
    test.right.type === "BinaryExpression" &&
    test.right.operator === "===" &&
    isExactCall(test.right.left, "resolve", isProcessArgvOne) &&
    isExactCall(test.right.right, "fileURLToPath", isImportMetaUrl)
  );
}

function isExactCall(node, name, argumentCheck) {
  return (
    node.type === "CallExpression" &&
    node.optional !== true &&
    node.callee.type === "Identifier" &&
    node.callee.name === name &&
    node.arguments.length === 1 &&
    argumentCheck(node.arguments[0])
  );
}

function isProcessArgvOne(node) {
  return (
    node?.type === "MemberExpression" &&
    node.computed &&
    node.object.type === "MemberExpression" &&
    !node.object.computed &&
    node.object.object.type === "Identifier" &&
    node.object.object.name === "process" &&
    node.object.property.type === "Identifier" &&
    node.object.property.name === "argv" &&
    node.property.type === "Literal" &&
    node.property.value === 1
  );
}

function isImportMetaUrl(node) {
  return (
    node?.type === "MemberExpression" &&
    !node.computed &&
    node.object.type === "MetaProperty" &&
    node.object.meta.name === "import" &&
    node.object.property.name === "meta" &&
    node.property.type === "Identifier" &&
    node.property.name === "url"
  );
}
