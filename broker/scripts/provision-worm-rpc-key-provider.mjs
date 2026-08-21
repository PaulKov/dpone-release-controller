import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

import {
  canonicalWorkerVersionResourceProjectionBytes,
  projectWorkerVersionResources,
} from "./worker-version-resources.mjs";
import {
  MAX_PROVIDER_BYTES,
  UPLOAD_VERSION,
  VERSION,
} from "./provision-worm-rpc-key-constants.mjs";
import { taggedSha256 } from "./provision-worm-rpc-key-crypto.mjs";

export function uploadFinalVersion(config, secretValues, extraArguments, options, role, execute) {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "dpone-final-version-"));
  const secretsPath = join(temporaryDirectory, "secrets.json");
  const secrets = Buffer.from(`${JSON.stringify(secretValues)}\n`, "utf8");
  try {
    writeFileSync(secretsPath, secrets, { flag: "wx", mode: 0o600 });
    const wrangler = fileURLToPath(
      new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
    );
    const result = execute(
      process.execPath,
      [
        wrangler,
        "versions",
        "upload",
        "--strict",
        "--message",
        options.versionMessage,
        "--tag",
        options.versionTag,
        ...extraArguments,
        "--secrets-file",
        secretsPath,
        "--config",
        config,
      ],
      { encoding: "utf8", maxBuffer: 65_536 },
    );
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0) throw new Error(`immutable final ${role} version upload failed`);
    const matches = [...(result.stdout ?? "").matchAll(UPLOAD_VERSION)];
    UPLOAD_VERSION.lastIndex = 0;
    if (matches.length !== 1 || matches[0]?.[1] === undefined) {
      throw new Error(`Wrangler did not return one exact immutable ${role} version ID`);
    }
    return matches[0][1];
  } finally {
    secrets.fill(0);
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

/**
 * Prove that the one-use ceremony tag is absent before the first effect.
 * Wrangler intentionally exposes only the ten deployable versions; the tag is
 * therefore a ceremony nonce and no unrelated uploads are permitted until the
 * ceremony reaches READY or HOLD reconciliation completes.
 */
export function requireUnusedVersionTag(
  configPath,
  role,
  options,
  predecessorCompletedUploads,
  execute,
) {
  const listed = listTaggedVersions(configPath, role, options, execute);
  if (listed.candidates.length !== 0) {
    throw new Error(`immutable ${role} version tag was already consumed`);
  }
  if (listed.observation.listed_version_count === 10) {
    throw new Error(`immutable ${role} version absence window is saturated`);
  }
  return {
    ...listed.observation,
    outcome: "ABSENT",
    predecessor_completed_uploads: [...predecessorCompletedUploads],
  };
}

/** Resolve exactly one provider effect that may have outlived its journal write. */
export function discoverRecoverableVersion(
  configPath,
  role,
  options,
  config,
  expectedSecrets,
  variableOverrides,
  execute,
) {
  const listed = listTaggedVersions(configPath, role, options, execute);
  if (listed.candidates.length === 0) {
    if (listed.observation.listed_version_count === 10) {
      throw new Error(`immutable ${role} recovery window is saturated`);
    }
    return null;
  }
  if (listed.candidates.length !== 1) {
    throw new Error(`immutable ${role} recovery version is ambiguous`);
  }
  const versionId = listed.candidates[0];
  const version = requeryVersion(
    configPath,
    versionId,
    role,
    options,
    config,
    expectedSecrets,
    variableOverrides,
    execute,
  );
  return {
    observation: {
      list_observation: listed.observation,
      outcome: "RECOVERED_EXACT_EFFECT",
      version_observation: version,
    },
    versionId,
  };
}

function listTaggedVersions(configPath, role, options, execute) {
  const wrangler = fileURLToPath(
    new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
  );
  const result = execute(
    process.execPath,
    [wrangler, "versions", "list", "--json", "--config", configPath],
    { encoding: "utf8", maxBuffer: MAX_PROVIDER_BYTES },
  );
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`immutable ${role} version list failed`);
  const bytes = Buffer.from(result.stdout ?? "", "utf8");
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PROVIDER_BYTES) {
    throw new Error(`immutable ${role} version list size invalid`);
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`immutable ${role} version list is not UTF-8 JSON`);
  }
  if (!Array.isArray(value) || value.length > 10) {
    throw new Error(`immutable ${role} version list contract mismatch`);
  }
  const ids = new Set();
  const candidates = [];
  for (const item of value) {
    if (
      item === null ||
      typeof item !== "object" ||
      Array.isArray(item) ||
      typeof item.id !== "string" ||
      !VERSION.test(item.id) ||
      ids.has(item.id)
    ) {
      throw new Error(`immutable ${role} version list identity is ambiguous`);
    }
    ids.add(item.id);
    if (item.annotations?.["workers/tag"] !== options.versionTag) continue;
    if (item.annotations?.["workers/message"] !== options.versionMessage) {
      throw new Error(`immutable ${role} version tag has a different message`);
    }
    candidates.push(item.id);
  }
  candidates.sort();
  return {
    candidates,
    observation: {
      listed_version_count: value.length,
      matching_version_ids: [...candidates],
      raw_provider_response_sha256: taggedSha256(bytes),
      role,
    },
  };
}

export function requeryVersion(
  configPath,
  versionId,
  role,
  options,
  config,
  expectedSecrets,
  variableOverrides,
  execute,
) {
  if (typeof versionId !== "string" || !VERSION.test(versionId)) {
    throw new Error(`immutable ${role} version identity unavailable for requery`);
  }
  const wrangler = fileURLToPath(
    new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
  );
  const result = execute(
    process.execPath,
    [wrangler, "versions", "view", versionId, "--json", "--config", configPath],
    { encoding: "utf8", maxBuffer: MAX_PROVIDER_BYTES },
  );
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(`immutable ${role} version requery failed`);
  const bytes = Buffer.from(result.stdout ?? "", "utf8");
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PROVIDER_BYTES) {
    throw new Error(`immutable ${role} version requery size invalid`);
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`immutable ${role} version requery is not UTF-8 JSON`);
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.id !== versionId ||
    value.annotations?.["workers/message"] !== options.versionMessage ||
    value.annotations?.["workers/tag"] !== options.versionTag ||
    typeof value.metadata?.created_on !== "string"
  ) {
    throw new Error(`immutable ${role} version requery identity mismatch`);
  }
  const projection = projectWorkerVersionResources(
    value.resources,
    config,
    expectedSecrets,
    variableOverrides,
  );
  return {
    binding_projection: projection,
    binding_projection_sha256: taggedSha256(
      canonicalWorkerVersionResourceProjectionBytes(projection),
    ),
    created_on: value.metadata.created_on,
    raw_provider_response_sha256: taggedSha256(bytes),
    role,
    version_id: versionId,
  };
}
