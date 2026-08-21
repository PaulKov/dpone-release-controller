import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

export const root = new URL("..", import.meta.url);
export const script = new URL("./provision-worm-rpc-key.mjs", import.meta.url);
export const configs = Object.freeze({
  cloudflareObserver: {
    dry: new URL("../wrangler.cloudflare-deployment-observer.jsonc", import.meta.url),
    live: new URL("../wrangler.cloudflare-deployment-observer.live.jsonc", import.meta.url),
    main: "src/private/cloudflare-deployment-observer-worker.ts",
    name: "dpone-release-cloudflare-deployment-observer",
  },
  ingress: {
    dry: new URL("../wrangler.jsonc", import.meta.url),
    live: new URL("../wrangler.live.jsonc", import.meta.url),
    main: "src/index.ts",
    name: "dpone-release-authority-broker",
  },
  observer: {
    dry: new URL("../wrangler.worm-version-observer.jsonc", import.meta.url),
    live: new URL("../wrangler.worm-version-observer.live.jsonc", import.meta.url),
    main: "src/private/worm-version-observer-worker.ts",
    name: "dpone-release-worm-version-observer",
  },
  worm: {
    dry: new URL("../wrangler.worm-mirror.jsonc", import.meta.url),
    live: new URL("../wrangler.worm-mirror.live.jsonc", import.meta.url),
    main: "src/private/worm-mirror-worker.ts",
    name: "dpone-release-worm-mirror",
  },
});
export const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
export const BUCKET_ID = "0123456789abcdef01234567";
export const BUCKET_NAME = "dpone-release-evidence";
export const RPC_KEY = Buffer.from(Array.from({ length: 32 }, (_value, index) => index));
export const OBSERVER_RPC_KEY = Buffer.alloc(32, 0x31);
export const EVIDENCE_RPC_KEY = Buffer.alloc(32, 0x32);
export const CLOUDFLARE_TOKEN = "cloudflare_read_only_token_abcdefghijklmnopqrstuvwxyz";
export const CLOUDFLARE_TOKEN_FINGERPRINT = taggedSha256(Buffer.from(CLOUDFLARE_TOKEN, "utf8"));
export const ZONE_ID = "fedcba9876543210fedcba9876543210";
export const NOW = Date.parse("2026-08-19T12:00:30.000Z");
export const WRITER = Object.freeze({
  application_key: "writerapplicationkey000000000001",
  key_id: "writerkeyid000001",
});
export const OBSERVER = Object.freeze({
  application_key: "observerapplicationkey0000000001",
  key_id: "observerkeyid0001",
});
export const VERSION_IDS = Object.freeze({
  cloudflareObserver: "123e4567-e89b-42d3-a456-426614174003",
  ingress: "123e4567-e89b-42d3-a456-426614174000",
  observer: "123e4567-e89b-42d3-a456-426614174001",
  worm: "123e4567-e89b-42d3-a456-426614174002",
});
export const BOOTSTRAP_IDS = Object.freeze({
  cloudflareObserver: "123e4567-e89b-42d3-a456-426614174013",
  ingress: "123e4567-e89b-42d3-a456-426614174010",
  observer: "123e4567-e89b-42d3-a456-426614174011",
  worm: "123e4567-e89b-42d3-a456-426614174012",
});
export const ROLES = Object.freeze(["ingress", "observer", "cloudflareObserver", "worm"]);
export const CONFIG_BYTES = Object.freeze(
  Object.fromEntries(
    Object.keys(configs).map((role) => [
      role,
      Buffer.from(`reviewed final ${role} config\n`, "utf8"),
    ]),
  ),
);
export const MAIN_BYTES = Object.freeze(
  Object.fromEntries(
    Object.entries(configs).map(([role, config]) => [
      role,
      readFileSync(resolve(root.pathname, config.main)),
    ]),
  ),
);
export const BOOTSTRAP_BYTES = Object.freeze({
  cloudflareObserver: readFileSync(new URL("../src/bootstrap-private.ts", import.meta.url)),
  ingress: readFileSync(new URL("../src/bootstrap-ingress.ts", import.meta.url)),
  observer: readFileSync(new URL("../src/bootstrap-private.ts", import.meta.url)),
  worm: readFileSync(new URL("../src/bootstrap-worm.ts", import.meta.url)),
});
export const temporaryDirectory = mkdtempSync(`${tmpdir()}/dpone-authority-keys-test-`);
export const paths = Object.freeze({
  adminPrincipals: `${temporaryDirectory}/admin-principals.json`,
  bootstrap: `${temporaryDirectory}/bootstrap-report.json`,
  cloudflareEvidenceRpc: `${temporaryDirectory}/cloudflare-evidence-rpc.key`,
  cloudflareObserverPolicy: `${temporaryDirectory}/cloudflare-observer-policy.json`,
  cloudflareObserverRestriction: `${temporaryDirectory}/cloudflare-observer-restriction.json`,
  cloudflareObserverRpc: `${temporaryDirectory}/cloudflare-observer-rpc.key`,
  cloudflareObserverToken: `${temporaryDirectory}/cloudflare-observer-token.json`,
  observerEvidence: `${temporaryDirectory}/observer-evidence.json`,
  observerSecret: `${temporaryDirectory}/observer-secret.json`,
  result: `${temporaryDirectory}/ceremony-result.json`,
  rpc: `${temporaryDirectory}/worm-rpc.key`,
  writerEvidence: `${temporaryDirectory}/writer-evidence.json`,
  writerSecret: `${temporaryDirectory}/writer-secret.json`,
});

export function argumentsFor(apply, resultPath = paths.result) {
  const selected = (role) => configs[role][apply ? "live" : "dry"].pathname;
  return [
    script.pathname,
    "--admin-access-principals",
    paths.adminPrincipals,
    "--cloudflare-evidence-rpc-key",
    paths.cloudflareEvidenceRpc,
    "--cloudflare-observer-config",
    selected("cloudflareObserver"),
    "--cloudflare-observer-restriction-evidence",
    paths.cloudflareObserverRestriction,
    "--cloudflare-observer-rpc-key",
    paths.cloudflareObserverRpc,
    "--cloudflare-observer-token",
    paths.cloudflareObserverToken,
    "--input",
    paths.rpc,
    "--writer-secret",
    paths.writerSecret,
    "--observer-secret",
    paths.observerSecret,
    "--writer-restriction-evidence",
    paths.writerEvidence,
    "--observer-restriction-evidence",
    paths.observerEvidence,
    "--ingress-config",
    selected("ingress"),
    "--observer-config",
    selected("observer"),
    "--worm-config",
    selected("worm"),
    "--version-tag",
    "authority-keys-test-v1",
    "--version-message",
    "reviewed authority key ceremony",
    ...(apply
      ? [
          "--bootstrap-report",
          paths.bootstrap,
          "--cloudflare-observer-provider-policy-evidence",
          paths.cloudflareObserverPolicy,
          "--result",
          resultPath,
          "--apply",
        ]
      : []),
  ];
}

export function dependencies() {
  return {
    loadLiveWorkerConfig: (path) => {
      const [role, definition] = Object.entries(configs).find(
        ([, config]) => config.live.pathname === path,
      );
      assert.ok(role !== undefined && definition !== undefined);
      return {
        config: {
          account_id: ACCOUNT_ID,
          compatibility_date: "2026-08-15",
          main: definition.main,
          name: definition.name,
          version_metadata: { binding: "CF_VERSION_METADATA" },
          ...liveRoleConfig(role, definition),
        },
        expectedName: definition.name,
        path,
      };
    },
    now: () => NOW,
    readFileSync: exactRead,
    writeOutput: () => undefined,
  };
}

export function liveRoleConfig(role, definition) {
  if (role === "ingress") {
    return {
      durable_objects: {
        bindings: [
          { class_name: "ActivationRegistry", name: "ACTIVATION_REGISTRY" },
          { class_name: "AuthReplayLedger", name: "AUTH_REPLAY_LEDGER" },
          {
            class_name: "GlobalActivatedAuthorityHead",
            name: "GLOBAL_ACTIVATED_AUTHORITY_HEAD",
          },
          { class_name: "ReleaseLedger", name: "RELEASE_LEDGERS" },
        ],
      },
      migrations: [
        { new_sqlite_classes: ["AuthReplayLedger", "ReleaseLedger"], tag: "v1" },
        { new_sqlite_classes: ["ActivationRegistry"], tag: "v2" },
        { new_sqlite_classes: ["GlobalActivatedAuthorityHead"], tag: "v3" },
      ],
      routes: [{ custom_domain: true, pattern: "release.example.test" }],
      vars: { ADMIN_HOSTNAME: "release.example.test", OPERATING_MODE: "live" },
    };
  }
  if (role === "cloudflareObserver") {
    return {
      services: [{ binding: "WORM_MIRROR", service: configs.worm.name }],
      vars: {
        APPROVED_INGRESS_HOSTNAME: "release.example.test",
        APPROVED_INGRESS_ZONE_ID: ZONE_ID,
        CF_ACCOUNT_ID: ACCOUNT_ID,
        EXPECTED_INGRESS_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
        OPERATING_MODE: "live",
        SERVICE_NAME: definition.name,
      },
    };
  }
  if (role === "observer") {
    return {
      vars: {
        B2_BUCKET_ID: BUCKET_ID,
        B2_BUCKET_NAME: BUCKET_NAME,
        OPERATING_MODE: "live",
      },
    };
  }
  return {
    durable_objects: {
      bindings: [
        { class_name: "CloudflareEvidenceBatch", name: "CLOUDFLARE_EVIDENCE_BATCHES" },
        { class_name: "WormExactObjectEffect", name: "WORM_EXACT_OBJECT_EFFECTS" },
      ],
    },
    migrations: [
      { new_sqlite_classes: ["CloudflareEvidenceBatch"], tag: "v1" },
      { new_sqlite_classes: ["WormExactObjectEffect"], tag: "v2" },
    ],
    services: [{ binding: "WORM_VERSION_OBSERVER", service: configs.observer.name }],
    vars: {
      B2_BUCKET_ID: BUCKET_ID,
      B2_BUCKET_NAME: BUCKET_NAME,
      OPERATING_MODE: "live",
      SERVICE_NAME: definition.name,
      WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
      WORM_EXPECTED_CALLER_SERVICE_IDENTITY: "INJECTED_BY_WORM_RPC_KEY_CEREMONY",
      WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY: "INJECTED_BY_AUTHORITY_VERSION_CEREMONY",
    },
  };
}

export function exactRead(path) {
  const matched = Object.entries(configs).find(([, config]) => config.live.pathname === path);
  if (matched !== undefined) return CONFIG_BYTES[matched[0]];
  return readFileSync(path);
}

export function writePrivate(path, value) {
  writeFileSync(path, value, { mode: 0o600 });
}

export function uploadCounts(value) {
  return { cloudflareObserver: value, ingress: value, observer: value, worm: value };
}

export function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

export function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

export function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function parseJournal(bytes) {
  const source = bytes.toString("utf8");
  assert.equal(source.endsWith("\n"), true);
  return source
    .slice(0, -1)
    .split("\n")
    .map((line) => JSON.parse(line));
}

export function expectTerminalJournal(bytes) {
  const entries = parseJournal(bytes);
  assert.equal(entries.at(-1).status, "READY_FOR_PRIVATE_PREFLIGHT");
  assert.equal(entries.filter((entry) => entry.status === "READY_FOR_PRIVATE_PREFLIGHT").length, 1);
}

export function cleanupFixture() {
  RPC_KEY.fill(0);
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
