import { basename, resolve } from "node:path";

import { DRY_CONFIGS, LIVE_CONFIGS, PROJECT_ROOT } from "./provision-worm-rpc-key-constants.mjs";

export function parseArguments(arguments_) {
  const values = new Map();
  let apply = false;
  let recover = false;
  const allowed = new Set([
    "--admin-access-principals",
    "--bootstrap-report",
    "--cloudflare-evidence-rpc-key",
    "--cloudflare-observer-config",
    "--cloudflare-observer-provider-policy-evidence",
    "--cloudflare-observer-restriction-evidence",
    "--cloudflare-observer-rpc-key",
    "--cloudflare-observer-token",
    "--ingress-config",
    "--input",
    "--observer-config",
    "--observer-restriction-evidence",
    "--observer-secret",
    "--result",
    "--version-message",
    "--version-tag",
    "--worm-config",
    "--writer-restriction-evidence",
    "--writer-secret",
  ]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--apply") {
      if (apply) throw new Error(usage());
      apply = true;
      continue;
    }
    if (argument === "--recover") {
      if (recover) throw new Error(usage());
      recover = true;
      continue;
    }
    if (!allowed.has(argument)) throw new Error(usage());
    const value = arguments_[index + 1];
    if (value === undefined || value.startsWith("--") || values.has(argument)) {
      throw new Error(usage());
    }
    values.set(argument, value);
    index += 1;
  }
  const configs = apply ? LIVE_CONFIGS : DRY_CONFIGS;
  const ingressConfig = reviewedConfig(values.get("--ingress-config"), configs.get("ingress"));
  const observerConfig = reviewedConfig(values.get("--observer-config"), configs.get("observer"));
  const cloudflareObserverConfig = reviewedConfig(
    values.get("--cloudflare-observer-config"),
    configs.get("cloudflareObserver"),
  );
  const wormConfig = reviewedConfig(values.get("--worm-config"), configs.get("worm"));
  const requiredPaths = [
    "--admin-access-principals",
    "--cloudflare-evidence-rpc-key",
    "--cloudflare-observer-restriction-evidence",
    "--cloudflare-observer-rpc-key",
    "--cloudflare-observer-token",
    "--input",
    "--observer-restriction-evidence",
    "--observer-secret",
    "--writer-restriction-evidence",
    "--writer-secret",
  ];
  const versionMessage = values.get("--version-message");
  const versionTag = values.get("--version-tag");
  const bootstrapReport = values.get("--bootstrap-report");
  const cloudflareProviderPolicyEvidence = values.get(
    "--cloudflare-observer-provider-policy-evidence",
  );
  const result = values.get("--result");
  if (
    requiredPaths.some((name) => values.get(name) === undefined) ||
    (apply &&
      (bootstrapReport === undefined ||
        cloudflareProviderPolicyEvidence === undefined ||
        result === undefined)) ||
    (!apply &&
      (bootstrapReport !== undefined ||
        cloudflareProviderPolicyEvidence !== undefined ||
        result !== undefined)) ||
    (recover && !apply) ||
    versionMessage === undefined ||
    versionTag === undefined ||
    !/^[ -~]{8,128}$/u.test(versionMessage) ||
    !/^[a-z0-9][a-z0-9._-]{7,63}$/u.test(versionTag)
  ) {
    throw new Error(usage());
  }
  return {
    adminAccessPrincipals: resolve(values.get("--admin-access-principals")),
    apply,
    bootstrapReport: bootstrapReport === undefined ? null : resolve(bootstrapReport),
    cloudflareEvidenceRpcKey: resolve(values.get("--cloudflare-evidence-rpc-key")),
    cloudflareObserverConfig,
    cloudflareObserverProviderPolicyEvidence:
      cloudflareProviderPolicyEvidence === undefined
        ? null
        : resolve(cloudflareProviderPolicyEvidence),
    cloudflareObserverRestrictionEvidence: resolve(
      values.get("--cloudflare-observer-restriction-evidence"),
    ),
    cloudflareObserverRpcKey: resolve(values.get("--cloudflare-observer-rpc-key")),
    cloudflareObserverToken: resolve(values.get("--cloudflare-observer-token")),
    ingressConfig,
    input: resolve(values.get("--input")),
    observerConfig,
    observerRestrictionEvidence: resolve(values.get("--observer-restriction-evidence")),
    observerSecret: resolve(values.get("--observer-secret")),
    recover,
    result: result === undefined ? null : resolve(result),
    versionMessage,
    versionTag,
    wormConfig,
    writerRestrictionEvidence: resolve(values.get("--writer-restriction-evidence")),
    writerSecret: resolve(values.get("--writer-secret")),
  };
}
function reviewedConfig(value, expectedName) {
  const path = value === undefined ? undefined : resolve(value);
  if (
    path === undefined ||
    expectedName === undefined ||
    basename(path) !== expectedName ||
    path !== resolve(PROJECT_ROOT, expectedName)
  ) {
    throw new Error(usage());
  }
  return path;
}
function usage() {
  return (
    "usage: pnpm authority-keys:provision -- --input <32-byte-rpc-key> " +
    "--writer-secret <canonical-0600-json> --observer-secret <canonical-0600-json> " +
    "--writer-restriction-evidence <canonical-json> " +
    "--observer-restriction-evidence <canonical-json> " +
    "--ingress-config <reviewed-ingress.jsonc> " +
    "--observer-config <reviewed-observer.jsonc> --worm-config <reviewed-worm.jsonc> " +
    "--version-tag <reviewed-tag> --version-message <reviewed-message> " +
    "[--bootstrap-report <canonical-bootstrap-report.json> --result <hold-journal.jsonl> " +
    "--apply [--recover]]"
  );
}
