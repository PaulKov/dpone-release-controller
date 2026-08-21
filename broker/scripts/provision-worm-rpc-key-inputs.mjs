import { lstatSync, readFileSync } from "node:fs";
import { TextDecoder } from "node:util";

import {
  readProviderPolicyEvidence as readCloudflareProviderPolicyEvidence,
  readRestrictionEvidence as readCloudflareRestrictionEvidence,
} from "./provision-cloudflare-deployment-observer-token.mjs";
import {
  B2_PREFIX,
  B2_SECRET_DOCUMENT,
  BUCKET_ID,
  BUCKET_NAME,
  CAPABILITIES,
  MAX_INPUT_BYTES,
} from "./provision-worm-rpc-key-constants.mjs";
import { taggedSha256 } from "./provision-worm-rpc-key-crypto.mjs";
import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export function readB2SecretDocument(path, role) {
  assertProviderMutationReleased("worm-authority-apply");
  const bytes = readPrivateFile(path, 38, 360, `B2 ${role} secret document`);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    bytes.fill(0);
    throw new Error(`B2 ${role} secret document is not canonical UTF-8`);
  }
  const match = B2_SECRET_DOCUMENT.exec(text);
  if (match?.[1] === undefined || match[2] === undefined) {
    bytes.fill(0);
    throw new Error(`B2 ${role} secret document is not canonical`);
  }
  return {
    applicationKey: match[1],
    bytes,
    keyId: match[2],
    keyIdSha256: taggedSha256(Buffer.from(match[2], "utf8")),
  };
}

export function readRestrictionEvidence(path, role, keyIdSha256) {
  assertProviderMutationReleased("worm-authority-apply");
  const bytes = readPrivateFile(path, 64, MAX_INPUT_BYTES, `B2 ${role} restriction evidence`);
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`B2 ${role} restriction evidence is not canonical UTF-8 JSON`);
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    `${JSON.stringify(value)}\n` !== bytes.toString("utf8") ||
    JSON.stringify(Object.keys(value)) !==
      JSON.stringify([
        "application_key_expiration_timestamp",
        "bucket_id",
        "bucket_name",
        "capabilities",
        "key_id_sha256",
        "name_prefix",
        "role",
        "schema",
        "schema_version",
      ]) ||
    value.application_key_expiration_timestamp !== null ||
    typeof value.bucket_id !== "string" ||
    !BUCKET_ID.test(value.bucket_id) ||
    typeof value.bucket_name !== "string" ||
    !BUCKET_NAME.test(value.bucket_name) ||
    JSON.stringify(value.capabilities) !== JSON.stringify(CAPABILITIES[role]) ||
    value.key_id_sha256 !== keyIdSha256 ||
    value.name_prefix !== B2_PREFIX ||
    value.role !== role ||
    value.schema !== "dpone.release-b2-key-restriction-evidence.v1" ||
    value.schema_version !== 1
  ) {
    throw new Error(`B2 ${role} restriction evidence contract mismatch`);
  }
  return {
    application_key_expiration_timestamp: null,
    bucket_id: value.bucket_id,
    bucket_name: value.bucket_name,
    capabilities: [...CAPABILITIES[role]],
    evidence_sha256: taggedSha256(bytes),
    key_id_sha256: keyIdSha256,
    name_prefix: B2_PREFIX,
    role,
  };
}

export function readPrivateFile(path, minimumBytes, maximumBytes, label) {
  assertProviderMutationReleased("worm-authority-apply");
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o077) !== 0 ||
    stat.size < minimumBytes ||
    stat.size > maximumBytes
  ) {
    throw new Error(`${label} must be an exact mode-0600 regular file`);
  }
  const bytes = readFileSync(path);
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== stat.size) {
    throw new Error(`${label} read is not byte-exact`);
  }
  return bytes;
}

export function readAdminPrincipalDocument(path) {
  assertProviderMutationReleased("worm-authority-apply");
  const bytes = readPrivateFile(path, 64, 2048, "Access principal secret document");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    bytes.fill(0);
    throw new Error("Access principal secret document is not canonical UTF-8 JSON");
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    `${JSON.stringify(value)}\n` !== bytes.toString("utf8") ||
    JSON.stringify(Object.keys(value)) !==
      JSON.stringify(["access_group", "access_identity", "access_subject_id"]) ||
    typeof value.access_group !== "string" ||
    !/^[ -~]{1,256}$/u.test(value.access_group) ||
    typeof value.access_identity !== "string" ||
    !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]{3,253}$/u.test(value.access_identity) ||
    typeof value.access_subject_id !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{7,255}$/u.test(value.access_subject_id)
  ) {
    bytes.fill(0);
    throw new Error("Access principal secret document contract mismatch");
  }
  return {
    accessGroup: value.access_group,
    accessIdentity: value.access_identity,
    accessSubjectId: value.access_subject_id,
    bytes,
  };
}

export function adminPrincipalDigests(principals) {
  assertProviderMutationReleased("worm-authority-apply");
  return {
    access_group_sha256: adminPrincipalDigest("access_group", principals.accessGroup),
    access_identity_sha256: adminPrincipalDigest("access_identity", principals.accessIdentity),
    access_subject_id_sha256: adminPrincipalDigest("access_subject_id", principals.accessSubjectId),
  };
}

function adminPrincipalDigest(field, value) {
  return taggedSha256(
    Buffer.from(
      JSON.stringify({
        field,
        schema: "dpone.release-broker-admin-access-principal-digest.v1",
        schema_version: 1,
        value,
      }),
      "utf8",
    ),
  );
}

export function readCloudflareObserverRestriction(options, token, acceptedAtMs) {
  assertProviderMutationReleased("worm-authority-apply");
  const tokenFingerprint = taggedSha256(Buffer.from(token, "utf8"));
  const restriction = readCloudflareRestrictionEvidence(
    options.cloudflareObserverRestrictionEvidence,
    tokenFingerprint,
  );
  const providerPolicy =
    options.cloudflareObserverProviderPolicyEvidence === null
      ? null
      : readCloudflareProviderPolicyEvidence(
          options.cloudflareObserverProviderPolicyEvidence,
          restriction,
          tokenFingerprint,
          acceptedAtMs,
        );
  if (options.apply && providerPolicy === null) {
    throw new Error("Cloudflare observer apply requires fresh provider policy evidence");
  }
  return {
    ...restriction,
    provider_policy_evidence: providerPolicy,
    provider_policy_evidence_required: true,
  };
}

export function validateCloudflareObserverConfig(config, restriction) {
  assertProviderMutationReleased("worm-authority-apply");
  const vars = config?.vars;
  if (
    vars === null ||
    typeof vars !== "object" ||
    vars.CF_ACCOUNT_ID !== restriction.account_id ||
    vars.APPROVED_INGRESS_ZONE_ID !== restriction.zone_id
  ) {
    throw new Error("reviewed Cloudflare observer config differs from token restriction");
  }
}

export function validateAuthorityNetworkCrossBind(ingressConfig, observerConfig) {
  assertProviderMutationReleased("worm-authority-apply");
  const ingressAccountId = ingressConfig?.account_id;
  const observerAccountId = observerConfig?.account_id;
  const routeHostname = ingressConfig?.routes?.[0]?.pattern;
  const adminHostname = ingressConfig?.vars?.ADMIN_HOSTNAME;
  const observerHostname = observerConfig?.vars?.APPROVED_INGRESS_HOSTNAME;
  const zoneId = observerConfig?.vars?.APPROVED_INGRESS_ZONE_ID;
  if (
    typeof routeHostname !== "string" ||
    routeHostname.endsWith(".invalid") ||
    routeHostname !== adminHostname ||
    routeHostname !== observerHostname ||
    typeof ingressAccountId !== "string" ||
    !/^[0-9a-f]{32}$/u.test(ingressAccountId) ||
    /^0{32}$/u.test(ingressAccountId) ||
    ingressAccountId !== observerAccountId ||
    typeof zoneId !== "string" ||
    /^0{32}$/u.test(zoneId)
  ) {
    throw new Error("authority ceremony requires one resolved reviewed ingress origin");
  }
}

export function ceremonyVariableOverrides(
  role,
  expectedCallerServiceIdentity,
  expectedCloudflareObserverServiceIdentity,
  expectedB2ObserverServiceIdentity,
) {
  assertProviderMutationReleased("worm-authority-apply");
  if (role === "cloudflareObserver") {
    if (expectedCallerServiceIdentity === null) {
      throw new Error("Cloudflare observer upload requires the immutable ingress identity");
    }
    return { EXPECTED_INGRESS_SERVICE_IDENTITY: expectedCallerServiceIdentity };
  }
  if (role === "worm") {
    if (
      expectedCallerServiceIdentity === null ||
      expectedCloudflareObserverServiceIdentity === null ||
      expectedB2ObserverServiceIdentity === null
    ) {
      throw new Error("WORM upload requires all immutable caller and B2 observer identities");
    }
    return {
      WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: expectedB2ObserverServiceIdentity,
      WORM_EXPECTED_CALLER_SERVICE_IDENTITY: expectedCallerServiceIdentity,
      WORM_EXPECTED_CLOUDFLARE_OBSERVER_SERVICE_IDENTITY: expectedCloudflareObserverServiceIdentity,
    };
  }
  return {};
}

export function authoritySecretNames() {
  assertProviderMutationReleased("worm-authority-apply");
  return {
    cloudflareObserver: [
      "CLOUDFLARE_API_TOKEN",
      "CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY",
      "CLOUDFLARE_OBSERVER_RPC_AUTH_KEY",
    ],
    ingress: [
      "ADMIN_ACCESS_GROUP",
      "ADMIN_ACCESS_IDENTITY",
      "ADMIN_ACCESS_SUBJECT_ID",
      "CLOUDFLARE_OBSERVER_RPC_AUTH_KEY",
      "WORM_RPC_AUTH_KEY",
    ],
    observer: ["B2_APPLICATION_KEY", "B2_KEY_ID"],
    worm: [
      "B2_APPLICATION_KEY",
      "B2_KEY_ID",
      "CLOUDFLARE_EVIDENCE_RPC_AUTH_KEY",
      "WORM_RPC_AUTH_KEY",
    ],
  };
}

export function validateB2Config(config, restriction, role) {
  assertProviderMutationReleased("worm-authority-apply");
  const vars = config.vars;
  if (
    vars === null ||
    typeof vars !== "object" ||
    vars.B2_BUCKET_ID !== restriction.bucket_id ||
    vars.B2_BUCKET_NAME !== restriction.bucket_name ||
    restriction.role !== role
  ) {
    throw new Error(`reviewed ${role} B2 config differs from restriction evidence`);
  }
}
