import { createHash } from "node:crypto";

import { assertProviderMutationReleased } from "./provider-mutation-hold.mjs";

export function canonicalBytes(value) {
  assertProviderMutationReleased("worm-authority-apply");
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

export function taggedSha256(value) {
  assertProviderMutationReleased("worm-authority-apply");
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
