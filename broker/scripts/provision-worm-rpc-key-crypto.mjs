import { createHash } from "node:crypto";

export function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

export function taggedSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
