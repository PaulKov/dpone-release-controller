import type { JsonObject, PrivateServicePin } from "../src/types";

export function uuid(value: number): string {
  return `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
}

export function digest(value: number): string {
  return `sha256:${hex(value, 64)}`;
}

export function hex(value: number, width: number): string {
  return value.toString(16).padStart(width, "0");
}

export function fetcher(callback: (request: Request) => Promise<Response>): Fetcher {
  return { fetch: callback } as unknown as Fetcher;
}

export function privatePin(
  accountId: string,
  serviceName: string,
  version: number,
): PrivateServicePin {
  const versionId = uuid(version);
  return {
    serviceIdentity: `cloudflare-worker:${accountId}/${serviceName}@${versionId}`,
    serviceName,
    versionId,
  };
}

export function requireDefined<T>(value: T | null | undefined, message: string): T {
  if (value === null || value === undefined) throw new Error(message);
  return value;
}

export function requiredString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`missing ${key}`);
  return candidate;
}

export function requireObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected object fixture");
  }
  return value as JsonObject;
}
