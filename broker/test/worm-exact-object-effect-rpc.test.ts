import { describe, expect, it } from "vitest";

import { canonicalBytes, sha256Hex } from "../src/canonical";
import wormMirrorWorker from "../src/private/worm-mirror-worker";
import type { WormMirrorEnv } from "../src/private/worm-mirror-worker-helpers";
import type { PrivateServicePin } from "../src/types";
import { WormExactObjectEffectClient } from "../src/worm-exact-object-effect-client";
import {
  prepareWormExactObjectEffect,
  type ConfirmedWormExactObjectEffect,
  type WormExactObjectEffectInput,
} from "../src/worm-exact-object-effect-contract";
import { buildWormExactObjectEffectResult } from "../src/worm-exact-object-effect-result";
import type { WormExactObjectEffectRpcInput } from "../src/private/worm-exact-object-effect-do";
import type { WormRpcCallerAuth } from "../src/worm-rpc-auth";
import { fetcher } from "./cloudflare-deployment-observer-common.fixtures";
import { retainableEvidence } from "./worm-mirror-boundary.fixtures";

const ACCOUNT_ID = "a".repeat(32);
const EXECUTOR_VERSION = "11111111-1111-4111-8111-111111111111";
const OBSERVER_VERSION = "22222222-2222-4222-8222-222222222222";
const INGRESS_VERSION = "33333333-3333-4333-8333-333333333333";
const AUTH_KEY = "A".repeat(43);
const REQUEST_ID = `activation-${"a".repeat(64)}`;
const COMMITTED_AT = "2026-08-19T12:00:00.000Z";
const RETENTION_UNTIL = "2034-08-20T12:00:00.000Z";

const EXECUTOR_PIN: PrivateServicePin = pin("dpone-release-worm-mirror", EXECUTOR_VERSION);
const OBSERVER_PIN: PrivateServicePin = pin(
  "dpone-release-worm-version-observer",
  OBSERVER_VERSION,
);
const CALLER: WormRpcCallerAuth = {
  key: AUTH_KEY,
  serviceIdentity: identity("dpone-release-authority-broker", INGRESS_VERSION),
  versionId: INGRESS_VERSION,
};

describe("WORM exact-object RPC boundary", () => {
  it("derives the DO identity server-side and returns one exact confirmed result", async () => {
    const input = await evidenceInput();
    const prepared = await prepareWormExactObjectEffect(input);
    const calls: { effectId: string; input: WormExactObjectEffectRpcInput }[] = [];
    let captured: Request | undefined;
    const workerEnv = exactObjectEnv(calls);
    const service = fetcher(async (request) => {
      captured = request.clone() as unknown as Request;
      return wormMirrorWorker.fetch(request, workerEnv);
    });

    const accepted = await new WormExactObjectEffectClient(
      service,
      EXECUTOR_PIN,
      OBSERVER_PIN,
      CALLER,
    ).execute(input, REQUEST_ID);

    expect(accepted.confirmed).toMatchObject({
      digest: prepared.digest,
      effectId: prepared.effectId,
      key: prepared.key,
      status: "CONFIRMED",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.effectId).toBe(prepared.effectId);
    expect(new Uint8Array(calls[0]?.input.canonicalBytes ?? new ArrayBuffer(0))).toEqual(
      prepared.canonicalBytes,
    );
    const headers = captured?.headers;
    expect(headers?.get("x-dpone-object-key")).toBe(prepared.key);
    expect(headers?.get("x-dpone-effect-id")).toBe(prepared.effectId);
    expect(headers?.get("x-request-id")).toBe(REQUEST_ID);
  });

  it("rejects key/body split authority and signed-header tampering before DO lookup", async () => {
    const input = await evidenceInput();
    const calls: { effectId: string; input: WormExactObjectEffectRpcInput }[] = [];
    let captured: Request | undefined;
    const workerEnv = exactObjectEnv(calls);
    const service = fetcher(async (request) => {
      captured = request.clone() as unknown as Request;
      return wormMirrorWorker.fetch(request, workerEnv);
    });
    await new WormExactObjectEffectClient(service, EXECUTOR_PIN, OBSERVER_PIN, CALLER).execute(
      input,
      REQUEST_ID,
    );
    expect(calls).toHaveLength(1);

    const mismatched = {
      ...input,
      key:
        `receipts/v1/activation-evidence/${INGRESS_VERSION}/github_branch_ruleset/` +
        `${input.digest.slice("sha256:".length)}.json`,
    };
    await expect(
      new WormExactObjectEffectClient(service, EXECUTOR_PIN, OBSERVER_PIN, CALLER).execute(
        mismatched,
        REQUEST_ID,
      ),
    ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_RPC_KEY_INVALID");

    const exactRequest = requireRequest(captured);
    const body = await exactRequest.arrayBuffer();
    for (const header of ["x-dpone-effect-id", "x-dpone-object-key", "x-request-id"] as const) {
      const headers = new Headers(exactRequest.headers);
      headers.set(
        header,
        header === "x-dpone-effect-id"
          ? `sha256:${"f".repeat(64)}`
          : header === "x-dpone-object-key"
            ? input.key.replace("github_oidc_subject_customization", "github_branch_ruleset")
            : `activation-${"b".repeat(64)}`,
      );
      const rejected = await wormMirrorWorker.fetch(
        new Request(exactRequest.url, { body: body.slice(0), headers, method: "POST" }),
        workerEnv,
      );
      expect(rejected.status).toBe(503);
      await expect(rejected.json()).resolves.toMatchObject({
        error: { code: "WORM_RPC_AUTH_INVALID", retryable: false },
      });
    }
    expect(calls).toHaveLength(1);
  });

  it("rejects noncanonical and oversized bodies before a service call or copy", async () => {
    let serviceCalls = 0;
    const service = fetcher(async () => {
      serviceCalls += 1;
      throw new Error("service must not be called");
    });
    const client = new WormExactObjectEffectClient(service, EXECUTOR_PIN, OBSERVER_PIN, CALLER);
    const input = await evidenceInput();
    const noncanonical = new TextEncoder().encode(
      `${new TextDecoder().decode(input.canonicalBytes)} `,
    );
    await expect(
      client.execute(
        {
          ...input,
          canonicalBytes: noncanonical,
          digest: `sha256:${await sha256Hex(noncanonical)}`,
        },
        REQUEST_ID,
      ),
    ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_RPC_BODY_NONCANONICAL");
    const copyTrap = {
      byteLength: 65_537,
      [Symbol.iterator](): never {
        throw new Error("OVERSIZED_RPC_BODY_WAS_COPIED");
      },
    } as unknown as Uint8Array;
    await expect(
      client.execute({ ...input, canonicalBytes: copyTrap }, REQUEST_ID),
    ).rejects.toThrow("WORM_EXACT_OBJECT_EFFECT_INPUT_INVALID");
    await expect(client.execute(input, "transport-request-0001")).rejects.toThrow(
      "WORM_EXACT_OBJECT_EFFECT_RPC_REQUEST_ID_INVALID",
    );
    await expect(client.execute(input, undefined as unknown as string)).rejects.toThrow(
      "WORM_EXACT_OBJECT_EFFECT_RPC_REQUEST_ID_INVALID",
    );
    expect(serviceCalls).toBe(0);
  });

  it("rejects an activation envelope outside the closed top-level record schema", async () => {
    let serviceCalls = 0;
    const service = fetcher(async () => {
      serviceCalls += 1;
      throw new Error("service must not be called");
    });
    const document = {
      attacker_extension: true,
      record_id: `sha256:${"0".repeat(64)}`,
      schema: "dpone.release-broker-provisioned.v1",
      sequence: 0,
    };
    const bytes = canonicalBytes(document);
    const digest = `sha256:${await sha256Hex(bytes)}`;
    await expect(
      new WormExactObjectEffectClient(service, EXECUTOR_PIN, OBSERVER_PIN, CALLER).execute(
        {
          canonicalBytes: bytes,
          committedAt: COMMITTED_AT,
          digest,
          key:
            `receipts/v1/activation/${INGRESS_VERSION}/` +
            `0-${digest.slice("sha256:".length)}.json`,
          pins: {
            executorServiceIdentity: EXECUTOR_PIN.serviceIdentity,
            executorVersionId: EXECUTOR_PIN.versionId,
            observerServiceIdentity: OBSERVER_PIN.serviceIdentity,
            observerVersionId: OBSERVER_PIN.versionId,
          },
        },
        REQUEST_ID,
      ),
    ).rejects.toThrow("UNKNOWN_FIELD");
    expect(serviceCalls).toBe(0);
  });
});

async function evidenceInput(): Promise<WormExactObjectEffectInput> {
  const document = await retainableEvidence();
  const bytes = canonicalBytes(document);
  const digest = `sha256:${await sha256Hex(bytes)}`;
  return {
    canonicalBytes: bytes,
    committedAt: COMMITTED_AT,
    digest,
    key:
      `receipts/v1/activation-evidence/${INGRESS_VERSION}/` +
      `github_oidc_subject_customization/${digest.slice("sha256:".length)}.json`,
    pins: {
      executorServiceIdentity: EXECUTOR_PIN.serviceIdentity,
      executorVersionId: EXECUTOR_PIN.versionId,
      observerServiceIdentity: OBSERVER_PIN.serviceIdentity,
      observerVersionId: OBSERVER_PIN.versionId,
    },
  };
}

function exactObjectEnv(calls: { effectId: string; input: WormExactObjectEffectRpcInput }[]) {
  return {
    CF_ACCOUNT_ID: ACCOUNT_ID,
    CF_VERSION_METADATA: { id: EXECUTOR_VERSION, tag: "test", timestamp: COMMITTED_AT },
    OPERATING_MODE: "live",
    SERVICE_NAME: EXECUTOR_PIN.serviceName,
    WORM_EXPECTED_B2_OBSERVER_SERVICE_IDENTITY: OBSERVER_PIN.serviceIdentity,
    WORM_EXPECTED_CALLER_SERVICE_IDENTITY: CALLER.serviceIdentity,
    WORM_EXACT_OBJECT_EFFECTS: {
      getByName: (effectId: string) => ({
        execute: async (input: WormExactObjectEffectRpcInput) => {
          calls.push({ effectId, input });
          const prepared = await prepareWormExactObjectEffect({
            canonicalBytes: new Uint8Array(input.canonicalBytes),
            committedAt: input.committedAt,
            digest: input.digest,
            key: input.key,
            pins: {
              executorServiceIdentity: EXECUTOR_PIN.serviceIdentity,
              executorVersionId: EXECUTOR_PIN.versionId,
              observerServiceIdentity: input.observerServiceIdentity,
              observerVersionId: input.observerVersionId,
            },
          });
          expect(input.ingressVersionId).toBe(INGRESS_VERSION);
          return Uint8Array.from(buildWormExactObjectEffectResult(confirmed(prepared))).buffer;
        },
      }),
    },
    WORM_RPC_AUTH_KEY: AUTH_KEY,
  } as unknown as WormMirrorEnv;
}

function confirmed(
  prepared: Awaited<ReturnType<typeof prepareWormExactObjectEffect>>,
): ConfirmedWormExactObjectEffect {
  return {
    absenceInventoryDigest: `sha256:${"a".repeat(64)}`,
    committedAt: prepared.committedAt,
    digest: prepared.digest,
    effectId: prepared.effectId,
    key: prepared.key,
    pins: prepared.pins,
    status: "CONFIRMED",
    worm: {
      digest: prepared.digest,
      key: prepared.key,
      retentionUntil: RETENTION_UNTIL,
      versionId: "4_z-worm-exact-rpc-0001",
    },
  };
}

function pin(serviceName: string, versionId: string): PrivateServicePin {
  return { serviceIdentity: identity(serviceName, versionId), serviceName, versionId };
}

function identity(serviceName: string, versionId: string): string {
  return `cloudflare-worker:${ACCOUNT_ID}/${serviceName}@${versionId}`;
}

function requireRequest(value: Request | undefined): Request {
  if (value === undefined) throw new Error("captured request missing");
  return value;
}
