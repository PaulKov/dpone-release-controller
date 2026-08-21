import { describe, expect, it } from "vitest";

import { canonicalBytes, canonicalJson, sha256Hex } from "../src/canonical";
import { WormMirrorClient } from "../src/worm-client";
import { signWormRpcRequest, verifyWormRpcRequest } from "../src/worm-rpc-auth";
import {
  CALLER,
  INGRESS_VERSION,
  OBSERVER,
  PIN,
  RPC_AUTH_KEY,
  retainableEvidence,
  uuid,
} from "./worm-mirror-boundary.fixtures";

describe("WORM pre-side-effect version boundary", () => {
  it("authenticates the deterministic batch id and rejects header substitution", async () => {
    const headers = new Headers({
      "content-length": "2",
      "content-type": "application/json",
      "x-dpone-batch-id": `sha256:${"1".repeat(64)}`,
      "x-dpone-callee-service": PIN.serviceName,
      "x-dpone-callee-service-identity": PIN.serviceIdentity,
      "x-dpone-callee-version": PIN.versionId,
      "x-dpone-canonical-sha256": `sha256:${"2".repeat(64)}`,
      "x-dpone-cloudflare-observer-worker-version": CALLER.versionId,
    });
    await signWormRpcRequest(headers, "/rpc/v1/cloudflare-evidence/batch", CALLER);
    await verifyWormRpcRequest(
      headers,
      "/rpc/v1/cloudflare-evidence/batch",
      RPC_AUTH_KEY,
      CALLER.serviceIdentity,
    );
    const forged = new Headers(headers);
    forged.set("x-dpone-batch-id", `sha256:${"3".repeat(64)}`);
    await expect(
      verifyWormRpcRequest(
        forged,
        "/rpc/v1/cloudflare-evidence/batch",
        RPC_AUTH_KEY,
        CALLER.serviceIdentity,
      ),
    ).rejects.toThrow("WORM_RPC_AUTH_INVALID");
  });

  it("mirrors provider evidence under a deterministic versioned key", async () => {
    const evidence = await retainableEvidence();
    const bytes = canonicalBytes(evidence);
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const committedAt = "2026-08-15T12:00:00Z";
    const key =
      `receipts/v1/activation-evidence/${INGRESS_VERSION}/` +
      `github_oidc_subject_customization/${digest.slice(7)}.json`;
    let captured: Request | undefined;
    const service = {
      async fetch(request: Request): Promise<Response> {
        captured = request;
        return new Response(
          canonicalJson({
            digest,
            key,
            kind: "activation_evidence",
            retention_until: "2033-08-16T12:00:00Z",
            schema: "dpone.release-worm-mirror-result.v1",
            version_id: "b2-evidence-version-0001",
            worker_version_id: PIN.versionId,
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        );
      },
    } as unknown as Fetcher;

    const result = await new WormMirrorClient(service, PIN, OBSERVER, CALLER).mirrorEvidence({
      bytes,
      committedAt,
      digest,
      evidenceKind: "github_oidc_subject_customization",
      ingressWorkerVersion: INGRESS_VERSION,
    });

    expect(result).toMatchObject({ digest, key, versionId: "b2-evidence-version-0001" });
    expect(captured?.url).toBe("https://worm-mirror.internal/rpc/v1/activation-evidence");
    expect(captured?.headers.get("x-dpone-callee-service-identity")).toBe(PIN.serviceIdentity);
    expect(captured?.headers.get("x-dpone-observer-service-identity")).toBe(
      OBSERVER.serviceIdentity,
    );
    expect(captured?.headers.get("x-dpone-rpc-caller-service-identity")).toBe(
      CALLER.serviceIdentity,
    );
    await verifyWormRpcRequest(
      captured?.headers ?? new Headers(),
      "/rpc/v1/activation-evidence",
      RPC_AUTH_KEY,
      CALLER.serviceIdentity,
    );
    for (const [name, value] of [
      ["x-dpone-canonical-sha256", `sha256:${"0".repeat(64)}`],
      ["x-dpone-observer-version", uuid(9998)],
      ["x-dpone-rpc-caller-version", uuid(9999)],
    ] as const) {
      const forged = new Headers(captured?.headers);
      forged.set(name, value);
      await expect(
        verifyWormRpcRequest(
          forged,
          "/rpc/v1/activation-evidence",
          RPC_AUTH_KEY,
          CALLER.serviceIdentity,
        ),
      ).rejects.toThrow("WORM_RPC_AUTH_INVALID");
    }
  });

  it("rejects a WORM response whose key is not bound to kind, ingress version, and digest", async () => {
    const evidence = await retainableEvidence();
    const bytes = canonicalBytes(evidence);
    const digest = `sha256:${await sha256Hex(bytes)}`;
    const service = {
      async fetch(): Promise<Response> {
        return new Response(
          canonicalJson({
            digest,
            key:
              `receipts/v1/activation-evidence/${INGRESS_VERSION}/` +
              `github_branch_ruleset/${digest.slice(7)}.json`,
            kind: "activation_evidence",
            retention_until: "2033-08-16T12:00:00Z",
            schema: "dpone.release-worm-mirror-result.v1",
            version_id: "b2-evidence-version-0001",
            worker_version_id: PIN.versionId,
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        );
      },
    } as unknown as Fetcher;

    await expect(
      new WormMirrorClient(service, PIN, OBSERVER, CALLER).mirrorEvidence({
        bytes,
        committedAt: "2026-08-15T12:00:00Z",
        digest,
        evidenceKind: "github_oidc_subject_customization",
        ingressWorkerVersion: INGRESS_VERSION,
      }),
    ).rejects.toThrow("WORM_MIRROR_KEY_MISMATCH");
  });

  it("rejects raw capability/secret payloads before the WORM service is called", async () => {
    let called = false;
    const service = {
      async fetch(): Promise<Response> {
        called = true;
        throw new Error("must not call WORM for forbidden evidence");
      },
    } as unknown as Fetcher;
    const evidence = await retainableEvidence({ authorizationToken: "provider-secret" });
    const bytes = canonicalBytes(evidence);
    await expect(
      new WormMirrorClient(service, PIN, OBSERVER, CALLER).mirrorEvidence({
        bytes,
        committedAt: "2026-08-15T12:00:00Z",
        digest: `sha256:${await sha256Hex(bytes)}`,
        evidenceKind: "github_oidc_subject_customization",
        ingressWorkerVersion: INGRESS_VERSION,
      }),
    ).rejects.toThrow();
    expect(called).toBe(false);
  });
});
