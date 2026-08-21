import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  bindActivationProvisionAuthority,
  snapshotConfirmedActivationProvisionAuthority,
} from "../src/activation-component-operation-authority";
import { validateActivationRecordV2ComponentAuthority } from "../src/activation-record-v2-evidence";
import { activationRecordV2IntentSha256 } from "../src/activation-record-v2-evidence";
import { canonicalBytes, canonicalJson, sha256Hex } from "../src/canonical";
import { SERVICE_AUTHORITY_DEFINITIONS } from "../src/service-authority";
import type { JsonObject } from "../src/types";
import { compactActivationRecordV2Fixture } from "./activation-record-v2.fixtures";
import { activationProvisionAuthorityFixture } from "./activation-component-operation-authority.fixtures";

afterEach(async () => {
  await reset();
});

describe("confirmed activation provision authority", () => {
  it("binds real journal and resolver brands to the exact compact-v2 A0 topology", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-authority-happy-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await activationProvisionAuthorityFixture(state.storage);
      const compact = await compactActivationRecordV2Fixture();
      const authority = fixture.authority;
      const compactAuthority = object(compact.provisioned.document.component_authority);
      const parsed = await validateActivationRecordV2ComponentAuthority(
        authority.componentAuthority,
        authority.descriptor.workerVersionId,
      );

      expect(authority.trust).toBe("CONFIRMED_COMPONENT_OPERATION_AUTHORITY");
      expect(authority.canonicalComponentAuthorityBytes).toEqual(canonicalBytes(compactAuthority));
      expect(authority.componentAuthority).toEqual(compactAuthority);
      expect(authority.componentAuthoritySha256).toBe(
        `sha256:${await sha256Hex(authority.canonicalComponentAuthorityBytes)}`,
      );
      expect(authority.provisionIntentSha256).toBe(
        await activationRecordV2IntentSha256(parsed.intent, 0),
      );
      expect(decode(authority.canonicalProvisionIntentBytes)).toEqual({
        component_authority: parsed.intent,
        schema: "dpone.release-broker-provision-intent.v2",
        schema_version: 2,
      });
      expect(authority.canonicalManifestPointerBytes).toEqual(
        fixture.journal.canonicalPointerBytes,
      );
      expect(authority.manifestPointerSha256).toBe(fixture.journal.pointerSha256);
      expect(authority.canonicalResolvedProjectionBytes).toEqual(
        fixture.resolved.canonicalProjectionBytes,
      );
      expect(canonicalJson(authority.componentAuthority)).not.toContain("private_services");
    });
  }, 30_000);

  it("derives only historical resolver commitments and reviewed operation pins", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-authority-pins-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const currentWorker = "99999999-9999-4999-8999-999999999999";
      const fixture = await activationProvisionAuthorityFixture(state.storage, 0, currentWorker);
      const authority = fixture.authority;
      const runtime = object(fixture.resolved.document.runtime);
      const accountId = string(runtime, "cloudflare_account_id");
      const historicalWorker = authority.descriptor.workerVersionId;

      expect(authority.historicalWorker).toEqual({
        serviceIdentity:
          `cloudflare-worker:${accountId}/` +
          `${SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service}@${historicalWorker}`,
        serviceName: SERVICE_AUTHORITY_DEFINITIONS.release_authority_ingress.service,
        versionId: historicalWorker,
      });
      expect(authority.historicalWorker.versionId).not.toBe(currentWorker);
      expect(authority.pins.providerReads.controllerAction).toEqual(
        authority.pins.providerReads.controllerOidc,
      );
      expect(authority.pins.providerReads.targetOidc).toEqual(
        authority.pins.providerReads.targetRuleset,
      );
      expect(authority.pins.cloudflareBatch).toMatchObject({
        b2ObserverServiceIdentity: authority.pins.directEvidenceWorm.observerServiceIdentity,
        b2ObserverWorkerVersionId: authority.pins.directEvidenceWorm.observerWorkerVersionId,
        wormServiceIdentity: authority.pins.directEvidenceWorm.executorServiceIdentity,
        wormWorkerVersionId: authority.pins.directEvidenceWorm.executorWorkerVersionId,
      });
      expect(fixture.journal.pins).toEqual({
        executorServiceIdentity: authority.pins.directEvidenceWorm.executorServiceIdentity,
        executorVersionId: authority.pins.directEvidenceWorm.executorWorkerVersionId,
        observerServiceIdentity: authority.pins.directEvidenceWorm.observerServiceIdentity,
        observerVersionId: authority.pins.directEvidenceWorm.observerWorkerVersionId,
      });
      expect(authority.semanticCommitments).toEqual({
        cloudflareAccountId: accountId,
        controllerActionBundleSha256: runtime.controller_action_bundle_sha256,
        serviceAuthorityExpectationSha256: runtime.service_authority_expectation_sha256,
        targetBranchRulesetEvidenceSha256: runtime.target_branch_ruleset_evidence_sha256,
        targetBranchRulesetProjectionSha256: runtime.target_branch_ruleset_projection_sha256,
      });
      expect(Object.isFrozen(authority.pins)).toBe(true);
      expect(Object.isFrozen(authority.semanticCommitments)).toBe(true);
    });
  }, 30_000);

  it("rederives identical retry authority after output-byte mutation and historical TTL", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-authority-retry-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await activationProvisionAuthorityFixture(state.storage);
      const authority = fixture.authority;
      const expected = {
        component: authority.canonicalComponentAuthorityBytes,
        descriptor: authority.canonicalDescriptorBytes,
        intent: authority.canonicalProvisionIntentBytes,
        pointer: authority.canonicalManifestPointerBytes,
        projection: authority.canonicalResolvedProjectionBytes,
      };
      authority.canonicalComponentAuthorityBytes.fill(0);
      authority.canonicalDescriptorBytes.fill(0);
      authority.canonicalManifestPointerBytes.fill(0);
      authority.canonicalProvisionIntentBytes.fill(0);
      authority.canonicalResolvedProjectionBytes.fill(0);
      fixture.selected.clock.milliseconds =
        Date.parse(fixture.selected.prepared.session.freshUntil) + 1;

      const snapshot = await snapshotConfirmedActivationProvisionAuthority(authority);
      expect(snapshot).not.toBe(authority);
      expect(snapshot.canonicalComponentAuthorityBytes).toEqual(expected.component);
      expect(snapshot.canonicalDescriptorBytes).toEqual(expected.descriptor);
      expect(snapshot.canonicalManifestPointerBytes).toEqual(expected.pointer);
      expect(snapshot.canonicalProvisionIntentBytes).toEqual(expected.intent);
      expect(snapshot.canonicalResolvedProjectionBytes).toEqual(expected.projection);
      expect(snapshot.componentAuthoritySha256).toBe(authority.componentAuthoritySha256);
      expect(snapshot.provisionIntentSha256).toBe(authority.provisionIntentSha256);
      expect(snapshot.pins).toEqual(authority.pins);
    });
  }, 30_000);

  it("concurrently binds exact retry inputs to byte-identical independently branded values", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-authority-race-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await activationProvisionAuthorityFixture(state.storage);
      const [left, right] = await Promise.all([
        bindActivationProvisionAuthority(fixture.journal, fixture.resolved),
        bindActivationProvisionAuthority(fixture.journal, fixture.resolved),
      ]);
      expect(left).not.toBe(right);
      expect(left.canonicalComponentAuthorityBytes).toEqual(right.canonicalComponentAuthorityBytes);
      expect(left.canonicalProvisionIntentBytes).toEqual(right.canonicalProvisionIntentBytes);
      expect(left.provisionIntentSha256).toBe(right.provisionIntentSha256);
      expect(left.pins).toEqual(right.pins);
    });
  }, 30_000);
});

function decode(bytes: Uint8Array): JsonObject {
  return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown);
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("operation authority test object missing");
  }
  return value as JsonObject;
}

function string(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`operation authority ${key} missing`);
  return candidate;
}
