import { provisionReadPlan } from "../src/activation-operation-read-plan";
import { canonicalBytes, sha256Hex } from "../src/canonical";
import type { JsonObject } from "../src/types";
import { prepareWormExactObjectEffectWithKeyPolicy } from "../src/worm-exact-object-effect-contract";
import { buildWormExactObjectEffectResult } from "../src/worm-exact-object-effect-result";
import type { productionResolverFixture } from "./activation-component-resolver.fixtures";

const RETENTION = "2034-08-20T12:00:00.000Z";
const KINDS = Object.freeze([
  "controller_action_bundle_observation",
  "github_oidc_subject_customization",
  "github_oidc_subject_customization",
  "github_branch_ruleset",
] as const);

export async function compactDirectEvidenceFixture(
  source: Awaited<ReturnType<typeof productionResolverFixture>>,
  resolved: JsonObject,
  operation: JsonObject,
  committedAt: string,
  worstCase: boolean,
): Promise<JsonObject[]> {
  const requestId = string(operation, "internal_request_id");
  const plans = provisionReadPlan(source.source.source.request, requestId);
  const services = object(object(resolved.runtime).private_services);
  const executor = object(services.worm_mirror);
  const observer = object(services.worm_version_observer);
  return Promise.all(
    plans.map(async (plan, index) => {
      const providerRequestSha256 = await taggedBytes(plan.canonicalRequestBytes);
      const evidenceBytes = canonicalBytes({
        provider_request_sha256: providerRequestSha256,
        schema: "dpone.compact-v2-fixture-direct-evidence.v1",
        slot_id: plan.slotId,
        source_component_envelope_sha256: await sourceEnvelopeDigest(source, index),
      });
      const evidenceSha256 = await taggedBytes(evidenceBytes);
      const kind = KINDS[index];
      if (kind === undefined) throw new Error("compact v2 direct kind missing");
      const key =
        `receipts/v2/activation-evidence/${source.source.input.descriptor.workerVersionId}/` +
        `${kind}/${evidenceSha256.slice(7)}.json`;
      const effect = await prepareWormExactObjectEffectWithKeyPolicy(
        {
          canonicalBytes: evidenceBytes,
          committedAt,
          digest: evidenceSha256,
          key,
          pins: {
            executorServiceIdentity: string(executor, "service_identity"),
            executorVersionId: string(executor, "version_id"),
            observerServiceIdentity: string(observer, "service_identity"),
            observerVersionId: string(observer, "version_id"),
          },
        },
        (candidate) => candidate === key,
      );
      const absenceInventoryDigest = tagged(900 + index);
      const worm = {
        digest: evidenceSha256,
        key,
        retentionUntil: RETENTION,
        versionId: worstCase ? longVersion(10 + index) : `4_z-direct-v2-000${index}`,
      };
      const resultBytes = buildWormExactObjectEffectResult({
        absenceInventoryDigest,
        committedAt,
        digest: evidenceSha256,
        effectId: effect.effectId,
        key,
        pins: effect.pins,
        status: "CONFIRMED",
        worm,
      });
      return {
        absence_inventory_sha256: absenceInventoryDigest,
        effect_id: effect.effectId,
        evidence_sha256: evidenceSha256,
        provider_request_sha256: providerRequestSha256,
        result_sha256: await taggedBytes(resultBytes),
        slot_id: plan.slotId,
        worm: {
          digest: worm.digest,
          key: worm.key,
          retention_until: worm.retentionUntil,
          version_id: worm.versionId,
        },
      };
    }),
  );
}

async function sourceEnvelopeDigest(
  source: Awaited<ReturnType<typeof productionResolverFixture>>,
  index: number,
): Promise<string> {
  const version = source.componentSnapshot.versions[index];
  if (version === undefined) throw new Error("compact v2 source envelope missing");
  return taggedBytes(version.canonicalBytes);
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("compact v2 direct fixture object missing");
  }
  return value as JsonObject;
}

function string(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") throw new Error(`compact v2 fixture ${key} missing`);
  return candidate;
}

function tagged(index: number): string {
  return `sha256:${index.toString(16).padStart(64, "0")}`;
}

async function taggedBytes(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

function longVersion(index: number): string {
  const prefix = `v${index}_`;
  return prefix + "x".repeat(512 - prefix.length);
}
