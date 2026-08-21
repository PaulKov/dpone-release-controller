import { describe, expect, it } from "vitest";

import {
  APP_PERMISSIONS,
  CONTROLLER_RUN_READER_PERMISSIONS,
  targetSelectedActions,
} from "../src/activation-contract";
import {
  assertControllerActionsPolicyFrozen,
  assertObservedAtBounded,
  validateDurableObjectInventory,
  validatePrivateServiceInventory,
} from "../src/activation-schema";
import { validateApps } from "../src/activation-infrastructure";
import {
  SOURCE_COMMIT,
  durableObjects,
  githubApps,
  object,
  privateServices,
  requiredString,
  service,
} from "./activation-schema-topology.fixtures";

describe("activation epoch schema", () => {
  it("freezes the isolated controller reader to the exact read-only provider grant", () => {
    expect(CONTROLLER_RUN_READER_PERMISSIONS).toEqual({
      actions: "read",
      administration: "read",
      attestations: "read",
      checks: "read",
      contents: "read",
      environments: "read",
      metadata: "read",
    });
    expect(APP_PERMISSIONS.controller_run_reader).toEqual([
      "actions:read",
      "administration:read",
      "attestations:read",
      "checks:read",
      "contents:read",
      "environments:read",
      "metadata:read",
    ]);
    expect(APP_PERMISSIONS.controller_run_reader.every((item) => item.endsWith(":read"))).toBe(
      true,
    );
  });

  it("derives the exact wildcard-free selected-actions policy from Commit A", () => {
    const actionCommit = "d".repeat(40);
    expect(assertControllerActionsPolicyFrozen(actionCommit)).toEqual([
      `paulkov/dpone-release-controller@${actionCommit}`,
      "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
    ]);
    expect(() => assertControllerActionsPolicyFrozen("not-a-commit")).toThrow(
      "ACTIVATION_CONTROLLER_ACTION_COMMIT_INVALID",
    );
    expect(targetSelectedActions(actionCommit)).toEqual([
      "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610",
      "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
      "azure/setup-helm@1a275c3b69536ee54be43f2070a358922e12c8d4",
      "docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2",
      "ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a",
      `paulkov/dpone-release-controller@${actionCommit}`,
      "trufflesecurity/trufflehog@27b0417c16317ca9a472a9a8092acce143b49c55",
    ]);
    expect(targetSelectedActions(actionCommit).every((item) => !item.endsWith("@*"))).toBe(true);
  });

  it("accepts only immutable, identity-bound private service pins", () => {
    const services = privateServices();
    expect(() => validatePrivateServiceInventory(services, SOURCE_COMMIT)).not.toThrow();

    const wrongVersion = structuredClone(services);
    service(wrongVersion, "worm_mirror").worker_version_id = "opaque-version-alias";
    expect(() => validatePrivateServiceInventory(wrongVersion, SOURCE_COMMIT)).toThrow(
      "FIELD_INVALID",
    );
  });

  it("rejects service aliasing", () => {
    const aliasedService = privateServices();
    const mirrorService = requiredString(service(aliasedService, "worm_mirror"), "service");
    const observerVersion = requiredString(
      service(aliasedService, "worm_version_observer"),
      "worker_version_id",
    );
    service(aliasedService, "worm_version_observer").service = mirrorService;
    service(aliasedService, "worm_version_observer").service_identity =
      `cloudflare-worker:${"0".repeat(32)}/${mirrorService}@${observerVersion}`;
    expect(() => validatePrivateServiceInventory(aliasedService, SOURCE_COMMIT)).toThrow(
      "ACTIVATION_SERVICE_ALIAS_FORBIDDEN",
    );
  });

  it("keeps both deployment gates webhook-only and rejects GitHub App aliases", () => {
    const services = privateServices();
    const apps = githubApps(services);
    expect(() => validateApps(apps, services)).not.toThrow();

    const wrongRuntimeSubscription = structuredClone(apps);
    object(wrongRuntimeSubscription, "runtime_deployment_gate").subscriptions = [];
    expect(() => validateApps(wrongRuntimeSubscription, services)).toThrow(
      "ACTIVATION_STRING_ARRAY_MISMATCH",
    );

    const wrongRuntimeWebhook = structuredClone(apps);
    object(wrongRuntimeWebhook, "runtime_deployment_gate").webhook_active = false;
    expect(() => validateApps(wrongRuntimeWebhook, services)).toThrow(
      "ACTIVATION_APP_INTERACTIVE_SURFACE_FORBIDDEN",
    );

    for (const [field, error] of [
      ["app_slug", "ACTIVATION_APP_SLUG_ALIAS_FORBIDDEN"],
      ["credential_fingerprint_sha256", "ACTIVATION_APP_CREDENTIAL_ALIAS_FORBIDDEN"],
    ] as const) {
      const aliased = structuredClone(apps);
      object(aliased, "runtime_deployment_gate")[field] = requiredString(
        object(aliased, "pypi_deployment_gate"),
        field,
      );
      expect(() => validateApps(aliased, services)).toThrow(error);
    }
  });

  it("pins three distinct Durable Object namespaces to exact classes and migrations", () => {
    const inventory = durableObjects();
    expect(() => validateDurableObjectInventory(inventory)).not.toThrow();

    const wrongBinding = structuredClone(inventory);
    object(wrongBinding, "release_ledgers").binding_name = "RELEASE_MUTATOR";
    expect(() => validateDurableObjectInventory(wrongBinding)).toThrow(
      "ACTIVATION_LITERAL_MISMATCH",
    );

    const wrongMigration = structuredClone(inventory);
    object(wrongMigration, "activation_registry").migration_tag = "v1";
    expect(() => validateDurableObjectInventory(wrongMigration)).toThrow(
      "ACTIVATION_LITERAL_MISMATCH",
    );

    const aliased = structuredClone(inventory);
    object(aliased, "auth_replay_ledger").namespace_id =
      object(aliased, "release_ledgers").namespace_id ?? "";
    expect(() => validateDurableObjectInventory(aliased)).toThrow(
      "ACTIVATION_DURABLE_OBJECT_NAMESPACE_ALIAS_FORBIDDEN",
    );
  });

  it("rejects stale and future ceremony observations", () => {
    const now = Date.parse("2026-08-15T12:00:00.000Z");
    expect(() => assertObservedAtBounded("2026-08-15T12:00:30.000Z", now)).not.toThrow();
    expect(() => assertObservedAtBounded("2026-08-15T12:00:30.001Z", now)).toThrow(
      "ACTIVATION_OBSERVED_AT_OUT_OF_BOUNDS",
    );
    expect(() => assertObservedAtBounded("2026-08-15T11:44:59.999Z", now)).toThrow(
      "ACTIVATION_OBSERVED_AT_OUT_OF_BOUNDS",
    );
  });
});
