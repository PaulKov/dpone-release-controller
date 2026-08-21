import {
  APP_PERMISSIONS,
  POSITIVE_ID,
  SAFE_NAME,
  SERVICE_BINDINGS,
  WORKER_VERSION,
} from "./activation-contract";
import {
  nested,
  requireDigest,
  requireExactInteger,
  requireExactStringArray,
  requireLiteral,
} from "./activation-fields";
import { TRUST } from "./config";
import { assert } from "./errors";
import type { JsonObject } from "./types";
import { exactObject, requireBoolean, requireObject, requireString } from "./validation";

/** Validate the exact closed GitHub App authority set and service pins. */
export function validateApps(apps: JsonObject, services: JsonObject): void {
  const exact = exactObject(apps, Object.keys(APP_PERMISSIONS));
  const appIds: string[] = [];
  const appSlugs: string[] = [];
  const credentialFingerprints: string[] = [];
  const installationIds: string[] = [];
  for (const [role, permissions] of Object.entries(APP_PERMISSIONS)) {
    const app = nested(exact, role, [
      "app_id",
      "app_slug",
      "credential_fingerprint_sha256",
      "installation_id",
      "oauth_callback_configured",
      "permissions",
      "provider_observation_sha256",
      "repository",
      "repository_id",
      "repository_selection",
      "repository_selection_evidence_sha256",
      "request_on_install_enabled",
      "service_binding",
      "subscriptions",
      "user_authorization_enabled",
      "webhook_active",
      "worker_version_id",
    ]);
    appIds.push(requireString(app, "app_id", 32, POSITIVE_ID));
    installationIds.push(requireString(app, "installation_id", 32, POSITIVE_ID));
    appSlugs.push(requireString(app, "app_slug", 128, SAFE_NAME));
    credentialFingerprints.push(requireDigest(app, "credential_fingerprint_sha256"));
    requireDigest(app, "provider_observation_sha256");
    requireLiteral(app, "service_binding", SERVICE_BINDINGS[role as keyof typeof SERVICE_BINDINGS]);
    const service = requireObject(services[role], "ACTIVATION_APP_SERVICE_INVALID");
    assert(
      app.worker_version_id === service.worker_version_id,
      "ACTIVATION_APP_SERVICE_VERSION_MISMATCH",
    );
    requireString(app, "worker_version_id", 128, WORKER_VERSION);
    requireExactStringArray(app, "permissions", permissions);
    const controllerScoped = role === "controller_run_reader" || role === "pypi_deployment_gate";
    const deploymentGate = role === "pypi_deployment_gate" || role === "runtime_deployment_gate";
    requireLiteral(
      app,
      "repository",
      controllerScoped ? TRUST.controllerRepository : TRUST.targetRepository,
    );
    requireExactInteger(
      app,
      "repository_id",
      controllerScoped ? TRUST.controllerRepositoryId : TRUST.targetRepositoryId,
    );
    requireLiteral(app, "repository_selection", "selected");
    requireDigest(app, "repository_selection_evidence_sha256");
    requireExactStringArray(
      app,
      "subscriptions",
      deploymentGate ? ["deployment_protection_rule"] : [],
    );
    assert(
      !requireBoolean(app, "oauth_callback_configured") &&
        !requireBoolean(app, "request_on_install_enabled") &&
        !requireBoolean(app, "user_authorization_enabled") &&
        requireBoolean(app, "webhook_active") === deploymentGate,
      "ACTIVATION_APP_INTERACTIVE_SURFACE_FORBIDDEN",
    );
  }
  assert(new Set(appIds).size === appIds.length, "ACTIVATION_APP_ID_ALIAS_FORBIDDEN");
  assert(new Set(appSlugs).size === appSlugs.length, "ACTIVATION_APP_SLUG_ALIAS_FORBIDDEN");
  assert(
    new Set(credentialFingerprints).size === credentialFingerprints.length,
    "ACTIVATION_APP_CREDENTIAL_ALIAS_FORBIDDEN",
  );
  assert(
    new Set(installationIds).size === installationIds.length,
    "ACTIVATION_APP_INSTALLATION_ALIAS_FORBIDDEN",
  );
}
