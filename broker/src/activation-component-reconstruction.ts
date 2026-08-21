import { PROVISION_REQUEST_SCHEMA, SHA1 } from "./activation-contract";
import {
  verifyAdminAccessPrincipalDigests,
  verifyProvisionEvidenceDigests,
} from "./activation-record-builders";
import {
  validateController,
  validateControllerGovernance,
  validateOidc,
  validateTargetGovernance,
  validateTrustedPublishers,
} from "./activation-governance";
import {
  validateAdminAccess,
  validateApps,
  validateB2,
  validateBroker,
} from "./activation-infrastructure";
import type { ActivationComponentSetSemanticInput } from "./activation-component-journal-contract";
import { reconstructActivationAuthorities } from "./activation-component-authority-reconstruction";
import { parseActivationComponentPayloadSet } from "./activation-component-payload-codec";
import type { ValidatedActivationComponentSet } from "./activation-component-payload-contract";
import type { ProvisionRequest } from "./activation-schema-types";
import { assert } from "./errors";
import type { ActivationComponentSemanticTrust, JsonObject } from "./types";
import { requireObject, requireString } from "./validation";

/** Parse, reconstruct, and fully validate every confidential A0 component. */
export async function validateAndReconstructActivationComponentSet(
  input: ActivationComponentSetSemanticInput,
  trustedConfig: ActivationComponentSemanticTrust,
): Promise<ValidatedActivationComponentSet> {
  const config = snapshotConfig(trustedConfig);
  const parsed = await parseActivationComponentPayloadSet(input);
  assert(
    parsed.descriptor.workerVersionId === config.workerVersionId,
    "ACTIVATION_COMPONENT_WORKER_MISMATCH",
    409,
  );
  const payloads = parsed.payloads;
  const authorities = await reconstructActivationAuthorities(payloads, config);
  validateBroker(authorities.broker);
  validateAdminAccess(payloads.admin_access, config);
  validateB2(payloads.b2);
  const controller = validateController(payloads.controller);
  validateApps(
    authorities.githubApps,
    requireObject(authorities.broker.private_services, "ACTIVATION_SERVICES_REQUIRED"),
  );
  const oidc = validateOidc(payloads.oidc, controller);
  validateControllerGovernance(payloads.controller_governance, authorities.githubApps, controller);
  validateTargetGovernance(
    payloads.target_governance,
    requireString(controller, "controller_action_commit_sha", 40, SHA1),
  );
  const publishers = payloads.trusted_publishers.publishers;
  validateTrustedPublishers(publishers);

  const serviceAuthorities: JsonObject = {
    expectation: authorities.expectation.document,
    expectation_sha256: authorities.expectation.expectationSha256,
  };
  const evidence: JsonObject = {
    admin_access: payloads.admin_access,
    b2: payloads.b2,
    broker: authorities.broker,
    controller,
    controller_governance: payloads.controller_governance,
    github_apps: authorities.githubApps,
    oidc,
    service_authorities: serviceAuthorities,
    target_governance: payloads.target_governance,
    trusted_publishers: publishers ?? null,
  };
  const request = validationRequest(
    evidence,
    authorities.broker,
    controller,
    oidc,
    serviceAuthorities,
    parsed.descriptor.committedAt,
  );
  await verifyProvisionEvidenceDigests(request);
  await verifyAdminAccessPrincipalDigests(request, config);
  return deepFreeze({
    broker: authorities.broker,
    descriptor: {
      committedAt: parsed.descriptor.committedAt,
      components: parsed.descriptor.components.map((component) => ({ ...component })),
      descriptorId: parsed.descriptor.descriptorId,
      descriptorSha256: parsed.descriptor.descriptorSha256,
      setId: parsed.descriptor.setId,
      workerVersionId: parsed.descriptor.workerVersionId,
    },
    evidence,
    githubApps: authorities.githubApps,
    payloads,
    serviceAuthorityExpectation: authorities.expectation,
    trust: "VALIDATED" as const,
  });
}

function validationRequest(
  evidence: JsonObject,
  broker: JsonObject,
  controller: JsonObject,
  oidc: JsonObject,
  serviceAuthorities: JsonObject,
  observedAt: string,
): ProvisionRequest {
  return {
    body: {
      evidence,
      observed_at: observedAt,
      request_id: "activation-component-validation-v2",
      schema: PROVISION_REQUEST_SCHEMA,
      schema_version: 1,
    },
    broker,
    controller,
    evidence,
    observedAt,
    oidc,
    requestId: "activation-component-validation-v2",
    serviceAuthorities,
  };
}

function snapshotConfig(
  config: ActivationComponentSemanticTrust,
): ActivationComponentSemanticTrust {
  return Object.freeze({
    adminAccessApplicationId: config.adminAccessApplicationId,
    adminAccessAudience: config.adminAccessAudience,
    adminAccessGroup: config.adminAccessGroup,
    adminAccessIdentity: config.adminAccessIdentity,
    adminAccessIssuer: config.adminAccessIssuer,
    adminAccessPolicyId: config.adminAccessPolicyId,
    adminAccessSubjectId: config.adminAccessSubjectId,
    adminHostname: config.adminHostname,
    adminMtlsCertSha256: config.adminMtlsCertSha256,
    cloudflareAccountId: config.cloudflareAccountId,
    workerServiceIdentity: config.workerServiceIdentity,
    workerVersionId: config.workerVersionId,
  });
}

function deepFreeze<T extends object>(value: T): T {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") deepFreeze(child);
  }
  return Object.freeze(value);
}
