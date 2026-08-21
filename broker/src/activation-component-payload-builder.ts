import { APP_PERMISSIONS } from "./activation-contract";
import {
  activationJsonBudget,
  decodeBoundedActivationObject,
  exactActivationObject,
  componentError,
} from "./activation-component-codec";
import {
  ACTIVATION_COMPONENT_KINDS,
  ACTIVATION_COMPONENT_MAX_DEPTH,
  ACTIVATION_COMPONENT_MAX_STRING_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
  ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
  type ActivationComponentKind,
  type ActivationComponentPayloadInput,
} from "./activation-component-contract";
import {
  ADMIN_ACCESS_FIELDS,
  B2_FIELDS,
  BROKER_CORE_FIELDS,
  BROKER_FIELDS,
  CONTROLLER_FIELDS,
  CONTROLLER_GOVERNANCE_FIELDS,
  GITHUB_APP_FIELDS,
  NORMALIZED_GITHUB_APP_FIELDS,
  OIDC_FIELDS,
  TARGET_GOVERNANCE_FIELDS,
} from "./activation-component-payload-fields";
import { canonicalBytes, canonicalJson } from "./canonical";
import {
  RECEIPT_ROLE_BINDINGS,
  SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
  type ServiceAuthorityExpectation,
  assertServiceAuthorityExpectationMatchesBroker,
} from "./service-authority-expectation";
import type { ExpectedDeploymentVersion } from "./service-authority";
import type { ProvisionRequest } from "./activation-schema-types";
import type { JsonObject, JsonValue } from "./types";
import { exactObject, requireObject } from "./validation";

const BUILD_INVALID = "ACTIVATION_COMPONENT_PAYLOAD_BUILD_INVALID";

/** Normalize one already parsed v1 A0 request into the fixed candidate component roster. */
export function buildActivationComponentPayloads(
  request: ProvisionRequest,
  expectation: ServiceAuthorityExpectation,
): readonly ActivationComponentPayloadInput[] {
  const evidence = request.evidence;
  const broker = exactObject(request.broker, BROKER_FIELDS);
  const apps = exactObject(
    requireObject(evidence.github_apps, BUILD_INVALID),
    Object.keys(APP_PERMISSIONS),
  );
  assertServiceAuthorityExpectationMatchesBroker(expectation, broker);
  if (
    request.serviceAuthorities.expectation_sha256 !== expectation.expectationSha256 ||
    canonicalJson(request.serviceAuthorities.expectation) !== canonicalJson(expectation.document)
  ) {
    throw componentError(BUILD_INVALID);
  }
  const documents: Readonly<Record<ActivationComponentKind, JsonObject>> = {
    admin_access: exactObject(evidence.admin_access, ADMIN_ACCESS_FIELDS),
    b2: exactObject(evidence.b2, B2_FIELDS),
    broker_core: {
      ...selectFields(
        broker,
        BROKER_CORE_FIELDS.filter((field) => field !== "authority_role"),
      ),
      authority_role: "release_authority_ingress",
    },
    controller: exactObject(request.controller, CONTROLLER_FIELDS),
    controller_governance: exactObject(
      evidence.controller_governance,
      CONTROLLER_GOVERNANCE_FIELDS,
    ),
    github_apps: normalizeApps(apps),
    oidc: exactObject(request.oidc, OIDC_FIELDS),
    service_authority_header: {
      broker_source_commit_sha: expectation.document.broker_source_commit_sha ?? null,
      cloudflare_account_id: expectation.document.cloudflare_account_id ?? null,
      expectation_sha256: expectation.expectationSha256,
      schema: SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
      schema_version: 1,
    },
    service_authority_inventory: {
      authorities: expectation.authorities.map((row) => ({ ...row })),
    },
    service_authority_a0_deployments: {
      deployments: expectation.a0PreDeployments.map(normalizeDeployment),
    },
    service_authority_a1_deployments: {
      deployments: expectation.a1PrecommitDeployments.map(normalizeDeployment),
    },
    service_authority_network: {
      authority_role: "release_authority_ingress",
      cert_id: expectation.networkSurface.cert_id,
      domain_id: expectation.networkSurface.domain_id,
      environment: expectation.networkSurface.environment,
      hostname: expectation.networkSurface.hostname,
      zone_id: expectation.networkSurface.zone_id,
      zone_name: expectation.networkSurface.zone_name,
    },
    service_authority_receipt_bindings: {
      receipt_role_bindings: RECEIPT_ROLE_BINDINGS.map((row) => ({ ...row })),
    },
    target_governance: exactObject(evidence.target_governance, TARGET_GOVERNANCE_FIELDS),
    trusted_publishers: {
      publishers: evidence.trusted_publishers ?? null,
    },
  };
  return Object.freeze(
    ACTIVATION_COMPONENT_KINDS.map((componentKind) =>
      payloadInput(componentKind, documents[componentKind]),
    ),
  );
}

function normalizeApps(apps: JsonObject): JsonObject {
  return Object.fromEntries(
    Object.keys(APP_PERMISSIONS).map((role) => {
      const app = exactObject(apps[role], GITHUB_APP_FIELDS);
      return [role, selectFields(app, NORMALIZED_GITHUB_APP_FIELDS)];
    }),
  );
}

function normalizeDeployment(deployment: {
  readonly authority_role: string;
  readonly deployment_id: string | null;
  readonly deployment_versions: readonly ExpectedDeploymentVersion[];
}): JsonObject {
  return {
    authority_role: deployment.authority_role,
    deployment_id: deployment.deployment_id,
    deployment_versions: deployment.deployment_versions.map((member) =>
      member.artifact_kind === "FINAL_AUTHORITY"
        ? {
            artifact_kind: member.artifact_kind,
            percentage: member.percentage,
            provisioning_record_id: member.provisioning_record_id,
            provisioning_record_sha256: member.provisioning_record_sha256,
            script_etag: member.script_etag,
          }
        : { ...member },
    ),
  };
}

function selectFields(source: JsonObject, fields: readonly string[]): JsonObject {
  return Object.fromEntries(fields.map((field) => [field, source[field] as JsonValue]));
}

function payloadInput(
  componentKind: ActivationComponentKind,
  document: JsonObject,
): ActivationComponentPayloadInput {
  activationJsonBudget(
    document,
    {
      bytes: ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH - 2,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
    },
    BUILD_INVALID,
  );
  const bytes = canonicalBytes(document);
  const parsed = decodeBoundedActivationObject(
    bytes,
    {
      bytes: ACTIVATION_COMPONENT_PAYLOAD_MAX_BYTES,
      depth: ACTIVATION_COMPONENT_MAX_DEPTH - 2,
      maxStringBytes: ACTIVATION_COMPONENT_MAX_STRING_BYTES,
      nodes: ACTIVATION_COMPONENT_PAYLOAD_MAX_NODES,
    },
    BUILD_INVALID,
  );
  exactActivationObject(parsed.value, Object.keys(document), BUILD_INVALID);
  return Object.freeze({ canonicalPayloadBytes: parsed.bytes, componentKind });
}
