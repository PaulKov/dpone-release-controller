import { describe, expect, it } from "vitest";

import { AUDIENCES } from "../src/activation-contract";
import { validateBroker } from "../src/activation-infrastructure";
import { SAFE_CLOUDFLARE_MIGRATION_TAG } from "../src/cloudflare-migration-tag";
import type { JsonObject } from "../src/types";
import {
  SOURCE_COMMIT,
  WORKER_VERSION,
  durableObjects,
  privateServices,
  tagged,
} from "./activation-schema-topology.fixtures";

describe("activation broker validation", () => {
  it("accepts a safe migration tag without pinning the broker to v3", () => {
    const migrationTag = "release.2026-08-19_v4";

    expect(SAFE_CLOUDFLARE_MIGRATION_TAG.test(migrationTag)).toBe(true);
    expect(validateBroker(brokerFixture(migrationTag)).durable_object_migration_tag).toBe(
      migrationTag,
    );
  });

  it.each(["", ".v4", "v4/next", "v4 next", "v4\nnext", "v".repeat(129)])(
    "rejects unsafe migration tag %j",
    (migrationTag) => {
      expect(() => validateBroker(brokerFixture(migrationTag))).toThrow("FIELD_INVALID");
    },
  );

  it("requires the migration tag in broker evidence", () => {
    const broker = brokerFixture("v4");
    delete broker.durable_object_migration_tag;

    expect(() => validateBroker(broker)).toThrow("FIELD_INVALID");
  });
});

function brokerFixture(migrationTag: string): JsonObject {
  const accountId = "0".repeat(32);
  const workerScript = "dpone-release-authority-broker";
  const workerHostname = "release.example.test";
  return {
    api_version: "v1",
    audiences: { ...AUDIENCES },
    cloudflare_account_id: accountId,
    configuration_sha256: tagged(201),
    durable_object_migration_tag: migrationTag,
    durable_object_namespaces: durableObjects(),
    endpoint: `https://${workerHostname}`,
    lockfile_sha256: tagged(202),
    openapi_sha256: tagged(203),
    private_services: privateServices(),
    route_schema_sha256: tagged(204),
    service_identity: `cloudflare-worker:${accountId}/${workerScript}@${WORKER_VERSION}`,
    source_commit_sha: SOURCE_COMMIT,
    source_path: "broker",
    source_repository: "PaulKov/dpone-release-controller",
    source_repository_id: 1_305_993_853,
    source_sha256: tagged(205),
    source_tree_sha: "b".repeat(40),
    version_resource_projection_sha256: tagged(206),
    worker_hostname: workerHostname,
    worker_script: workerScript,
    worker_version_id: WORKER_VERSION,
    worker_version_tag: "release-v4",
  };
}
