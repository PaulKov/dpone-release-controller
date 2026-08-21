import { SHA1 } from "./activation-contract";
import { requireDigest } from "./activation-fields";
import type { JsonObject } from "./types";
import { requireString } from "./validation";

export function controllerActionFromProvisioned(controller: JsonObject): {
  readonly controllerActionBundleSha256: string;
  readonly controllerActionCommitSha: string;
  readonly controllerActionMetadataBlobSha: string;
} {
  return {
    controllerActionBundleSha256: requireDigest(controller, "controller_action_bundle_sha256"),
    controllerActionCommitSha: requireString(controller, "controller_action_commit_sha", 40, SHA1),
    controllerActionMetadataBlobSha: requireString(
      controller,
      "controller_action_metadata_blob_sha",
      40,
      SHA1,
    ),
  };
}
