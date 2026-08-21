import { parseCanonicalPublicV2 } from "./canonical";
import { candidateAssert } from "./error";
import { requireDigest } from "./identity";
import { publicReleaseId } from "./release-identity";
import type { CandidateJsonObject } from "./types";
import { TAG, exactObject, literalField } from "./validation";

export const RUNTIME_CLOSURE_REQUEST_SCHEMA = "dpone.release-runtime-closure-request.v2";

export async function parseRuntimeClosureRequest(input: Uint8Array): Promise<CandidateJsonObject> {
  const request = exactObject(
    parseCanonicalPublicV2(input),
    ["public_release_id", "schema", "schema_version", "tag"],
    "PUBLIC_V2_CLOSURE_REQUEST_INVALID",
  );
  const releaseId = requireDigest(request.public_release_id, "PUBLIC_V2_RELEASE_ID_INVALID");
  literalField(
    request,
    "schema",
    RUNTIME_CLOSURE_REQUEST_SCHEMA,
    "PUBLIC_V2_CLOSURE_REQUEST_INVALID",
  );
  literalField(request, "schema_version", 2, "PUBLIC_V2_CLOSURE_REQUEST_INVALID");
  const tag = request.tag;
  candidateAssert(typeof tag === "string" && TAG.test(tag), "PUBLIC_V2_RELEASE_TAG_INVALID");
  candidateAssert(releaseId === (await publicReleaseId(tag)), "PUBLIC_V2_RELEASE_ID_MISMATCH");
  return request;
}
