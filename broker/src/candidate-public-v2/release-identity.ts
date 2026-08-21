import { PUBLIC_PROJECTS } from "./distributions";
import { candidateAssert } from "./error";
import { publicV2Id } from "./identity";
import type { DigestSha256 } from "./types";
import { TAG } from "./validation";

export const PUBLIC_RELEASE_ID_DOMAIN = "dpone.release.public-identity.v2";

export async function publicReleaseId(tag: string): Promise<DigestSha256> {
  candidateAssert(TAG.test(tag), "PUBLIC_V2_RELEASE_TAG_INVALID");
  return publicV2Id(PUBLIC_RELEASE_ID_DOMAIN, {
    projects: [...PUBLIC_PROJECTS],
    release: tag,
  });
}
