import { describe, expect, it } from "vitest";

import { buildFullCandidate } from "./candidate-public-v2-fixtures";

describe("candidate public-v2 deterministic vector", () => {
  it("pins candidate identities, commitments, private nonce fingerprint and ZIP digest", async () => {
    const { activated, archive, closure, proof, provisioned } = await buildFullCandidate();
    expect({
      activatedCommitment: activated.commitment,
      activatedId: activated.document.record_id,
      archiveBytes: archive.archiveBytes.byteLength,
      archiveSha256: archive.archiveSha256,
      closureCommitment: closure.commitment,
      closureId: closure.document.closure_id,
      nonceFingerprintSha256: provisioned.nonceFingerprintSha256,
      proofCommitment: proof.commitment,
      proofId: proof.document.proof_id,
      provisionedCommitment: provisioned.commitment,
      provisionedId: provisioned.document.record_id,
    }).toEqual({
      activatedCommitment:
        "sha256:e4c8ab23b2150bd3cbce84974e046e92df33a9bb53ca2843b50150e484ddbe8b",
      activatedId: "sha256:4ae98ae1637df48dcc9ba97c9cb81c463167eb28a03d3e178e92bfda70267866",
      archiveBytes: 6_111,
      archiveSha256: "sha256:53a4819a07c92accbb4df5f2c193fc94e91f13ff085bdd0d21d537f431508ad2",
      closureCommitment: "sha256:9e9619fab09d5940cf5a314b77e54ca10476db5a95c0e57ed0d4212dd5455c4f",
      closureId: "sha256:e45c7c340f30f1edb90be7ebe9aea318db04ad752b631f09bd4e697135a1b065",
      nonceFingerprintSha256:
        "sha256:72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793",
      proofCommitment: "sha256:8f7523e7ac2c2f023d4a80b2dd0cd0c62efaacfa6786049b98cac7800b54aafd",
      proofId: "sha256:bcb8021fd5daeb0984fe4438acc61d7e721c944f5d4a76cde1a07554c9ff3545",
      provisionedCommitment:
        "sha256:3dd4c97155215afde48a33395c4828232ca3d79f4418692e575a6cdd6e443406",
      provisionedId: "sha256:d0b163bff0666d76fd950ba9c6ed78abd01c88e2cf11e09503b31b181767a692",
    });
  });
});
