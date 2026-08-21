import { describe, expect, it } from "vitest";

import {
  deploymentReviewBody,
  deploymentReviewUrl,
  parseDeploymentCallbackUrl,
  verifyGitHubWebhookHmac,
} from "../src/deployment-gate-policy";

const EXPECTED =
  "https://api.github.com/repos/PaulKov/dpone-release-controller/actions/runs/123456789/deployment_protection_rule";

describe("PyPI deployment protection gate", () => {
  it("reconstructs only the exact GitHub review endpoint", () => {
    expect(parseDeploymentCallbackUrl(EXPECTED)).toBe("123456789");
    expect(deploymentReviewUrl("123456789")).toBe(EXPECTED);
    expect(
      new TextDecoder().decode(deploymentReviewBody("approved", `sha256:${"a".repeat(64)}`)),
    ).toBe(
      `{"comment":"dpone release authority receipt sha256:${"a".repeat(64)}","environment_name":"pypi","state":"approved"}`,
    );
  });

  it("rejects callback host, scheme, userinfo, query, path and run-id drift", () => {
    const invalid = [
      EXPECTED.replace("https:", "http:"),
      EXPECTED.replace("api.github.com", "evil.invalid"),
      EXPECTED.replace("https://", "https://attacker@"),
      `${EXPECTED}?redirect=https://evil.invalid`,
      `${EXPECTED}#fragment`,
      EXPECTED.replace("/actions/runs/", "/releases/"),
      EXPECTED.replace("123456789", "0"),
      EXPECTED.replace("123456789", "1/../../admin"),
    ];
    for (const value of invalid) {
      expect(() => parseDeploymentCallbackUrl(value), value).toThrowError();
    }
  });

  it("verifies webhook HMAC bytes and rejects tampering", async () => {
    const secret = new TextEncoder().encode("s".repeat(32));
    const body = new TextEncoder().encode('{"action":"requested"}');
    const key = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(secret).buffer,
      { hash: "SHA-256", name: "HMAC" },
      false,
      ["sign"],
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, Uint8Array.from(body).buffer),
    );
    const header = `sha256=${[...signature]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("")}`;
    await expect(verifyGitHubWebhookHmac(body, header, secret)).resolves.toBeUndefined();
    const tampered = new TextEncoder().encode('{"action":"approved"}');
    await expect(verifyGitHubWebhookHmac(tampered, header, secret)).rejects.toThrowError(
      "PYPI_GATE_WEBHOOK_SIGNATURE_INVALID",
    );
  });
});
