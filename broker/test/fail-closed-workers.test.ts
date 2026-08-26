import { describe, expect, it } from "vitest";

import bootstrapPrivate from "../src/bootstrap-private";
import operationPlaceholder from "../src/private/fail-closed-worker";

describe("credential-free private deny Workers", () => {
  it.each([
    [bootstrapPrivate, "PRIVATE_BOOTSTRAP_DENY"],
    [operationPlaceholder, "PRIVATE_OPERATION_UNFROZEN"],
  ] as const)(
    "denies every private call without reading a body or provider",
    async (handler, code) => {
      let bodyRead = false;
      const request = {
        arrayBuffer() {
          bodyRead = true;
          throw new Error("body must remain unread");
        },
        headers: new Headers({ "x-request-id": "private-deny-request-0001" }),
        json() {
          bodyRead = true;
          throw new Error("body must remain unread");
        },
        text() {
          bodyRead = true;
          throw new Error("body must remain unread");
        },
      } as unknown as Request;
      const response = handler.fetch(request);
      expect(response.status).toBe(503);
      expect(bodyRead).toBe(false);
      await expect(response.json()).resolves.toEqual({
        error: {
          code,
          request_id: "private-deny-request-0001",
          retryable: false,
        },
      });
    },
  );
});
