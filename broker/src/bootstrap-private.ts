import { BrokerError, errorResponse } from "./errors";
import { requestId } from "./validation";

/** Route-less one-use baseline for private service-binding dependencies. */
export default {
  fetch(request: Request): Response {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      throw new BrokerError("PRIVATE_BOOTSTRAP_DENY", 503, false);
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler;
