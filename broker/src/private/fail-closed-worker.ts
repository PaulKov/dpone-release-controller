import { BrokerError, errorResponse } from "../errors";
import { requestId } from "../validation";

/**
 * Typed-service placeholder for operations whose schema/transaction contract
 * is not yet frozen. It owns no credential and performs no outbound request.
 */
export default {
  fetch(request: Request): Response {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      throw new BrokerError("PRIVATE_OPERATION_UNFROZEN", 503, false);
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler;
