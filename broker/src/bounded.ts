import { assert, BrokerError } from "./errors";

const DEFAULT_IDLE_TIMEOUT_MS = 15_000;
const DEFAULT_TOTAL_TIMEOUT_MS = 30_000;
const DEFAULT_MAXIMUM_CHUNKS = 16_384;
const MAXIMUM_TIMEOUT_MS = 900_000;

export interface BoundedReadPolicy {
  readonly idleTimeoutMs?: number;
  readonly malformedStatus?: number;
  readonly maximumChunks?: number;
  readonly now?: () => number;
  readonly tooLargeStatus?: number;
  readonly totalTimeoutMs?: number;
}

export interface BoundedPipePolicy {
  readonly idleTimeoutMs?: number;
  readonly maximumChunks?: number;
  readonly now?: () => number;
  readonly totalTimeoutMs?: number;
}

/** Map private-service/provider response drift to service unavailability. */
export const INTERNAL_RESPONSE_READ_POLICY = Object.freeze({
  malformedStatus: 503,
  tooLargeStatus: 503,
});

/**
 * Read one stream under explicit byte, fragmentation, idle and absolute limits.
 * Any failed read cancels the upstream body before the reader lock is released.
 */
export async function readBoundedBytes(
  source: {
    readonly body: ReadableStream<Uint8Array> | null;
    readonly headers: Headers;
  },
  maximumBytes: number,
  errorCode: string,
  policy: BoundedReadPolicy = {},
): Promise<Uint8Array> {
  assert(Number.isSafeInteger(maximumBytes) && maximumBytes >= 0, "READ_BYTE_LIMIT_INVALID", 500);
  const malformedStatus = validFailureStatus(policy.malformedStatus ?? 400);
  const tooLargeStatus = validFailureStatus(policy.tooLargeStatus ?? 413);
  const declaredLength = await parseDeclaredLength(
    source,
    maximumBytes,
    errorCode,
    malformedStatus,
    tooLargeStatus,
  );
  if (source.body === null) {
    if (declaredLength !== null && declaredLength !== 0) {
      throw new BrokerError(`${errorCode}_CONTENT_LENGTH_MISMATCH`, malformedStatus, false);
    }
    return new Uint8Array();
  }

  const reader = source.body.getReader();
  const chunks: Uint8Array[] = [];
  const now = policy.now ?? Date.now;
  const idleTimeoutMs = positiveTimeout(policy.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS);
  const totalTimeoutMs = positiveTimeout(policy.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS);
  const maximumChunks = positiveChunkLimit(policy.maximumChunks ?? DEFAULT_MAXIMUM_CHUNKS);
  const startedAt = now();
  let chunkCount = 0;
  let total = 0;

  try {
    for (;;) {
      const elapsed = now() - startedAt;
      const remaining = totalTimeoutMs - elapsed;
      if (remaining <= 0) {
        throw new BrokerError(`${errorCode}_STREAM_TIMEOUT`, 504, true);
      }
      const item = await readBeforeDeadline(reader, Math.min(idleTimeoutMs, remaining), errorCode);
      if (item.done) break;

      chunkCount += 1;
      if (item.value.byteLength === 0 || chunkCount > maximumChunks) {
        throw new BrokerError(`${errorCode}_STREAM_SHAPE_INVALID`, malformedStatus, false);
      }
      total += item.value.byteLength;
      if (total > maximumBytes) {
        throw new BrokerError(errorCode, tooLargeStatus, false);
      }
      chunks.push(item.value);
    }
    if (declaredLength !== null && declaredLength !== total) {
      throw new BrokerError(`${errorCode}_CONTENT_LENGTH_MISMATCH`, malformedStatus, false);
    }
  } catch (error) {
    await reader.cancel(errorCode).catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

export async function readBoundedText(
  source: {
    readonly body: ReadableStream<Uint8Array> | null;
    readonly headers: Headers;
  },
  maximumBytes: number,
  errorCode: string,
  policy: BoundedReadPolicy = {},
): Promise<string> {
  const bytes = await readBoundedBytes(source, maximumBytes, errorCode, policy);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BrokerError(`${errorCode}_UTF8_INVALID`, policy.malformedStatus ?? 502, false);
  }
}

/**
 * Stream an exact number of bytes with backpressure while enforcing byte,
 * fragmentation, idle and absolute bounds. A failure cancels the source and
 * aborts the destination, so no consumer can accept a truncated prefix.
 */
export async function pipeBoundedBytes(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  expectedBytes: number,
  errorCode: string,
  policy: BoundedPipePolicy = {},
): Promise<void> {
  assert(Number.isSafeInteger(expectedBytes) && expectedBytes > 0, "PIPE_BYTE_LIMIT_INVALID", 500);
  const reader = source.getReader();
  const writer = destination.getWriter();
  const now = policy.now ?? Date.now;
  const idleTimeoutMs = positiveTimeout(policy.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS);
  const totalTimeoutMs = positiveTimeout(policy.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS);
  const maximumChunks = positiveChunkLimit(policy.maximumChunks ?? DEFAULT_MAXIMUM_CHUNKS);
  const startedAt = now();
  let chunkCount = 0;
  let total = 0;
  try {
    for (;;) {
      const item = await beforePipeDeadline(
        reader.read(),
        startedAt,
        now,
        idleTimeoutMs,
        totalTimeoutMs,
        errorCode,
      );
      if (item.done) break;
      chunkCount += 1;
      if (item.value.byteLength === 0 || chunkCount > maximumChunks) {
        throw new BrokerError(`${errorCode}_STREAM_SHAPE_INVALID`, 503, false);
      }
      total += item.value.byteLength;
      if (total > expectedBytes) {
        throw new BrokerError(`${errorCode}_LENGTH_MISMATCH`, 503, false);
      }
      await beforePipeDeadline(
        writer.write(item.value),
        startedAt,
        now,
        idleTimeoutMs,
        totalTimeoutMs,
        errorCode,
      );
    }
    if (total !== expectedBytes) {
      throw new BrokerError(`${errorCode}_LENGTH_MISMATCH`, 503, false);
    }
    await beforePipeDeadline(
      writer.close(),
      startedAt,
      now,
      idleTimeoutMs,
      totalTimeoutMs,
      errorCode,
    );
  } catch (error) {
    await Promise.allSettled([reader.cancel(errorCode), writer.abort(error)]);
    throw error;
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}

/**
 * Re-establish Content-Length at an isolate boundary while the bounded pump
 * validates the complete body without buffering a release archive in memory.
 */
export function boundedFixedLengthStream(
  source: ReadableStream<Uint8Array>,
  expectedBytes: number,
  errorCode: string,
  policy: BoundedPipePolicy = {},
): ReadableStream<Uint8Array> {
  const fixed = new FixedLengthStream(expectedBytes);
  void pipeBoundedBytes(source, fixed.writable, expectedBytes, errorCode, policy).catch(() => {
    // pipeBoundedBytes already aborts the fixed stream. Observing the promise
    // prevents an unhandled rejection while the downstream reader gets it.
  });
  return fixed.readable;
}

async function parseDeclaredLength(
  source: { readonly body: ReadableStream<Uint8Array> | null; readonly headers: Headers },
  maximumBytes: number,
  errorCode: string,
  malformedStatus: number,
  tooLargeStatus: number,
): Promise<number | null> {
  const value = source.headers.get("content-length");
  if (value === null) return null;
  if (!/^(?:0|[1-9][0-9]{0,15})$/u.test(value)) {
    return rejectAndCancel(source.body, `${errorCode}_CONTENT_LENGTH_INVALID`, malformedStatus);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    return rejectAndCancel(source.body, `${errorCode}_CONTENT_LENGTH_INVALID`, malformedStatus);
  }
  if (parsed > maximumBytes) {
    return rejectAndCancel(source.body, errorCode, tooLargeStatus);
  }
  return parsed;
}

function positiveTimeout(value: number): number {
  assert(
    Number.isSafeInteger(value) && value > 0 && value <= MAXIMUM_TIMEOUT_MS,
    "READ_TIMEOUT_INVALID",
    500,
  );
  return value;
}

async function beforePipeDeadline<T>(
  operation: Promise<T>,
  startedAt: number,
  now: () => number,
  idleTimeoutMs: number,
  totalTimeoutMs: number,
  errorCode: string,
): Promise<T> {
  const remaining = totalTimeoutMs - (now() - startedAt);
  if (remaining <= 0) {
    throw new BrokerError(`${errorCode}_STREAM_TIMEOUT`, 504, true);
  }
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new BrokerError(`${errorCode}_STREAM_TIMEOUT`, 504, true)),
          Math.min(idleTimeoutMs, remaining),
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function positiveChunkLimit(value: number): number {
  assert(
    Number.isSafeInteger(value) && value > 0 && value <= 100_000,
    "READ_CHUNK_LIMIT_INVALID",
    500,
  );
  return value;
}

function validFailureStatus(value: number): number {
  assert(Number.isSafeInteger(value) && value >= 400 && value <= 599, "READ_STATUS_INVALID", 500);
  return value;
}

async function readBeforeDeadline(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
  errorCode: string,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new BrokerError(`${errorCode}_STREAM_TIMEOUT`, 504, true)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function rejectAndCancel(
  body: ReadableStream<Uint8Array> | null,
  code: string,
  status: number,
): Promise<never> {
  await body?.cancel(code).catch(() => undefined);
  throw new BrokerError(code, status, false);
}
