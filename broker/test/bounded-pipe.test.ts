import { describe, expect, it } from "vitest";

import { pipeBoundedBytes } from "../src/bounded";

describe("bounded streaming pump", () => {
  it("streams an exact body with backpressure", async () => {
    const received: number[] = [];
    await pipeBoundedBytes(
      chunks([
        [1, 2],
        [3, 4],
      ]).stream,
      sink({ write: (chunk) => received.push(...chunk) }).stream,
      4,
      "TEST_BODY",
      { maximumChunks: 2 },
    );
    expect(received).toEqual([1, 2, 3, 4]);
  });

  it.each([
    {
      chunks: [[1, 2, 3]],
      code: "TEST_BODY_LENGTH_MISMATCH",
      expectedBytes: 4,
    },
    {
      chunks: [[1, 2, 3, 4, 5]],
      code: "TEST_BODY_LENGTH_MISMATCH",
      expectedBytes: 4,
    },
    {
      chunks: [[], [1, 2, 3, 4]],
      code: "TEST_BODY_STREAM_SHAPE_INVALID",
      expectedBytes: 4,
    },
    {
      chunks: [[1], [2], [3], [4]],
      code: "TEST_BODY_STREAM_SHAPE_INVALID",
      expectedBytes: 4,
    },
  ])("cancels and aborts invalid whole bodies: $code", async (testCase) => {
    const source = chunks(testCase.chunks);
    const destination = sink();
    await expect(
      pipeBoundedBytes(source.stream, destination.stream, testCase.expectedBytes, "TEST_BODY", {
        maximumChunks: 3,
      }),
    ).rejects.toThrow(testCase.code);
    expect(destination.aborted).toBe(true);
  });

  it("enforces idle and absolute deadlines and cancels upstream", async () => {
    let cancelled = false;
    const source = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
      pull() {
        return new Promise(() => undefined);
      },
    });
    await expect(
      pipeBoundedBytes(source, sink().stream, 4, "TEST_BODY", {
        idleTimeoutMs: 5,
        totalTimeoutMs: 10,
      }),
    ).rejects.toThrow("TEST_BODY_STREAM_TIMEOUT");
    expect(cancelled).toBe(true);
  });
});

function chunks(values: readonly (readonly number[])[]): {
  readonly stream: ReadableStream<Uint8Array>;
  readonly cancelled: boolean;
} {
  let cancelled = false;
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
    pull(controller) {
      const value = values[index];
      index += 1;
      if (value === undefined) controller.close();
      else controller.enqueue(Uint8Array.from(value));
    },
  });
  return {
    get cancelled() {
      return cancelled;
    },
    stream,
  };
}

function sink(
  options: {
    readonly write?: (chunk: Uint8Array) => void;
  } = {},
): { readonly stream: WritableStream<Uint8Array>; readonly aborted: boolean } {
  let aborted = false;
  const stream = new WritableStream<Uint8Array>({
    abort() {
      aborted = true;
    },
    write(chunk) {
      options.write?.(chunk);
    },
  });
  return {
    get aborted() {
      return aborted;
    },
    stream,
  };
}
