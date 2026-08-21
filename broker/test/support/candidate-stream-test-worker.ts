import { buildCandidateStreamResponse } from "../../src/candidate-stream";
import { boundedFixedLengthStream } from "../../src/bounded";
import type { CandidateReaderStream } from "../../src/candidate-reader-client";
import {
  CANDIDATE_READER_PIN,
  asCandidateReaderStream,
  candidateServiceFixture,
} from "./candidate-reader-service-fixture";

const EXPECTED_BYTES = 4;
const TEST_PIPE_POLICY = {
  idleTimeoutMs: 50,
  maximumChunks: 3,
  totalTimeoutMs: 200,
};

/** Test-only network boundary for validating Workers FixedLengthStream semantics. */
export default {
  async fetch(request: Request): Promise<Response> {
    const fixture = await candidateServiceFixture();
    const baseline = asCandidateReaderStream(fixture);
    const path = new URL(request.url).pathname;
    const stream: CandidateReaderStream = {
      ...baseline,
      // The first pump models provider -> private Worker. The response builder
      // adds the second private Worker -> ingress pump used in production.
      body: boundedFixedLengthStream(
        faultBody(path),
        EXPECTED_BYTES,
        "TEST_PRIVATE_SOURCE",
        TEST_PIPE_POLICY,
      ),
      length: EXPECTED_BYTES,
    };
    return buildCandidateStreamResponse(
      stream,
      CANDIDATE_READER_PIN,
      fixture.input.requestId,
      TEST_PIPE_POLICY,
    );
  },
};

function faultBody(path: string): ReadableStream<Uint8Array> {
  if (path === "/success") return bytesBody([0x50, 0x4b, 0x03, 0x04]);
  if (path === "/short") return bytesBody([0x50, 0x4b, 0x03]);
  if (path === "/long") return bytesBody([0x50, 0x4b, 0x03, 0x04, 0x05]);
  if (path === "/fragmented") {
    return chunksBody([[0x50], [0x4b], [0x03], [0x04]]);
  }
  if (path === "/empty") {
    return chunksBody([[], [0x50, 0x4b, 0x03, 0x04]]);
  }
  if (path === "/stall") {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(Uint8Array.from([0x50, 0x4b]));
      },
    });
  }
  if (path === "/abort") {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("synthetic upstream abort"));
      },
    });
  }
  throw new Error("unknown candidate stream test path");
}

function bytesBody(bytes: readonly number[]): ReadableStream<Uint8Array> {
  return chunksBody([bytes]);
}

function chunksBody(chunks: readonly (readonly number[])[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(Uint8Array.from(chunk));
      controller.close();
    },
  });
}
