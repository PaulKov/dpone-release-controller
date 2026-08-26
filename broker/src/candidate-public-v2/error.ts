/** Candidate-only fail-closed error for the pure public-v2 codecs. */
export class CandidatePublicV2Error extends Error {
  public readonly code: string;

  public constructor(code: string) {
    super(code);
    this.name = "CandidatePublicV2Error";
    this.code = code;
  }
}

/** Keep validation branches explicit without coupling candidate code to broker errors. */
export function candidateAssert(condition: boolean, code: string): asserts condition {
  if (!condition) throw new CandidatePublicV2Error(code);
}
