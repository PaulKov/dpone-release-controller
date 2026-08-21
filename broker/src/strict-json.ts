import { BrokerError } from "./errors";
import type { JsonObject } from "./types";

const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/uy;

/**
 * Decode provider JSON while rejecting duplicate object members before
 * `JSON.parse` can silently apply last-member-wins semantics.
 *
 * Provider documents need not use the broker's canonical serialization, but
 * they must be exact UTF-8 JSON with bounded depth and node counts.
 */
export function parseStrictJsonObject(
  bytes: Uint8Array,
  code: string,
  maximumDepth = 64,
  maximumNodes = 100_000,
): JsonObject {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BrokerError(`${code}_UTF8_INVALID`, 503, false);
  }
  new ExactJsonScanner(text, code, maximumDepth, maximumNodes).scan();
  let decoded: unknown;
  try {
    decoded = JSON.parse(text) as unknown;
  } catch {
    throw new BrokerError(code, 503, false);
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new BrokerError(code, 503, false);
  }
  return decoded as JsonObject;
}

class ExactJsonScanner {
  private index = 0;
  private nodes = 0;

  public constructor(
    private readonly text: string,
    private readonly code: string,
    private readonly maximumDepth: number,
    private readonly maximumNodes: number,
  ) {
    if (
      !Number.isSafeInteger(maximumDepth) ||
      maximumDepth < 1 ||
      !Number.isSafeInteger(maximumNodes) ||
      maximumNodes < 1
    ) {
      throw new BrokerError("STRICT_JSON_BUDGET_INVALID", 500, false);
    }
  }

  public scan(): void {
    this.skipWhitespace();
    this.value(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.invalid();
  }

  private value(depth: number): void {
    this.nodes += 1;
    if (depth > this.maximumDepth || this.nodes > this.maximumNodes) this.invalid();
    const current = this.text[this.index];
    if (current === "{") {
      this.object(depth + 1);
    } else if (current === "[") {
      this.array(depth + 1);
    } else if (current === '"') {
      this.string();
    } else if (current === "t") {
      this.literal("true");
    } else if (current === "f") {
      this.literal("false");
    } else if (current === "n") {
      this.literal("null");
    } else {
      JSON_NUMBER.lastIndex = this.index;
      const match = JSON_NUMBER.exec(this.text);
      if (match === null) this.invalid();
      this.index = JSON_NUMBER.lastIndex;
    }
  }

  private object(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.consume("}")) return;
    for (;;) {
      if (this.text[this.index] !== '"') this.invalid();
      const key = this.string();
      if (keys.has(key)) throw new BrokerError(`${this.code}_DUPLICATE_FIELD`, 503, false);
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.invalid();
      this.skipWhitespace();
      this.value(depth);
      this.skipWhitespace();
      if (this.consume("}")) return;
      if (!this.consume(",")) this.invalid();
      this.skipWhitespace();
    }
  }

  private array(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("]")) return;
    for (;;) {
      this.value(depth);
      this.skipWhitespace();
      if (this.consume("]")) return;
      if (!this.consume(",")) this.invalid();
      this.skipWhitespace();
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    for (;;) {
      const current = this.text[this.index];
      if (current === undefined || current.charCodeAt(0) < 0x20) this.invalid();
      if (current === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.text.slice(start, this.index)) as string;
        } catch {
          this.invalid();
        }
      }
      if (current === "\\") {
        this.index += 1;
        if (this.text[this.index] === undefined) this.invalid();
      }
      this.index += 1;
    }
  }

  private literal(expected: string): void {
    if (!this.text.startsWith(expected, this.index)) this.invalid();
    this.index += expected.length;
  }

  private skipWhitespace(): void {
    while (/^[\t\n\r ]$/u.test(this.text[this.index] ?? "")) this.index += 1;
  }

  private consume(expected: string): boolean {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  private invalid(): never {
    throw new BrokerError(this.code, 503, false);
  }
}
