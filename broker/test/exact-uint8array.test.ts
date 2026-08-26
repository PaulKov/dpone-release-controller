import { describe, expect, it } from "vitest";

import { BrokerError } from "../src/errors";
import { ownExactUint8Array, type ExactUint8ArrayBoundary } from "../src/exact-uint8array";

const BOUNDARY: ExactUint8ArrayBoundary = Object.freeze({
  code: "TEST_EXACT_UINT8ARRAY_INVALID",
  invalidStatus: 409,
  maximum: 65_536,
  minimum: 1,
  sizeStatus: 413,
});

describe("exact Uint8Array ownership boundary", () => {
  it("returns a fixed plain ArrayBuffer-backed copy of the exact selected view", () => {
    const backing = new ArrayBuffer(8);
    const source = new Uint8Array(backing, 2, 3);
    source.set([11, 22, 33]);

    const owned = ownExactUint8Array(source, BOUNDARY);
    source.fill(0);

    expect(owned).toEqual(new Uint8Array([11, 22, 33]));
    expect(owned).not.toBe(source);
    expect(Object.getPrototypeOf(owned)).toBe(Uint8Array.prototype);
    expect(Object.getPrototypeOf(owned.buffer)).toBe(ArrayBuffer.prototype);
    expect(owned.byteOffset).toBe(0);
    expect(owned.buffer.byteLength).toBe(owned.byteLength);
    expect(owned.buffer.resizable).toBe(false);
  });

  it("uses intrinsic size before allocation and never invokes shadow accessors or iterators", () => {
    let invoked = 0;
    const oversized = new Uint8Array(65_537);
    Object.defineProperty(oversized, "byteLength", { value: 1 });
    Object.defineProperty(oversized, Symbol.iterator, {
      get() {
        invoked += 1;
        throw new Error("iterator getter must not execute");
      },
    });

    expect(() => ownExactUint8Array(oversized, BOUNDARY)).toThrowError(
      expect.objectContaining({
        code: "TEST_EXACT_UINT8ARRAY_INVALID",
        retryable: false,
        status: 413,
      }),
    );
    expect(invoked).toBe(0);
  });

  it("ignores every own decoration without evaluating or retaining its value", () => {
    let invoked = 0;
    const decorated = [
      [
        define(new Uint8Array([1]), "byteLength", {
          get() {
            invoked += 1;
            throw new Error("byteLength getter must not execute");
          },
        }),
        "byteLength",
      ],
      [
        define(new Uint8Array([1]), Symbol.iterator, {
          get() {
            invoked += 1;
            throw new Error("iterator getter must not execute");
          },
        }),
        Symbol.iterator,
      ],
      [
        define(new Uint8Array([1]), Symbol.toStringTag, {
          get() {
            invoked += 1;
            throw new Error("toStringTag getter must not execute");
          },
        }),
        Symbol.toStringTag,
      ],
      [define(new Uint8Array([1]), "hidden", { value: true }), "hidden"],
      [define(new Uint8Array([1]), Symbol.for("hidden"), { value: true }), Symbol.for("hidden")],
    ] as const;

    for (const [candidate, decoration] of decorated) {
      const owned = ownExactUint8Array(candidate, BOUNDARY);
      expect(owned).toEqual(new Uint8Array([1]));
      expect(Reflect.getOwnPropertyDescriptor(owned, decoration)).toBeUndefined();
    }
    expect(invoked).toBe(0);
  });

  it("rejects malformed trusted boundary policy with a fixed infrastructure error", () => {
    expect(() =>
      ownExactUint8Array(new Uint8Array([1]), {
        ...BOUNDARY,
        maximum: 0,
      }),
    ).toThrowError(
      expect.objectContaining({ code: "EXACT_UINT8ARRAY_BOUNDARY_INVALID", status: 500 }),
    );
  });

  it("normalizes Proxy and subclass failures without invoking ordinary property reads", () => {
    let propertyReads = 0;
    let prototypeReads = 0;
    const proxy = new Proxy(new Uint8Array([1]), {
      get() {
        propertyReads += 1;
        throw new Error("ordinary get must not execute");
      },
      getPrototypeOf() {
        prototypeReads += 1;
        throw new Error("getPrototypeOf must not execute");
      },
    });
    class Uint8ArraySubclass extends Uint8Array {}

    for (const candidate of [proxy, new Uint8ArraySubclass([1])]) {
      expect(() => ownExactUint8Array(candidate, BOUNDARY)).toThrowError(
        expect.objectContaining({ code: "TEST_EXACT_UINT8ARRAY_INVALID", status: 409 }),
      );
    }
    expect(propertyReads).toBe(0);
    expect(prototypeReads).toBe(0);
  });

  it("rejects non-byte typed arrays even when their mutable prototype is forged", () => {
    const candidates = [
      new Uint16Array([0x1234, 0x5678]),
      new Int16Array([-1234, 5678]),
      new Float32Array([1.25, -3.5]),
    ];

    for (const candidate of candidates) {
      const rawBytes = Uint8Array.from(new Uint8Array(candidate.buffer));
      Object.setPrototypeOf(candidate, Uint8Array.prototype);
      expect(() => ownExactUint8Array(candidate, BOUNDARY)).toThrowError(
        expect.objectContaining({ code: BOUNDARY.code, status: BOUNDARY.invalidStatus }),
      );
      expect(new Uint8Array(candidate.buffer)).toEqual(rawBytes);
    }
  });

  it("rejects SharedArrayBuffer, resizable ArrayBuffer, and detached backing stores", () => {
    if (typeof SharedArrayBuffer === "function") {
      expect(() => ownExactUint8Array(new Uint8Array(new SharedArrayBuffer(4)), BOUNDARY)).toThrow(
        BrokerError,
      );
    }
    if (typeof ArrayBuffer.prototype.resize === "function") {
      const resizable = new ArrayBuffer(4, { maxByteLength: 8 });
      expect(() => ownExactUint8Array(new Uint8Array(resizable), BOUNDARY)).toThrow(BrokerError);
    }
    const detached = new ArrayBuffer(4);
    const detachedView = new Uint8Array(detached);
    structuredClone(detached, { transfer: [detached] });
    expect(() => ownExactUint8Array(detachedView, BOUNDARY)).toThrowError(
      expect.objectContaining({ code: "TEST_EXACT_UINT8ARRAY_INVALID", status: 409 }),
    );
  });

  it("preserves caller-selected invalid and size error contracts", () => {
    expect(() => ownExactUint8Array("not bytes", BOUNDARY)).toThrowError(
      expect.objectContaining({ code: BOUNDARY.code, status: BOUNDARY.invalidStatus }),
    );
    expect(() => ownExactUint8Array(new Uint8Array(), BOUNDARY)).toThrowError(
      expect.objectContaining({ code: BOUNDARY.code, status: BOUNDARY.sizeStatus }),
    );
  });
});

function define(input: Uint8Array, key: PropertyKey, descriptor: PropertyDescriptor): Uint8Array {
  Object.defineProperty(input, key, descriptor);
  return input;
}
