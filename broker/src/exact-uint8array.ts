import { BrokerError } from "./errors";

export interface ExactUint8ArrayBoundary {
  readonly code: string;
  readonly invalidStatus: number;
  readonly maximum: number;
  readonly minimum: number;
  readonly sizeStatus: number;
}

type BoundaryFailureKind = "INVALID" | "SIZE";

class ExactUint8ArrayFailure extends Error {
  public constructor(public readonly kind: BoundaryFailureKind) {
    super(kind);
  }
}

const TYPED_ARRAY_PROTOTYPE = Reflect.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GETTER = getter(TYPED_ARRAY_PROTOTYPE, "buffer");
const TYPED_ARRAY_BYTE_LENGTH_GETTER = getter(TYPED_ARRAY_PROTOTYPE, "byteLength");
const TYPED_ARRAY_BYTE_OFFSET_GETTER = getter(TYPED_ARRAY_PROTOTYPE, "byteOffset");
const TYPED_ARRAY_NAME_GETTER = getter(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag);
const ARRAY_BUFFER_BYTE_LENGTH_GETTER = getter(ArrayBuffer.prototype, "byteLength");
const ARRAY_BUFFER_DETACHED_GETTER = optionalGetter(ArrayBuffer.prototype, "detached");
const ARRAY_BUFFER_RESIZABLE_GETTER = optionalGetter(ArrayBuffer.prototype, "resizable");
// eslint-disable-next-line @typescript-eslint/unbound-method -- invoked with an explicit native receiver.
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

/**
 * Validate and own one exact native Uint8Array without consulting caller accessors or iterators.
 * The returned view always spans a new, fixed, plain ArrayBuffer.
 * `boundary` is trusted static policy, snapshotted once before the untrusted input is inspected.
 */
export function ownExactUint8Array(
  input: unknown,
  boundary: ExactUint8ArrayBoundary,
): Uint8Array<ArrayBuffer> {
  const policy = snapshotBoundary(boundary);
  try {
    if (
      !ArrayBuffer.isView(input) ||
      Reflect.getPrototypeOf(input) !== Uint8Array.prototype ||
      Reflect.apply(TYPED_ARRAY_NAME_GETTER, input, []) !== "Uint8Array"
    ) {
      invalid();
    }
    const byteLength = nativeInteger(TYPED_ARRAY_BYTE_LENGTH_GETTER, input);
    const byteOffset = nativeInteger(TYPED_ARRAY_BYTE_OFFSET_GETTER, input);
    const buffer = Reflect.apply(TYPED_ARRAY_BUFFER_GETTER, input, []);
    if (
      buffer === null ||
      typeof buffer !== "object" ||
      Reflect.getPrototypeOf(buffer) !== ArrayBuffer.prototype
    ) {
      invalid();
    }
    const bufferByteLength = nativeInteger(ARRAY_BUFFER_BYTE_LENGTH_GETTER, buffer);
    if (
      nativeBoolean(ARRAY_BUFFER_DETACHED_GETTER, buffer, false) ||
      nativeBoolean(ARRAY_BUFFER_RESIZABLE_GETTER, buffer, false)
    ) {
      invalid();
    }
    if (
      byteLength < policy.minimum ||
      byteLength > policy.maximum ||
      byteOffset < 0 ||
      byteOffset + byteLength > bufferByteLength
    ) {
      size();
    }
    const owned = new Uint8Array(byteLength);
    Reflect.apply(UINT8_ARRAY_SET, owned, [input]);
    return owned;
  } catch (error) {
    const status =
      error instanceof ExactUint8ArrayFailure && error.kind === "SIZE"
        ? policy.sizeStatus
        : policy.invalidStatus;
    throw new BrokerError(policy.code, status, false);
  }
}

function nativeInteger(nativeGetter: (this: unknown) => unknown, receiver: object): number {
  const value = Reflect.apply(nativeGetter, receiver, []);
  if (!Number.isSafeInteger(value)) invalid();
  return Number(value);
}

function nativeBoolean(
  nativeGetter: ((this: unknown) => unknown) | undefined,
  receiver: object,
  fallback: boolean,
): boolean {
  if (nativeGetter === undefined) return fallback;
  const value = Reflect.apply(nativeGetter, receiver, []);
  if (typeof value !== "boolean") invalid();
  return value;
}

function getter(prototype: object | null, key: PropertyKey): (this: unknown) => unknown {
  const value = optionalGetter(prototype, key);
  if (value === undefined) {
    throw new BrokerError("EXACT_UINT8ARRAY_INTRINSIC_MISSING", 500, false);
  }
  return value;
}

function optionalGetter(
  prototype: object | null,
  key: PropertyKey,
): ((this: unknown) => unknown) | undefined {
  if (prototype === null) return undefined;
  return Reflect.getOwnPropertyDescriptor(prototype, key)?.get;
}

function snapshotBoundary(boundary: ExactUint8ArrayBoundary): ExactUint8ArrayBoundary {
  const snapshot = Object.freeze({
    code: boundary.code,
    invalidStatus: boundary.invalidStatus,
    maximum: boundary.maximum,
    minimum: boundary.minimum,
    sizeStatus: boundary.sizeStatus,
  });
  if (
    snapshot.code.length < 1 ||
    !Number.isSafeInteger(snapshot.minimum) ||
    !Number.isSafeInteger(snapshot.maximum) ||
    snapshot.minimum < 1 ||
    snapshot.maximum < snapshot.minimum ||
    !validStatus(snapshot.invalidStatus) ||
    !validStatus(snapshot.sizeStatus)
  ) {
    throw new BrokerError("EXACT_UINT8ARRAY_BOUNDARY_INVALID", 500, false);
  }
  return snapshot;
}

function validStatus(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 400 && value <= 599;
}

function invalid(): never {
  throw new ExactUint8ArrayFailure("INVALID");
}

function size(): never {
  throw new ExactUint8ArrayFailure("SIZE");
}
