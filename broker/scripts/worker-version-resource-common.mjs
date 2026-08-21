export function compareProjected(left, right) {
  const leftName = typeof left === "string" ? left : left.name;
  const rightName = typeof right === "string" ? right : right.name;
  return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
}

export function compareNamed(left, right) {
  return left.name < right.name ? -1 : left.name > right.name ? 1 : 0;
}

export function exactKeys(value, expected, name) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${name} keys mismatch`);
  }
}

export function allowedKeys(value, allowed, required, name) {
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) {
    throw new Error(`${name} keys mismatch`);
  }
}

export function record(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}
