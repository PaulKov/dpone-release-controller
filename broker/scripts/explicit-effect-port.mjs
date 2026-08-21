/** Require a caller-owned effect port; engines never bind real provider adapters by default. */
export function requireEffectPort(dependencies, name, boundary) {
  const value = dependencies?.[name];
  if (typeof value !== "function") throw new Error(`${boundary} effect port missing: ${name}`);
  return value;
}
