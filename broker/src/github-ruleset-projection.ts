import { canonicalJson, digestObject } from "./canonical";
import { BrokerError } from "./errors";
import type { JsonObject, JsonValue } from "./types";

export const GITHUB_RULESET_PROJECTION_SCHEMA = "dpone.github-ruleset-projection.v1";
export const GITHUB_RULESET_PROJECTION_SCHEMA_VERSION = 1;

const TOP_LEVEL_KEYS = Object.freeze([
  "_links",
  "bypass_actors",
  "conditions",
  "created_at",
  "enforcement",
  "id",
  "name",
  "node_id",
  "rules",
  "source",
  "source_type",
  "target",
  "updated_at",
]);
const PULL_REQUEST_KEYS = Object.freeze([
  "allowed_merge_methods",
  "dismiss_stale_reviews_on_push",
  "require_code_owner_review",
  "require_last_push_approval",
  "required_approving_review_count",
  "required_review_thread_resolution",
  "required_reviewers",
]);
const STATUS_CHECK_KEYS = Object.freeze([
  "do_not_enforce_on_create",
  "required_status_checks",
  "strict_required_status_checks_policy",
]);
const RULE_TYPES = Object.freeze([
  "deletion",
  "non_fast_forward",
  "pull_request",
  "required_status_checks",
]);

/**
 * Normalize one complete GitHub GET-ruleset response into the shared v1
 * semantic contract. Every provider field that carries enforcement meaning is
 * closed and normalized; provider noise is validated but deliberately omitted.
 */
export function projectGitHubRuleset(
  payload: unknown,
  input: {
    readonly repository: string;
    readonly repositoryId: number;
    readonly rulesetId?: number;
  },
): JsonObject {
  const value = record(payload);
  exactKeys(value, TOP_LEVEL_KEYS);
  record(value._links);
  nonemptyString(value.created_at);
  nonemptyString(value.node_id);
  nonemptyString(value.updated_at);
  const rulesetId = positiveInteger(value.id);
  if (input.rulesetId !== undefined && rulesetId !== positiveInteger(input.rulesetId)) invalid();
  if (nonemptyString(value.target) !== "branch") invalid();

  return {
    bypass_actors: projectBypassActors(value.bypass_actors),
    conditions: projectConditions(value.conditions),
    enforcement: nonemptyString(value.enforcement),
    id: rulesetId,
    name: nonemptyString(value.name),
    repository: repository(input.repository),
    repository_id: positiveInteger(input.repositoryId),
    rules: projectRules(value.rules),
    schema: GITHUB_RULESET_PROJECTION_SCHEMA,
    schema_version: GITHUB_RULESET_PROJECTION_SCHEMA_VERSION,
    source: nonemptyString(value.source),
    source_type: nonemptyString(value.source_type),
    target: "branch",
  };
}

/** Canonical tagged digest shared byte-for-byte with the target Python contract. */
export async function githubRulesetProjectionDigest(projection: JsonObject): Promise<string> {
  return digestObject(projection);
}

/** Validate an A0 projection without accepting a caller-defined normalization. */
export function validateGitHubRulesetProjection(
  payload: unknown,
  input: {
    readonly repository: string;
    readonly repositoryId: number;
    readonly rulesetId: number;
  },
): JsonObject {
  const value = record(payload);
  exactKeys(value, [
    "bypass_actors",
    "conditions",
    "enforcement",
    "id",
    "name",
    "repository",
    "repository_id",
    "rules",
    "schema",
    "schema_version",
    "source",
    "source_type",
    "target",
  ]);
  const conditions = record(value.conditions);
  exactKeys(conditions, ["exclude", "include"]);
  const normalized: JsonObject = {
    bypass_actors: projectBypassActors(value.bypass_actors),
    conditions: {
      exclude: sortedStringSet(conditions.exclude),
      include: sortedStringSet(conditions.include),
    },
    enforcement: nonemptyString(value.enforcement),
    id: positiveInteger(value.id),
    name: nonemptyString(value.name),
    repository: repository(nonemptyString(value.repository)),
    repository_id: positiveInteger(value.repository_id),
    rules: projectRules(value.rules),
    schema: nonemptyString(value.schema),
    schema_version: positiveInteger(value.schema_version),
    source: nonemptyString(value.source),
    source_type: nonemptyString(value.source_type),
    target: nonemptyString(value.target),
  };
  if (
    normalized.schema !== GITHUB_RULESET_PROJECTION_SCHEMA ||
    normalized.schema_version !== GITHUB_RULESET_PROJECTION_SCHEMA_VERSION ||
    normalized.repository !== input.repository ||
    normalized.repository_id !== input.repositoryId ||
    normalized.id !== input.rulesetId ||
    normalized.target !== "branch" ||
    canonicalJson(normalized) !== canonicalJson(value)
  ) {
    invalid();
  }
  return normalized;
}

function projectConditions(value: JsonValue | undefined): JsonObject {
  const conditions = record(value);
  exactKeys(conditions, ["ref_name"]);
  const refName = record(conditions.ref_name);
  exactKeys(refName, ["exclude", "include"]);
  return {
    exclude: sortedStringSet(refName.exclude),
    include: sortedStringSet(refName.include),
  };
}

function projectBypassActors(value: JsonValue | undefined): JsonObject[] {
  const source = array(value);
  const seen = new Set<string>();
  const actors = source.map((item) => {
    const actor = record(item);
    exactKeys(actor, ["actor_id", "actor_type", "bypass_mode"]);
    const actorId = actor.actor_id === null ? null : positiveInteger(actor.actor_id);
    const projected = {
      actor_id: actorId,
      actor_type: nonemptyString(actor.actor_type),
      bypass_mode: nonemptyString(actor.bypass_mode),
    };
    const identity = `${actorId ?? "null"}\0${projected.actor_type}\0${projected.bypass_mode}`;
    if (seen.has(identity)) invalid();
    seen.add(identity);
    return projected;
  });
  return actors.sort(compareActor);
}

function projectRules(value: JsonValue | undefined): JsonObject[] {
  const source = array(value);
  const rules = new Map<string, JsonObject>();
  for (const item of source) {
    const rule = record(item);
    const type = nonemptyString(rule.type);
    if (rules.has(type)) invalid();
    if (type === "deletion" || type === "non_fast_forward") {
      exactKeys(rule, ["type"]);
      rules.set(type, { type });
    } else if (type === "pull_request") {
      exactKeys(rule, ["parameters", "type"]);
      rules.set(type, projectPullRequest(rule.parameters));
    } else if (type === "required_status_checks") {
      exactKeys(rule, ["parameters", "type"]);
      rules.set(type, projectStatusChecks(rule.parameters));
    } else {
      invalid();
    }
  }
  if (JSON.stringify([...rules.keys()].sort(compareUtf8)) !== JSON.stringify(RULE_TYPES)) invalid();
  return RULE_TYPES.map((type) => requiredRule(rules, type));
}

function projectPullRequest(value: JsonValue | undefined): JsonObject {
  const parameters = record(value);
  exactKeys(parameters, PULL_REQUEST_KEYS);
  const reviewers = array(parameters.required_reviewers);
  if (reviewers.length !== 0) invalid();
  const count = nonnegativeInteger(parameters.required_approving_review_count);
  if (count > 10) invalid();
  return {
    parameters: {
      allowed_merge_methods: sortedStringSet(parameters.allowed_merge_methods),
      dismiss_stale_reviews_on_push: boolean(parameters.dismiss_stale_reviews_on_push),
      require_code_owner_review: boolean(parameters.require_code_owner_review),
      require_last_push_approval: boolean(parameters.require_last_push_approval),
      required_approving_review_count: count,
      required_review_thread_resolution: boolean(parameters.required_review_thread_resolution),
      required_reviewers: [],
    },
    type: "pull_request",
  };
}

function projectStatusChecks(value: JsonValue | undefined): JsonObject {
  const parameters = record(value);
  exactKeys(parameters, STATUS_CHECK_KEYS);
  if (boolean(parameters.do_not_enforce_on_create)) invalid();
  const source = array(parameters.required_status_checks);
  if (source.length === 0) invalid();
  const seen = new Set<string>();
  const checks = source.map((item) => {
    const check = record(item);
    exactKeys(check, ["context", "integration_id"]);
    const context = nonemptyString(check.context);
    if (seen.has(context)) invalid();
    seen.add(context);
    return {
      context,
      integration_id: check.integration_id === null ? null : positiveInteger(check.integration_id),
    };
  });
  checks.sort((left, right) => compareUtf8(left.context, right.context));
  return {
    parameters: {
      do_not_enforce_on_create: false,
      required_status_checks: checks,
      strict_required_status_checks_policy: boolean(
        parameters.strict_required_status_checks_policy,
      ),
    },
    type: "required_status_checks",
  };
}

function sortedStringSet(value: JsonValue | undefined): string[] {
  const source = array(value);
  const result = source.map(nonemptyString).sort(compareUtf8);
  if (new Set(result).size !== result.length) invalid();
  return result;
}

function compareActor(left: JsonObject, right: JsonObject): number {
  const leftId = left.actor_id as number | null;
  const rightId = right.actor_id as number | null;
  if (leftId === null && rightId !== null) return 1;
  if (leftId !== null && rightId === null) return -1;
  if (leftId !== rightId) return (leftId ?? -1) - (rightId ?? -1);
  const type = compareUtf8(left.actor_type as string, right.actor_type as string);
  return type === 0 ? compareUtf8(left.bypass_mode as string, right.bypass_mode as string) : type;
}

function compareUtf8(left: string, right: string): number {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = byteAt(leftBytes, index) - byteAt(rightBytes, index);
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function exactKeys(value: JsonObject, expected: readonly string[]): void {
  const actual = Object.keys(value).sort(compareUtf8);
  const sortedExpected = [...expected].sort(compareUtf8);
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) invalid();
}

function requiredRule(rules: ReadonlyMap<string, JsonObject>, type: string): JsonObject {
  const rule = rules.get(type);
  if (rule === undefined) invalid();
  return rule;
}

function byteAt(bytes: Uint8Array, index: number): number {
  const byte = bytes[index];
  if (byte === undefined) invalid();
  return byte;
}

function record(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  return value as JsonObject;
}

function array(value: JsonValue | undefined): JsonValue[] {
  if (!Array.isArray(value)) invalid();
  return value;
}

function nonemptyString(value: JsonValue | undefined): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) invalid();
  return value;
}

function boolean(value: JsonValue | undefined): boolean {
  if (typeof value !== "boolean") invalid();
  return value;
}

function positiveInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) invalid();
  return value;
}

function nonnegativeInteger(value: JsonValue | undefined): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}

function repository(value: string): string {
  if (value.split("/").length !== 2 || value.split("/").some((part) => part.length === 0)) {
    invalid();
  }
  return value;
}

function invalid(): never {
  throw new BrokerError("GITHUB_RULESET_PROJECTION_INVALID", 503, false);
}
