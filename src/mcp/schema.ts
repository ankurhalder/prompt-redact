import type { InputSchema, JsonObject, JsonSchema } from "./protocol.js";
import { isJsonObject } from "./protocol.js";

export function validateArguments(schema: InputSchema, value: unknown): string[] {
  if (value === undefined) value = {};
  if (!isJsonObject(value)) return ["arguments must be a JSON object"];

  const problems: string[] = [];
  const known = new Set(Object.keys(schema.properties));

  for (const key of Object.keys(value)) {
    if (!known.has(key) && schema.additionalProperties !== true) {
      const allowed = [...known].sort().join(", ");
      problems.push(`unknown argument "${key}" (accepted: ${allowed || "none"})`);
    }
  }

  for (const required of schema.required ?? []) {
    if (value[required] === undefined) problems.push(`missing required argument "${required}"`);
  }

  for (const [key, propertySchema] of Object.entries(schema.properties)) {
    const argument = value[key];
    if (argument === undefined) continue;
    problems.push(...checkValue(key, propertySchema, argument));
  }

  return problems;
}

function checkValue(path: string, schema: JsonSchema, value: unknown): string[] {
  if (schema.enum && !schema.enum.includes(value as string)) {
    return [`"${path}" must be one of: ${schema.enum.join(", ")}`];
  }

  const declared: readonly string[] =
    schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type];
  if (declared.length > 0 && !declared.some((type) => matchesType(type, value))) {
    if (declared.length === 1 && declared[0] === "integer" && typeof value !== "number") {
      return [`"${path}" must be a number`];
    }
    const article = (type: string): string =>
      type === "integer" || type === "object" || type === "array" ? `an ${type}` : `a ${type}`;
    return [`"${path}" must be ${declared.map(article).join(" or ")}`];
  }

  const problems: string[] = [];
  if (declared.includes("string") && typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      problems.push(`"${path}" must be at least ${schema.minLength} character(s)`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      problems.push(`"${path}" must be at most ${schema.maxLength} character(s)`);
    }
  }
  if (
    (declared.includes("number") || declared.includes("integer")) &&
    typeof value === "number" &&
    !Number.isNaN(value)
  ) {
    if (declared.includes("integer") && !declared.includes("number") && !Number.isInteger(value)) {
      problems.push(`"${path}" must be an integer`);
    }
    if (schema.minimum !== undefined && value < schema.minimum) {
      problems.push(`"${path}" must be >= ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      problems.push(`"${path}" must be <= ${schema.maximum}`);
    }
  }
  if (declared.includes("array") && Array.isArray(value) && schema.items) {
    value.forEach((item, index) => {
      problems.push(...checkValue(`${path}[${index}]`, schema.items as JsonSchema, item));
    });
  }
  return problems;
}

function matchesType(type: string, value: unknown): boolean {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number" && !Number.isNaN(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "array":
      return Array.isArray(value);
    case "object":
      return isJsonObject(value);
    default:
      return false;
  }
}

export function applyDefaults(schema: InputSchema, value: JsonObject): JsonObject {
  const out: JsonObject = { ...value };
  for (const [key, propertySchema] of Object.entries(schema.properties)) {
    if (out[key] === undefined && propertySchema.default !== undefined) {
      out[key] = propertySchema.default;
    }
  }
  return out;
}

export function coerceNumericStrings(schema: InputSchema, value: JsonObject): JsonObject {
  const out: JsonObject = { ...value };
  for (const [key, propertySchema] of Object.entries(schema.properties)) {
    const raw = out[key];
    if (typeof raw !== "string") continue;
    const declared = Array.isArray(propertySchema.type)
      ? propertySchema.type
      : propertySchema.type === undefined
        ? []
        : [propertySchema.type];
    if (!declared.includes("number") && !declared.includes("integer")) continue;
    if (raw.trim().length === 0) continue;
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) out[key] = parsed;
  }
  return out;
}
