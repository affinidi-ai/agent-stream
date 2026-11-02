/**
 * Client-side validation for the custom LLM provider catalog, mirroring the
 * authoritative backend checks (JSON schema + no built-in `enum_value`
 * collision + no duplicates) so the JSON editor gives inline feedback before a
 * save round-trip. The backend re-validates on save and is the source of truth.
 *
 * The canonical contract is `config/schemas/llm_catalog.schema.json`;
 * these checks cover the schema's required fields plus the collision rule the
 * schema cannot express.
 */

const ENUM_VALUE_RE = /^[A-Za-z0-9_-]+$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const nonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.trim().length > 0;

/**
 * Validate a parsed custom-catalog document. Returns `null` when valid, or a
 * human-readable error string describing the first problem.
 *
 * @param parsed The `JSON.parse`d editor content.
 * @param builtInEnumValues Lower-cased set of built-in provider ids to reject collisions against.
 */
export function validateCustomCatalog(
  parsed: unknown,
  builtInEnumValues: Set<string>
): string | null {
  if (!isPlainObject(parsed)) {
    return "Configuration must be a JSON object with a 'providers' array.";
  }
  const providers = parsed.providers;
  if (!Array.isArray(providers)) {
    return "Configuration must contain a 'providers' array.";
  }

  const seen = new Set<string>();
  for (let i = 0; i < providers.length; i++) {
    const p = providers[i];
    if (!isPlainObject(p)) {
      return `providers[${i}] must be an object.`;
    }
    if (!nonEmptyString(p.enum_value)) {
      return `providers[${i}] is missing a non-empty "enum_value".`;
    }
    const ev = p.enum_value.trim();
    if (!ENUM_VALUE_RE.test(ev)) {
      return `providers[${i}] enum_value "${ev}" may only contain letters, digits, hyphens and underscores.`;
    }
    if (!nonEmptyString(p.name)) {
      return `Provider "${ev}" is missing a non-empty "name".`;
    }
    const lowered = ev.toLowerCase();
    if (builtInEnumValues.has(lowered)) {
      return `Custom provider "${ev}" reuses a built-in provider id — choose a unique enum_value.`;
    }
    if (seen.has(lowered)) {
      return `Custom provider "${ev}" is defined more than once.`;
    }
    seen.add(lowered);

    if (p.models !== undefined) {
      if (!Array.isArray(p.models)) {
        return `Provider "${ev}" has a "models" field that must be an array.`;
      }
      for (let j = 0; j < p.models.length; j++) {
        const m = p.models[j];
        if (!isPlainObject(m)) {
          return `Provider "${ev}" models[${j}] must be an object.`;
        }
        if (!nonEmptyString(m.name)) {
          return `Provider "${ev}" models[${j}] is missing a "name".`;
        }
        if (!nonEmptyString(m.value)) {
          return `Provider "${ev}" models[${j}] is missing a "value".`;
        }
      }
    }

    if (p.endpoints !== undefined) {
      if (!Array.isArray(p.endpoints)) {
        return `Provider "${ev}" has an "endpoints" field that must be an array.`;
      }
      for (let j = 0; j < p.endpoints.length; j++) {
        const ep = p.endpoints[j];
        if (!isPlainObject(ep)) {
          return `Provider "${ev}" endpoints[${j}] must be an object.`;
        }
        if (!nonEmptyString(ep.name)) {
          return `Provider "${ev}" endpoints[${j}] is missing a "name".`;
        }
        if (!nonEmptyString(ep.path)) {
          return `Provider "${ev}" endpoints[${j}] is missing a "path".`;
        }
      }
    }
  }

  return null;
}
