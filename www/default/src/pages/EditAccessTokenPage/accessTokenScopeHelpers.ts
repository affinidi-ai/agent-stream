import type { RequiredHeader } from '../../types';

export const ACCESS_TOKEN_LIST_ROUTE = '/secrets?tab=access-tokens';

export const ACCESS_TOKEN_RESOURCE_KINDS = [
  ['secrets', 'Secrets'],
  ['certificates', 'Certificates'],
  ['api-keys', 'API keys'],
  ['pipes', 'Surface configurations'],
  ['surfaces', 'Fabric surfaces'],
  ['gateways', 'Gateways'],
  ['connection-points', 'Connection points'],
  ['mediators', 'Mediators'],
  ['integrations', 'Integrations'],
  ['policy-definitions', 'Policy definitions'],
  ['pipe-templates', 'Surface templates'],
  ['credential-providers', 'Credential providers'],
  ['jwt-verification-strategies', 'JWT verification strategies'],
  ['oauth-identifiers', 'OAuth identifiers'],
  ['prompts', 'Prompts'],
  ['members', 'Members'],
  ['teams', 'Teams'],
] as const;

export type AccessTokenResourceKind = (typeof ACCESS_TOKEN_RESOURCE_KINDS)[number][0];

export type TenantInference =
  | { mode: 'appliance' }
  | { mode: 'tenant'; headerName: string }
  | { mode: 'invalid'; headerNames: string[] };

export interface ScopePreview {
  allowed: boolean;
  target: string;
  errors: string[];
}

const PLACEHOLDER_RE = /\$\{([A-Za-z0-9_-]+)\}/g;
const CANONICAL_RE = /^TENANT:\$\{([A-Za-z0-9_-]+)\}:(.+)$/;
const TENANT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const CANONICAL_PATTERN_ERROR = [
  'A non-empty resource pattern must use TENANT:',
  '$',
  '{header}:<resource-kind>:<resource-id-pattern>.',
].join('');

export const cleanRequiredHeaders = (headers: RequiredHeader[]): RequiredHeader[] =>
  headers.map(header => ({ ...header, name: header.name.trim() })).filter(header => header.name);

export const accessTokenFormError = (
  name: string,
  resourcePattern: string,
  headers: RequiredHeader[],
  expiryError?: string,
  unavailableScopes: string[] = []
): string | null => {
  if (!name.trim()) return 'Name is required';
  if (unavailableScopes.length > 0) return 'Remove the red unavailable scopes before saving.';
  const scopeError = validateScopeConfig(resourcePattern, headers)[0];
  if (scopeError) return scopeError;
  if (expiryError) return expiryError;
  return null;
};

export const anchored = (source: string): RegExp | null => {
  try {
    return new RegExp(`^(?:${source})$`, 's');
  } catch {
    return null;
  }
};

export const placeholderNames = (pattern: string): string[] => {
  const names = new Set<string>();
  for (const match of pattern.matchAll(PLACEHOLDER_RE)) names.add(match[1].toLowerCase());
  return [...names];
};

export const inferTenantSelection = (pattern: string): TenantInference => {
  if (!pattern.trim()) return { mode: 'appliance' };
  const matches = [...pattern.matchAll(PLACEHOLDER_RE)];
  const names = placeholderNames(pattern);
  if (matches.length === 1 && names.length === 1) {
    return { mode: 'tenant', headerName: names[0] };
  }
  return { mode: 'invalid', headerNames: names };
};

export const tenantInferenceText = (inference: TenantInference): string => {
  if (inference.mode === 'tenant') return `Tenant selected by ${inference.headerName}`;
  if (inference.mode === 'appliance') return 'Appliance-wide';
  return inference.headerNames.length > 1
    ? 'Multiple tenant headers are not allowed.'
    : 'A non-empty pattern must select one tenant header.';
};

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const splitTopLevelAlternatives = (selector: string): string[] => {
  const alternatives: string[] = [];
  let start = 0;
  let depth = 0;
  let inClass = false;
  let escaped = false;
  for (let index = 0; index < selector.length; index += 1) {
    const character = selector[index];
    if (escaped) {
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (character === '[' && !inClass) {
      inClass = true;
    } else if (character === ']' && inClass) {
      inClass = false;
    } else if (character === '(' && !inClass) {
      depth += 1;
    } else if (character === ')' && !inClass) {
      depth = Math.max(0, depth - 1);
    } else if (character === '|' && !inClass && depth === 0) {
      alternatives.push(selector.slice(start, index));
      start = index + 1;
    }
  }
  alternatives.push(selector.slice(start));
  return alternatives;
};

const unwrapSelector = (selector: string): string =>
  selector.startsWith('(?:') && selector.endsWith(')') ? selector.slice(3, -1) : selector;

export const validateScopeConfig = (pattern: string, headers: RequiredHeader[]): string[] => {
  const errors: string[] = [];
  const declared = new Set<string>();

  if (headers.length > 8) errors.push('A token can require at most 8 headers.');
  headers.forEach((header, index) => {
    const name = header.name.trim();
    const normalized = name.toLowerCase();
    if (!name || name.length > 64 || !/^[A-Za-z0-9-]+$/.test(name)) {
      errors.push(`Header ${index + 1} has an invalid name.`);
    } else if (declared.has(normalized)) {
      errors.push(`Required header '${name}' is duplicated.`);
    } else {
      declared.add(normalized);
    }
    if (!header.pattern || header.pattern.length > 256 || !anchored(header.pattern)) {
      errors.push(`Required header '${name || index + 1}' has an invalid pattern.`);
    }
  });

  const trimmed = pattern.trim();
  if (!trimmed) return errors;
  if (trimmed.length > 512) errors.push('Resource pattern must be 512 characters or fewer.');

  const placeholderOccurrences = [...trimmed.matchAll(PLACEHOLDER_RE)];
  const placeholders = placeholderNames(trimmed);
  const undeclared = placeholders.filter(name => !declared.has(name));
  if (undeclared.length > 0) {
    errors.push(`Resource pattern references undeclared header(s): ${undeclared.join(', ')}.`);
  }
  if (placeholderOccurrences.length > 1) {
    errors.push('Resource pattern may contain only one tenant-header placeholder.');
  }
  if (!anchored(trimmed.replace(PLACEHOLDER_RE, 'x'))) {
    errors.push('Resource pattern is not a valid regular expression.');
  }

  const canonical = CANONICAL_RE.exec(trimmed);
  if (!canonical) {
    errors.push(CANONICAL_PATTERN_ERROR);
    return errors;
  }
  const branches = splitTopLevelAlternatives(unwrapSelector(canonical[2]));
  if (
    branches.some(branch => {
      const separator = branch.indexOf(':');
      const kind = branch.slice(0, separator);
      return (
        separator <= 0 || !ACCESS_TOKEN_RESOURCE_KINDS.some(([candidate]) => candidate === kind)
      );
    })
  ) {
    errors.push("Every resource selector must start with a known resource kind followed by ':'.");
  }
  return errors;
};

export const evaluateScopePreview = (
  pattern: string,
  headers: RequiredHeader[],
  sampleHeaders: Record<string, string>,
  resourceKind: AccessTokenResourceKind,
  resourceId: string
): ScopePreview => {
  const errors: string[] = [];
  const values: Record<string, string> = {};
  for (const header of headers) {
    const name = header.name.trim().toLowerCase();
    const value = sampleHeaders[name] ?? '';
    const validator = anchored(header.pattern);
    if (!name || !validator || !validator.test(value))
      errors.push(`Invalid value for ${header.name || 'header'}.`);
    values[name] = value;
  }
  const placeholder = [...pattern.matchAll(PLACEHOLDER_RE)][0]?.[1]?.toLowerCase();
  const tenantId = placeholder ? values[placeholder] : undefined;
  if (tenantId && !TENANT_ID_RE.test(tenantId)) errors.push('Invalid tenant ID.');
  const target = tenantId ? `TENANT:${tenantId}:${resourceKind}:${resourceId}` : resourceId;
  const effective = pattern.replace(PLACEHOLDER_RE, (_whole, name: string) =>
    escapeRegExp(values[name.toLowerCase()] ?? '')
  );
  const matcher = effective ? anchored(effective) : null;
  return { allowed: errors.length === 0 && Boolean(matcher?.test(target)), target, errors };
};
