import type { RequiredHeader } from '../../types';
import { toLocalDateTimeInput, type AccessTokenExpiryForm } from './accessTokenExpiry';

export interface AccessTokenPrefill {
  name: string;
  description: string;
  scopes: string[];
  resourcePattern: string;
  requiredHeaders: RequiredHeader[];
  expiry?: AccessTokenExpiryForm;
}

const DAY_MS = 24 * 60 * 60 * 1000;

const scopesParam = (params: URLSearchParams): string[] =>
  [...params.getAll('scope'), ...params.getAll('scopes').flatMap(value => value.split(','))]
    .map(value => value.trim())
    .filter(Boolean);

const headerParam = (value: string): RequiredHeader | null => {
  const separator = value.indexOf(':');
  if (separator <= 0) return null;
  const name = value.slice(0, separator).trim();
  return name ? { name, pattern: value.slice(separator + 1) } : null;
};

const expiryParam = (params: URLSearchParams, now: Date): AccessTokenExpiryForm | undefined => {
  const at = params.get('expires_at');
  const days = params.get('expires_in_days');
  const expiry = at
    ? new Date(at)
    : days && /^\d+$/.test(days)
      ? new Date(now.getTime() + Number(days) * DAY_MS)
      : null;
  if (!expiry || Number.isNaN(expiry.getTime())) return undefined;
  return { neverExpires: false, expiresAt: toLocalDateTimeInput(expiry) };
};

/**
 * Query string that reproduces the current create form through
 * `accessTokenPrefill`. Empty fields are omitted; a set expiry is written as an
 * exact `expires_at`.
 */
export const accessTokenPermalinkQuery = (values: AccessTokenPrefill): string => {
  const params = new URLSearchParams();
  const name = values.name.trim();
  const description = values.description.trim();
  const pattern = values.resourcePattern.trim();
  if (name) params.set('name', name);
  if (description) params.set('description', description);
  if (values.scopes.length > 0) params.set('scopes', values.scopes.join(','));
  if (pattern) params.set('resource_pattern', pattern);
  for (const header of values.requiredHeaders) {
    const headerName = header.name.trim();
    if (headerName) params.append('header', `${headerName}:${header.pattern}`);
  }
  if (values.expiry && !values.expiry.neverExpires) {
    const expiry = new Date(values.expiry.expiresAt);
    if (!Number.isNaN(expiry.getTime())) params.set('expires_at', expiry.toISOString());
  }
  return params.toString();
};

/**
 * Initial create-form values from `/access-tokens/new?…` so an external link can
 * preset the form. Only fills fields; the operator still reviews and submits.
 * Every preset scope is kept, so one the operator cannot grant shows as unavailable.
 */
export const accessTokenPrefill = (
  params: URLSearchParams,
  now = new Date()
): AccessTokenPrefill => ({
  name: params.get('name') ?? '',
  description: params.get('description') ?? '',
  scopes: [...new Set(scopesParam(params))].sort(),
  resourcePattern: params.get('resource_pattern') ?? '',
  requiredHeaders: params
    .getAll('header')
    .map(headerParam)
    .filter((header): header is RequiredHeader => header !== null),
  expiry: expiryParam(params, now),
});
