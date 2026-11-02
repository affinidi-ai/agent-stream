export const SECRET_ID_SUFFIX = '_secret_id';
export const HEADERS_SECRET_ID = 'headers_secret_id';

export const PINNED_DESTINATION = 'pinned_destination';
export const SIGNING_SECRET_MIN_LENGTH = 32;

const URL_CREDENTIAL_KEYS = ['url', 'webhook_url', 'redis_url'];

export type HeaderSecretRefs = Record<string, string>;

export interface PinnedDestination {
  host: string;
  secretId: string;
}

export type PinnedDestinations = Readonly<Record<string, PinnedDestination>>;

export const NO_SECRET_REFERENCES: ReadonlySet<string> = new Set();
export const NO_PINNED_DESTINATIONS: PinnedDestinations = {};

const isBlank = (value: unknown): boolean =>
  value === undefined || value === null || (typeof value === 'string' && value.trim() === '');

const withoutHeaders = (
  headers: unknown,
  names: string[]
): Record<string, string | null> | undefined => {
  if (!headers || typeof headers !== 'object') return undefined;
  const lowered = names.map(name => name.toLowerCase());
  const kept = Object.entries(headers as Record<string, string | null>).filter(
    ([name]) => !lowered.includes(name.toLowerCase())
  );
  return kept.length > 0 ? Object.fromEntries(kept) : undefined;
};

const parseConfiguration = (configuration: unknown): Record<string, unknown> => {
  let parsed: unknown = configuration;
  if (typeof configuration === 'string') {
    try {
      parsed = JSON.parse(configuration);
    } catch {
      return {};
    }
  }
  return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
};

export const signingSecretTooShort = (value: string | undefined): boolean =>
  !!value && value.length < SIGNING_SECRET_MIN_LENGTH;

/**
 * The configuration an integration save or test sends: a chosen `<key>_secret_id` replaces the
 * inline `<key>`, blank references are dropped, a blank signing secret is left out so the saved
 * one is kept, and the server-recorded `pinned_destination` is never sent back.
 */
export function credentialPayload(configuration: object): Record<string, unknown> {
  const payload: Record<string, unknown> = { ...configuration };
  delete payload[PINNED_DESTINATION];

  Object.keys(payload).forEach(key => {
    if (key === HEADERS_SECRET_ID || !key.endsWith(SECRET_ID_SUFFIX)) return;
    if (isBlank(payload[key])) {
      delete payload[key];
    } else {
      delete payload[key.slice(0, -SECRET_ID_SUFFIX.length)];
    }
  });

  const headerRefs = Object.entries((payload[HEADERS_SECRET_ID] ?? {}) as HeaderSecretRefs)
    .map(([name, secretId]): [string, string] => [name.trim(), secretId])
    .filter(([name, secretId]) => name !== '' && !isBlank(secretId));
  delete payload[HEADERS_SECRET_ID];
  if (headerRefs.length > 0) {
    payload[HEADERS_SECRET_ID] = Object.fromEntries(headerRefs);
    const headers = withoutHeaders(
      payload.headers,
      headerRefs.map(([name]) => name)
    );
    if (headers) payload.headers = headers;
    else delete payload.headers;
  }

  if (payload.signing_secret === '') delete payload.signing_secret;

  return payload;
}

/**
 * The `<key>_secret_id` credentials a saved configuration holds. The server does not keep a
 * reference that a save leaves out, so a blank field loaded as one cannot keep the saved value.
 */
export function loadedSecretReferences(configuration: unknown): ReadonlySet<string> {
  return new Set(
    Object.entries(parseConfiguration(configuration))
      .filter(
        ([key, value]) =>
          key !== HEADERS_SECRET_ID && key.endsWith(SECRET_ID_SUFFIX) && !isBlank(value)
      )
      .map(([key]) => key)
  );
}

/**
 * The host each URL secret was checked against when the integration was saved, keyed by the URL
 * key (`url`, `webhook_url`, `redis_url`), with the reference it was pinned for.
 */
export function pinnedDestinations(configuration: unknown): PinnedDestinations {
  const parsed = parseConfiguration(configuration);
  const pinned = parsed[PINNED_DESTINATION];
  if (!pinned || typeof pinned !== 'object') return NO_PINNED_DESTINATIONS;
  const entries = URL_CREDENTIAL_KEYS.flatMap((key): [string, PinnedDestination][] => {
    const host = (pinned as Record<string, unknown>)[key];
    if (typeof host !== 'string' || host === '') return [];
    const secretId = parsed[`${key}${SECRET_ID_SUFFIX}`];
    return [[key, { host, secretId: typeof secretId === 'string' ? secretId : '' }]];
  });
  return Object.fromEntries(entries);
}
