import { lookup as dnsLookup } from 'dns/promises';
import { isIP } from 'net';

export interface EndpointSecurityOptions {
  allowLocalDevelopment?: boolean;
  lookup?: (hostname: string) => Promise<Array<{ address: string }>>;
}

export interface TimeoutOptions {
  timeoutMs: number;
  signal?: AbortSignal;
}

const CLOUD_METADATA_IPV4 = new Set([
  '169.254.169.254',
  '169.254.170.2',
  '192.0.0.192',
  '100.100.100.200',
]);

const CLOUD_METADATA_IPV6 = new Set([
  'fd00:ec2::254',
]);

const CLOUD_METADATA_HOSTS = new Set([
  'metadata',
  'metadata.google.internal',
]);

function defaultLookup(hostname: string): Promise<Array<{ address: string }>> {
  return dnsLookup(hostname, { all: true });
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function normalizeHostname(host: string): string {
  return stripIpv6Brackets(host).replace(/\.$/, '').toLowerCase();
}

function parseIpv4(address: string): number[] | undefined {
  const parts = address.split('.');
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map((part) => Number(part));
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
    ? octets
    : undefined;
}

function ipv4FromMappedIpv6(address: string): string | undefined {
  const normalized = stripIpv6Brackets(address).toLowerCase();
  const marker = '::ffff:';
  if (!normalized.startsWith(marker)) {
    return undefined;
  }
  const mapped = normalized.slice(marker.length);
  return parseIpv4(mapped) ? mapped : undefined;
}

function isCloudMetadataAddress(address: string): boolean {
  const normalized = stripIpv6Brackets(address).toLowerCase();
  const mapped = ipv4FromMappedIpv6(normalized);
  return CLOUD_METADATA_IPV4.has(mapped ?? normalized) || CLOUD_METADATA_IPV6.has(normalized);
}

function isPrivateOrLocalAddress(address: string): boolean {
  const mapped = ipv4FromMappedIpv6(address);
  const normalized = stripIpv6Brackets(mapped ?? address).toLowerCase();
  const version = isIP(normalized);
  if (version === 4) {
    const octets = parseIpv4(normalized);
    if (!octets) {
      return true;
    }
    const [a, b] = octets;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  if (version === 6) {
    return (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb')
    );
  }
  return true;
}

function isBlockedHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  return CLOUD_METADATA_HOSTS.has(host) || host === 'localhost' || host.endsWith('.localhost');
}

function endpointError(message: string): Error {
  return new Error(`Unsafe Agent Stream endpoint: ${message}`);
}

export async function validateEndpointBase(
  raw: string,
  options: EndpointSecurityOptions = {},
): Promise<URL> {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw endpointError('URL must not be empty');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (error) {
    throw endpointError(`invalid URL (${error instanceof Error ? error.message : String(error)})`);
  }

  if (!parsed.hostname) {
    throw endpointError('URL must include a host');
  }
  if (parsed.username || parsed.password) {
    throw endpointError('embedded credentials are not allowed');
  }
  if (parsed.protocol !== 'https:' && !(options.allowLocalDevelopment && parsed.protocol === 'http:')) {
    throw endpointError('production endpoints must use HTTPS');
  }

  const host = normalizeHostname(parsed.hostname);
  if (CLOUD_METADATA_HOSTS.has(host)) {
    throw endpointError(`cloud metadata host ${parsed.hostname} is not allowed`);
  }
  if (!options.allowLocalDevelopment && isBlockedHostname(host)) {
    throw endpointError(`local host ${parsed.hostname} is not allowed`);
  }

  const literal = stripIpv6Brackets(parsed.hostname);
  if (isIP(literal)) {
    if (isCloudMetadataAddress(literal)) {
      throw endpointError(`cloud metadata address ${literal} is not allowed`);
    }
    if (!options.allowLocalDevelopment && isPrivateOrLocalAddress(literal)) {
      throw endpointError(`private, loopback, link-local, or unspecified address ${literal} is not allowed`);
    }
    return parsed;
  }

  const lookup = options.lookup ?? defaultLookup;
  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(host);
  } catch (error) {
    throw endpointError(`DNS resolution failed for ${host} (${error instanceof Error ? error.message : String(error)})`);
  }
  if (addresses.length === 0) {
    throw endpointError(`DNS resolution returned no addresses for ${host}`);
  }
  for (const { address } of addresses) {
    if (isCloudMetadataAddress(address)) {
      throw endpointError(`host ${host} resolves to cloud metadata address ${address}`);
    }
    if (!options.allowLocalDevelopment && isPrivateOrLocalAddress(address)) {
      throw endpointError(`host ${host} resolves to private, loopback, link-local, or unspecified address ${address}`);
    }
  }

  return parsed;
}

function repeatedlyDecode(value: string): string {
  let current = value;
  for (let i = 0; i < 4; i += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) {
        return decoded;
      }
      current = decoded;
    } catch {
      return current;
    }
  }
  return current;
}

export function validateEndpointPath(raw: string, settingName: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw endpointError(`${settingName} must not be empty`);
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed) || trimmed.startsWith('//')) {
    throw endpointError(`${settingName} must be a same-endpoint path, not an absolute URL`);
  }
  const decoded = repeatedlyDecode(trimmed);
  if (decoded.includes('\0') || decoded.includes('?') || decoded.includes('#') || decoded.includes('\\')) {
    throw endpointError(`${settingName} must not contain query, fragment, NUL, or backslash characters`);
  }
  const segments = decoded.split('/').filter((segment) => segment.length > 0);
  if (segments.some((segment) => segment === '..' || segment === '.')) {
    throw endpointError(`${settingName} must not contain path traversal segments`);
  }
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function endpointPrefix(base: URL): string {
  return base.pathname.replace(/\/+$/, '');
}

export function assertSameEndpointTarget(expectedBase: URL | string, requestUrl: URL | string): void {
  const expected = typeof expectedBase === 'string' ? new URL(expectedBase) : expectedBase;
  const request = typeof requestUrl === 'string' ? new URL(requestUrl) : requestUrl;
  if (request.origin !== expected.origin) {
    throw endpointError('credentialed requests must stay on the configured endpoint origin');
  }
  const prefix = endpointPrefix(expected);
  if (prefix && request.pathname !== prefix && !request.pathname.startsWith(`${prefix}/`)) {
    throw endpointError('credentialed requests must stay under the configured endpoint prefix');
  }
}

export function resolveEndpointUrl(base: URL | string, path: string, settingName: string): string {
  const parsedBase = typeof base === 'string' ? new URL(base) : new URL(base.toString());
  const safePath = validateEndpointPath(path, settingName);
  const prefix = endpointPrefix(parsedBase);
  parsedBase.pathname = `${prefix}${safePath}`;
  parsedBase.search = '';
  parsedBase.hash = '';
  assertSameEndpointTarget(typeof base === 'string' ? new URL(base) : base, parsedBase);
  return parsedBase.toString();
}

export function createTimeoutSignal(options: TimeoutOptions): AbortSignal {
  const controller = new AbortController();
  let settled = false;
  const finish = () => {
    settled = true;
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', onAbort);
  };
  const timeout = setTimeout(() => {
    if (!settled) {
      controller.abort(new Error(`Request timed out after ${options.timeoutMs}ms`));
    }
  }, options.timeoutMs);
  const onAbort = () => {
    if (!settled) {
      controller.abort(options.signal?.reason);
      finish();
    }
  };
  if (options.signal?.aborted) {
    controller.abort(options.signal.reason);
    finish();
  } else {
    options.signal?.addEventListener('abort', onAbort, { once: true });
    controller.signal.addEventListener('abort', finish, { once: true });
  }
  return controller.signal;
}

export async function secureFetch(
  input: string,
  init: RequestInit,
  timeoutMs: number,
  signal?: AbortSignal,
  securityOptions?: EndpointSecurityOptions,
): Promise<Response> {
  if (securityOptions) {
    await validateEndpointBase(input, securityOptions);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort(new Error(`Request timed out after ${timeoutMs}ms`));
  }, timeoutMs);
  const onAbort = () => controller.abort(signal?.reason);
  try {
    if (signal?.aborted) {
      controller.abort(signal.reason);
    } else {
      signal?.addEventListener('abort', onAbort, { once: true });
    }
    return await fetch(input, {
      ...init,
      redirect: 'manual',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', onAbort);
  }
}
