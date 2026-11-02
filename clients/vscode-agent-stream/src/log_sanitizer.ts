const CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
const CRLF = /[\r\n]/g;
const BEARER_TOKEN = /\bBearer\s+([A-Za-z0-9._~+\/-]+=*)/gi;
const BASIC_TOKEN = /\bBasic\s+([A-Za-z0-9._~+\/-]+=*)/gi;
const AUTH_HEADER = /\b(Authorization|Proxy-Authorization|X-Agent-Stream-Upstream-Authorization)\s*[:=]\s*(?:(Bearer|Basic)\s+)?([^,;\s]+)/gi;
const SECRET_HEADER = /\b(X-Api-Key|Api-Key|ApiKey|Ocp-Apim-Subscription-Key|Cookie|Set-Cookie)\s*[:=]\s*([^\r\n]+)/gi;
const JWT = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const SENSITIVE_QUERY_KEYS = /^(access_token|api[-_]?key|apikey|authorization|client_secret|code|id_token|password|refresh_token|secret|token|x-api-key)$/i;
const SENSITIVE_FIELD = /(?<![?&A-Za-z0-9_-])(["']?)(access_token|api[-_]?key|apikey|authorization|client_secret|id_token|password|refresh_token|secret|token|x-api-key)(\1)\s*[:=]\s*("[^"]*"|'[^']*'|[^,;&\s}]+)/gi;

function redactSensitiveUrl(raw: string): string {
  try {
    const parsed = new URL(raw);
    if (parsed.username || parsed.password) {
      parsed.username = parsed.username ? '[redacted]' : '';
      parsed.password = parsed.password ? '[redacted]' : '';
    }
    for (const key of Array.from(parsed.searchParams.keys())) {
      if (SENSITIVE_QUERY_KEYS.test(key)) {
        parsed.searchParams.set(key, '[redacted]');
      }
    }
    return parsed.toString();
  } catch {
    return raw;
  }
}

export function sanitizeLogMessage(message: string): string {
  return message
    .replace(BEARER_TOKEN, 'Bearer [redacted]')
    .replace(BASIC_TOKEN, 'Basic [redacted]')
    .replace(AUTH_HEADER, '$1: [redacted]')
    .replace(SECRET_HEADER, '$1: [redacted]')
    .replace(JWT, '[redacted-jwt]')
    .replace(/https?:\/\/[^\s)]+/gi, redactSensitiveUrl)
    .replace(SENSITIVE_FIELD, (_match, keyOpen: string, key: string, keyClose: string, value: string) => {
      const quote = value.startsWith('"') ? '"' : value.startsWith("'") ? "'" : '';
      return `${keyOpen}${key}${keyClose}: ${quote}[redacted]${quote}`;
    })
    .replace(CRLF, (ch) => (ch === '\r' ? '\\r' : '\\n'))
    .replace(CONTROL_CHARACTERS, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
