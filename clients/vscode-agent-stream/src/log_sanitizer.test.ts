import test from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeLogMessage } from './log_sanitizer';

const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature';

test('sanitizeLogMessage redacts bearer tokens and authorization headers', () => {
  const sanitized = sanitizeLogMessage(
    `Authorization: Bearer ${jwt} X-Agent-Stream-Upstream-Authorization=${jwt}`,
  );
  assert.equal(sanitized.includes(jwt), false);
  assert.match(sanitized, /Authorization: \[redacted\]/);
  assert.match(sanitized, /X-Agent-Stream-Upstream-Authorization: \[redacted\]/);
  assert.equal(sanitizeLogMessage('Bearer opaque-secret-token').includes('opaque-secret-token'), false);
});

test('sanitizeLogMessage neutralizes CR, LF, and control characters', () => {
  const sanitized = sanitizeLogMessage('first\r\nFORGED: second\u0000third');
  assert.equal(sanitized.includes('\r'), false);
  assert.equal(sanitized.includes('\n'), false);
  assert.equal(sanitized, 'first\\r\\nFORGED: second\\u0000third');
});

test('sanitizeLogMessage redacts sensitive URL credentials and query parameters', () => {
  const sanitized = sanitizeLogMessage(
    'GET https://user:secret@example.com/path?access_token=abc&id_token=def&client_secret=ghi&api_key=jkl&ok=1',
  );
  assert.equal(sanitized.includes('user:secret'), false);
  assert.equal(sanitized.includes('abc'), false);
  assert.equal(sanitized.includes('def'), false);
  assert.equal(sanitized.includes('ghi'), false);
  assert.equal(sanitized.includes('jkl'), false);
  assert.match(sanitized, /ok=1/);
});

test('sanitizeLogMessage redacts common secret headers and structured fields', () => {
  const sanitized = sanitizeLogMessage(
    'Proxy-Authorization: Basic dXNlcjpwYXNz\n' +
      'X-Api-Key: sk-test-123\n' +
      'Cookie: session=abc; other=def\n' +
      '{"client_secret":"json-secret","password":"pw","token":"opaque"} apiKey=plain-secret',
  );
  assert.equal(sanitized.includes('dXNlcjpwYXNz'), false);
  assert.equal(sanitized.includes('sk-test-123'), false);
  assert.equal(sanitized.includes('session=abc'), false);
  assert.equal(sanitized.includes('json-secret'), false);
  assert.equal(sanitized.includes('plain-secret'), false);
  assert.match(sanitized, /Proxy-Authorization: \[redacted\]/);
  assert.match(sanitized, /X-Api-Key: \[redacted\]/);
  assert.match(sanitized, /"client_secret": "\[redacted\]"/);
});
