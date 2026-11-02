import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assertSameEndpointTarget,
  createTimeoutSignal,
  resolveEndpointUrl,
  secureFetch,
  validateEndpointBase,
  validateEndpointPath,
} from './security';

const publicLookup = async () => [{ address: '203.0.113.10' }];

test('validateEndpointBase accepts public HTTPS endpoints', async () => {
  const url = await validateEndpointBase('https://agent-stream.example.com/ide', { lookup: publicLookup });
  assert.equal(url.origin, 'https://agent-stream.example.com');
});

test('validateEndpointBase rejects workspace-style attacker endpoints before fetch', async () => {
  await assert.rejects(
    validateEndpointBase('http://evil.example.com', { lookup: publicLookup }),
    /HTTPS/,
  );
  await assert.rejects(
    validateEndpointBase('https://user:pass@agent-stream.example.com', { lookup: publicLookup }),
    /embedded credentials/,
  );
});

test('validateEndpointBase rejects local, private, link-local, and metadata hosts', async () => {
  await assert.rejects(validateEndpointBase('https://127.0.0.1'), /not allowed/);
  await assert.rejects(validateEndpointBase('https://10.0.0.7'), /not allowed/);
  await assert.rejects(validateEndpointBase('https://169.254.1.1'), /not allowed/);
  await assert.rejects(validateEndpointBase('https://169.254.169.254'), /metadata/);
  await assert.rejects(validateEndpointBase('https://metadata.google.internal'), /metadata/);
});

test('validateEndpointBase rejects DNS rebinding to private addresses', async () => {
  await assert.rejects(
    validateEndpointBase('https://agent-stream.example.com', {
      lookup: async () => [{ address: '192.168.1.40' }],
    }),
    /resolves to private/,
  );
});

test('validateEndpointBase permits local HTTP only with explicit local-development override', async () => {
  const url = await validateEndpointBase('http://localhost:8080/ide', { allowLocalDevelopment: true });
  assert.equal(url.origin, 'http://localhost:8080');
});

test('validateEndpointPath rejects traversal, encoded traversal, absolute URLs, query, and fragment injection', () => {
  assert.equal(validateEndpointPath('/v1/models', 'models_path'), '/v1/models');
  assert.throws(() => validateEndpointPath('../v1/models', 'models_path'), /traversal/);
  assert.throws(() => validateEndpointPath('/safe/%252e%252e/secret', 'models_path'), /traversal/);
  assert.throws(() => validateEndpointPath('https://evil.example.com/v1/models', 'models_path'), /absolute URL/);
  assert.throws(() => validateEndpointPath('/v1/models?token=1', 'models_path'), /query/);
  assert.throws(() => validateEndpointPath('/v1/models#frag', 'models_path'), /fragment|query/);
});

test('resolveEndpointUrl keeps bootstrap paths under the configured endpoint prefix', () => {
  assert.equal(
    resolveEndpointUrl('https://agent-stream.example.com/ide', '/v1/chat/completions', 'chat_path'),
    'https://agent-stream.example.com/ide/v1/chat/completions',
  );
});

test('assertSameEndpointTarget rejects token-bearing cross-origin and prefix escapes', () => {
  assert.doesNotThrow(() =>
    assertSameEndpointTarget('https://agent-stream.example.com/ide', 'https://agent-stream.example.com/ide/v1/chat'),
  );
  assert.throws(() =>
    assertSameEndpointTarget('https://agent-stream.example.com/ide', 'https://evil.example.com/ide/v1/chat'),
  /origin/);
  assert.throws(() =>
    assertSameEndpointTarget('https://agent-stream.example.com/ide', 'https://agent-stream.example.com/other/v1/chat'),
  /prefix/);
});

test('secureFetch disables automatic redirect following', async () => {
  const originalFetch = globalThis.fetch;
  let redirect: RequestRedirect | undefined;
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    redirect = init?.redirect;
    return new Response('', { status: 302, headers: { Location: 'https://evil.example.com/' } });
  }) as typeof fetch;
  try {
    const response = await secureFetch('https://agent-stream.example.com/ide/v1/models', { method: 'GET' }, 1000);
    assert.equal(response.status, 302);
    assert.equal(redirect, 'manual');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('secureFetch revalidates protected requests immediately before fetch', async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = (async () => {
    fetched = true;
    return new Response('', { status: 200 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      secureFetch('https://agent-stream.example.com/ide/v1/models', { method: 'GET' }, 1000, undefined, {
        lookup: async () => [{ address: '192.168.1.40' }],
      }),
      /resolves to private/,
    );
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('createTimeoutSignal aborts deterministically', async () => {
  const signal = createTimeoutSignal({ timeoutMs: 1 });
  await new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    signal.addEventListener('abort', () => resolve(), { once: true });
  });
  assert.equal(signal.aborted, true);
});
