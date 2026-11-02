import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveToolCallId } from './tool_call_id';

test('resolveToolCallId preserves provider-assigned IDs', () => {
  assert.equal(resolveToolCallId('provider-call-123'), 'provider-call-123');
});

test('resolveToolCallId generates unique cryptographic UUIDs for missing IDs', () => {
  const ids = new Set(Array.from({ length: 100 }, () => resolveToolCallId(undefined)));

  assert.equal(ids.size, 100);
  for (const id of ids) {
    assert.match(id, /^call_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }
});

test('resolveToolCallId does not retain an empty provider ID', () => {
  assert.notEqual(resolveToolCallId(''), '');
});
