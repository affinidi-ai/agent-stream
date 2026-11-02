import {
  credentialPayload,
  loadedSecretReferences,
  pinnedDestinations,
  signingSecretTooShort,
} from '../integrationCredentials';

describe('credentialPayload', () => {
  it('sends a chosen reference instead of the inline credential', () => {
    expect(
      credentialPayload({ webhook_url: 'https://hooks.example.com/x', webhook_url_secret_id: 's1' })
    ).toEqual({ webhook_url_secret_id: 's1' });
  });

  it('keeps the inline value and drops a blank reference', () => {
    expect(credentialPayload({ url: 'https://api.example.com/hook', url_secret_id: '' })).toEqual({
      url: 'https://api.example.com/hook',
    });
  });

  it('leaves out a blank signing secret so the saved one is kept', () => {
    expect(
      credentialPayload({ url_secret_id: 'hook', signing_secret: '', method: 'POST' })
    ).toEqual({ url_secret_id: 'hook', method: 'POST' });
  });

  it('never sends the server-recorded pinned destination', () => {
    expect(
      credentialPayload({
        webhook_url_secret_id: 'hook',
        pinned_destination: { webhook_url: 'hooks.slack.com:443' },
      })
    ).toEqual({ webhook_url_secret_id: 'hook' });
  });

  it('keeps non-credential empty fields as sent', () => {
    expect(credentialPayload({ platform: 'kafka', topic: 'events', brokers: '' })).toEqual({
      platform: 'kafka',
      topic: 'events',
      brokers: '',
    });
  });

  it('moves a header with a secret reference out of the inline headers', () => {
    expect(
      credentialPayload({
        headers: { authorization: 'Bearer x', 'X-Trace': '1' },
        headers_secret_id: { Authorization: 'tok', ' ': 'ignored', 'X-Empty': '' },
      })
    ).toEqual({ headers: { 'X-Trace': '1' }, headers_secret_id: { Authorization: 'tok' } });
  });

  it('drops an empty header reference map and keeps null header removals', () => {
    expect(credentialPayload({ headers: { Authorization: null }, headers_secret_id: {} })).toEqual({
      headers: { Authorization: null },
    });
  });

  it('never sends a credential and its reference together', () => {
    const payload = credentialPayload({
      smtp_password_secret_id: 'smtp',
      sasl_password_secret_id: 'sasl',
      redis_url_secret_id: '',
      url_secret_id: 'u',
    });
    Object.keys(payload)
      .filter(key => key.endsWith('_secret_id'))
      .forEach(key => expect(payload).not.toHaveProperty(key.replace(/_secret_id$/, '')));
    expect(JSON.stringify(payload)).not.toContain('********');
  });
});

describe('loadedSecretReferences', () => {
  it('lists the non-blank references a saved configuration holds', () => {
    expect(
      loadedSecretReferences({
        url_secret_id: 'hook',
        signing_secret_secret_id: '',
        headers_secret_id: { Authorization: 'tok' },
        method: 'POST',
      })
    ).toEqual(new Set(['url_secret_id']));
  });

  it('reads a configuration stored as a JSON string', () => {
    expect(loadedSecretReferences('{"redis_url_secret_id":"r"}')).toEqual(
      new Set(['redis_url_secret_id'])
    );
  });

  it('returns no references for a missing or malformed configuration', () => {
    expect(loadedSecretReferences(undefined).size).toBe(0);
    expect(loadedSecretReferences('not json').size).toBe(0);
  });
});

describe('pinnedDestinations', () => {
  it('maps each pinned URL host to the reference it was pinned for', () => {
    expect(
      pinnedDestinations({
        url_secret_id: 'hook',
        pinned_destination: { url: 'api.example.com:443', headers: { host: 'abc' } },
      })
    ).toEqual({ url: { host: 'api.example.com:443', secretId: 'hook' } });
  });

  it('reads a configuration stored as a JSON string', () => {
    expect(
      pinnedDestinations(
        '{"redis_url_secret_id":"r","pinned_destination":{"redis_url":"cache:6379"}}'
      )
    ).toEqual({ redis_url: { host: 'cache:6379', secretId: 'r' } });
  });

  it('returns nothing when no destination was pinned', () => {
    expect(pinnedDestinations({ webhook_url_secret_id: 'hook' })).toEqual({});
    expect(pinnedDestinations('not json')).toEqual({});
  });
});

describe('signingSecretTooShort', () => {
  it('flags only a typed value shorter than 32 characters', () => {
    expect(signingSecretTooShort('x'.repeat(31))).toBe(true);
    expect(signingSecretTooShort('x'.repeat(32))).toBe(false);
    expect(signingSecretTooShort('')).toBe(false);
    expect(signingSecretTooShort(undefined)).toBe(false);
  });
});
