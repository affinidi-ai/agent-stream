import { refreshMessage } from '../refreshMessage';

describe('refreshMessage', () => {
  it('reports an installed publication with its provider counts', () => {
    expect(
      refreshMessage({
        outcome: 'updated',
        version: '1.0.3',
        publication_sequence: 4,
        providers: 12,
        added: 2,
        skipped: [],
        backup: true,
      })
    ).toBe('Built-in models refreshed to catalog 1.0.3 — 12 providers, 2 added disabled.');
  });

  it('names the providers skipped for matching a custom provider', () => {
    expect(
      refreshMessage({
        outcome: 'updated',
        version: '1.0.3',
        publication_sequence: 4,
        providers: 12,
        added: 0,
        skipped: ['acme', 'globex'],
        backup: true,
      })
    ).toBe(
      'Built-in models refreshed to catalog 1.0.3 — 12 providers, 0 added disabled. ' +
        'Skipped because a custom provider uses the same id: acme, globex.'
    );
  });

  it('reports an unchanged publication without counts', () => {
    const message = refreshMessage({
      outcome: 'unchanged',
      version: '1.0.3',
      publication_sequence: 4,
    });
    expect(message).toBe('Built-in models are already up to date (catalog 1.0.3).');
    expect(message).not.toContain('undefined');
  });
});
