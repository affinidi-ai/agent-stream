import { apiKeySurfaceOptions } from './apiKeySurfaceOptions';

describe('apiKeySurfaceOptions', () => {
  it('uses pipe ids as selectable API-key surface option values', () => {
    const options = apiKeySurfaceOptions([
      { id: 'llm-surface-1', name: 'LLM Surface' },
      { id: 'ide-surface-1', name: 'IDE Surface' },
    ]);

    expect(options).toEqual([
      { id: 'ide-surface-1', name: 'IDE Surface' },
      { id: 'llm-surface-1', name: 'LLM Surface' },
    ]);
  });

  it('keeps legacy agent surface ids working', () => {
    expect(apiKeySurfaceOptions([{ surface_id: 'agent-surface-1', name: 'G2G Surface' }])).toEqual([
      { id: 'agent-surface-1', name: 'G2G Surface' },
    ]);
  });

  it('drops entries without any id so the select never renders undefined values', () => {
    expect(apiKeySurfaceOptions([{ name: 'Broken' }, { id: 'valid' }])).toEqual([
      { id: 'valid', name: 'valid' },
    ]);
  });
});
