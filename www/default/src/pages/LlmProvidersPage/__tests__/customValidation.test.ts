import { validateCustomCatalog } from '../customValidation';

const builtIns = new Set(['openai', 'anthropic']);

describe('validateCustomCatalog', () => {
  it('accepts a well-formed custom catalog', () => {
    const doc = {
      providers: [
        {
          enum_value: 'acme',
          name: 'Acme AI',
          models: [{ name: 'Acme One', value: 'acme-1' }],
        },
      ],
    };
    expect(validateCustomCatalog(doc, builtIns)).toBeNull();
  });

  it('accepts an empty providers array', () => {
    expect(validateCustomCatalog({ providers: [] }, builtIns)).toBeNull();
  });

  it('rejects a non-object root', () => {
    expect(validateCustomCatalog([], builtIns)).toMatch(/JSON object/i);
    expect(validateCustomCatalog(null, builtIns)).toMatch(/JSON object/i);
  });

  it('rejects a missing providers array', () => {
    expect(validateCustomCatalog({}, builtIns)).toMatch(/providers/i);
    expect(validateCustomCatalog({ providers: {} }, builtIns)).toMatch(/providers/i);
  });

  it('rejects a provider missing enum_value', () => {
    expect(validateCustomCatalog({ providers: [{ name: 'No id' }] }, builtIns)).toMatch(
      /enum_value/i
    );
  });

  it('rejects an invalid enum_value pattern', () => {
    expect(
      validateCustomCatalog({ providers: [{ enum_value: 'bad id!', name: 'X' }] }, builtIns)
    ).toMatch(/letters, digits/i);
  });

  it('rejects a provider missing name', () => {
    expect(validateCustomCatalog({ providers: [{ enum_value: 'acme' }] }, builtIns)).toMatch(
      /name/i
    );
  });

  it('rejects a collision with a built-in provider (case-insensitive)', () => {
    expect(
      validateCustomCatalog({ providers: [{ enum_value: 'OpenAI', name: 'Dup' }] }, builtIns)
    ).toMatch(/reuses a built-in/i);
  });

  it('rejects duplicates within the custom set', () => {
    expect(
      validateCustomCatalog(
        {
          providers: [
            { enum_value: 'acme', name: 'A' },
            { enum_value: 'acme', name: 'B' },
          ],
        },
        builtIns
      )
    ).toMatch(/more than once/i);
  });

  it('rejects a model missing name or value', () => {
    expect(
      validateCustomCatalog(
        { providers: [{ enum_value: 'acme', name: 'A', models: [{ name: 'Only name' }] }] },
        builtIns
      )
    ).toMatch(/value/i);
    expect(
      validateCustomCatalog(
        { providers: [{ enum_value: 'acme', name: 'A', models: [{ value: 'only-value' }] }] },
        builtIns
      )
    ).toMatch(/name/i);
  });

  it('rejects an endpoint missing path', () => {
    expect(
      validateCustomCatalog(
        {
          providers: [{ enum_value: 'acme', name: 'A', endpoints: [{ name: 'Chat' }] }],
        },
        builtIns
      )
    ).toMatch(/path/i);
  });
});
