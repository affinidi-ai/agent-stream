import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SecretSelector, { Secret } from '../SecretSelector';

let mockPermissions: { loading: boolean; hasPermission: (feature: string) => boolean } | undefined;

jest.mock('../../../context/PermissionsContext', () => ({
  useOptionalPermissions: () => mockPermissions,
}));

const permissions = (granted: string[], loading = false) => ({
  loading,
  hasPermission: (feature: string) => granted.includes(feature),
});

const s = (id: string, name: string, tags: string[] = []): Secret => ({ id, name, tags });

function Harness({
  secrets,
  filterRegex,
  initial = '',
  autoSelectSole,
}: {
  secrets: Secret[];
  filterRegex?: string;
  initial?: string;
  autoSelectSole?: boolean;
}) {
  const [selected, setSelected] = useState(initial);
  return (
    <>
      <SecretSelector
        secrets={secrets}
        selectedSecretId={selected}
        onChange={setSelected}
        filterRegex={filterRegex}
        testId="sec"
        autoSelectSole={autoSelectSole}
      />
      <output data-testid="selected">{selected}</output>
    </>
  );
}

const selectedValue = () => screen.getByTestId('selected').textContent;

describe('SecretSelector', () => {
  beforeEach(() => {
    mockPermissions = undefined;
  });

  it('auto-selects the only secret in the list on load', async () => {
    render(<Harness secrets={[s('a', 'Alpha')]} />);
    await waitFor(() => expect(selectedValue()).toBe('a'));
  });

  it('leaves a sole secret unpicked when auto-select is turned off', async () => {
    render(<Harness secrets={[s('a', 'Alpha')]} autoSelectSole={false} />);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(selectedValue()).toBe('');
  });

  it('does not auto-select when there is more than one secret', () => {
    render(<Harness secrets={[s('a', 'Alpha'), s('b', 'Beta')]} />);
    expect(selectedValue()).toBe('');
  });

  it('preserves an existing selection instead of re-picking', () => {
    render(<Harness secrets={[s('a', 'Alpha'), s('b', 'Beta')]} initial="b" />);
    expect(selectedValue()).toBe('b');
  });

  it('lets the user clear an auto-selected sole secret without it snapping back', async () => {
    render(<Harness secrets={[s('a', 'Alpha')]} />);
    await waitFor(() => expect(selectedValue()).toBe('a'));
    fireEvent.change(screen.getByTestId('sec'), { target: { value: '' } });
    await waitFor(() => expect(selectedValue()).toBe(''));
    // Still cleared a tick later — the auto-select does not fight the user.
    expect(selectedValue()).toBe('');
  });

  it('offers "(show all secrets)" when the tag filter hides every secret, and choosing it disables the filter', async () => {
    // The filter wants an "openai" tag; the only secret is tagged "anthropic".
    render(<Harness secrets={[s('a', 'Alpha', ['anthropic'])]} filterRegex="openai" />);
    // Filter on by default → nothing matches → escape hatch shown, nothing selected.
    expect(screen.getByRole('option', { name: '(show all secrets)' })).toBeTruthy();
    expect(selectedValue()).toBe('');
    // Choosing it turns the filter off; the now-visible sole secret is auto-selected.
    fireEvent.change(screen.getByTestId('sec'), { target: { value: '__show_all_secrets__' } });
    await waitFor(() => expect(selectedValue()).toBe('a'));
    expect(screen.queryByRole('option', { name: '(show all secrets)' })).toBeNull();
  });

  it('does not offer "(show all secrets)" when there are no secrets at all', () => {
    render(<Harness secrets={[]} filterRegex="openai" />);
    expect(screen.queryByRole('option', { name: '(show all secrets)' })).toBeNull();
  });

  it('keys options on secret_id (the gateway reference), not the internal id', async () => {
    const secrets: Secret[] = [
      { id: 'uuid-1', secret_id: 'openai-key', name: 'OpenAI key' },
      { id: 'uuid-2', secret_id: 'other-key', name: 'Other' },
    ];
    render(<Harness secrets={secrets} initial="openai-key" />);
    // A stored secret_id resolves to its named option, not the UUID or "(not found)".
    const option = screen.getByRole('option', { name: 'OpenAI key' }) as HTMLOptionElement;
    expect(option.value).toBe('openai-key');
    expect(screen.queryByRole('option', { name: /not found/i })).toBeNull();
    expect(selectedValue()).toBe('openai-key');
    // Selecting emits the secret_id, never the UUID.
    fireEvent.change(screen.getByTestId('sec'), { target: { value: 'other-key' } });
    await waitFor(() => expect(selectedValue()).toBe('other-key'));
  });

  describe('a saved secret the list does not contain', () => {
    const unlisted = () => screen.getByRole('option', { selected: true }).textContent;

    it('is hidden when the user may not view secrets', () => {
      mockPermissions = permissions(['pipes.edit']);
      render(<Harness secrets={[]} initial="openai-key" />);
      expect(unlisted()).toBe('openai-key (hidden)');
      const note = screen.getByTestId('secret-selector-hidden-note');
      expect(note).toHaveTextContent(
        "You don't have permission to view secrets, so this saved key can't be shown."
      );
      // Before secrets.view was required, an editor could have set the key too.
      expect(note).not.toHaveTextContent('administrator');
    });

    it('is not found when the user may view secrets', () => {
      mockPermissions = permissions(['secrets.view']);
      render(<Harness secrets={[s('b', 'Beta')]} initial="openai-key" />);
      expect(unlisted()).toBe('openai-key (not found)');
      expect(screen.queryByTestId('secret-selector-hidden-note')).toBeNull();
    });

    it('is not found while permissions are still loading', () => {
      mockPermissions = permissions([], true);
      render(<Harness secrets={[]} initial="openai-key" />);
      expect(unlisted()).toBe('openai-key (not found)');
    });

    it('is not found outside a permissions provider', () => {
      render(<Harness secrets={[]} initial="openai-key" />);
      expect(unlisted()).toBe('openai-key (not found)');
    });
  });
});
