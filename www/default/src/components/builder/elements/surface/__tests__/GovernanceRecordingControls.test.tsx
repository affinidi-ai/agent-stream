import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { GovernanceRecordingControls } from '../SurfacePanel';
import type { GovernanceRecordingForm } from '../../../../../pages/EditPipePage/types';

jest.mock('../../../../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

const { apiClient } = jest.requireMock('../../../../../api') as { apiClient: { get: jest.Mock } };

let mockPermissions: Record<string, boolean> = { 'integrations.view': true };
jest.mock('../../../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

const saved = (overrides: Partial<GovernanceRecordingForm>): GovernanceRecordingForm => ({
  enabled: true,
  include_streaming: true,
  retention_days: 0,
  export: null,
  ...overrides,
});

/** Renders the controls as the surface editor does, holding each saved value. */
function Editor({
  initial,
  onSave,
}: {
  initial: GovernanceRecordingForm;
  onSave: (value: GovernanceRecordingForm | null) => void;
}) {
  const [value, setValue] = useState<GovernanceRecordingForm | null>(initial);
  return (
    <GovernanceRecordingControls
      value={value}
      onChange={next => {
        setValue(next);
        onSave(next);
      }}
    />
  );
}

async function renderEditor(initial: GovernanceRecordingForm) {
  const onSave = jest.fn();
  render(<Editor initial={initial} onSave={onSave} />);
  await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/integrations'));
  return {
    onSave,
    bodies: screen.getByTestId('surface-governance-capture-bodies') as HTMLSelectElement,
    outcomes: screen.getByTestId('surface-governance-record-outcomes') as HTMLSelectElement,
    lastSaved: () => onSave.mock.calls[onSave.mock.calls.length - 1][0] as GovernanceRecordingForm,
  };
}

describe('GovernanceRecordingControls body capture and recorded outcomes', () => {
  beforeEach(() => {
    apiClient.get.mockReset();
    apiClient.get.mockResolvedValue({ data: [] });
  });

  it.each([
    [true, 'all'],
    [undefined, 'all'],
    ['blocked', 'blocked'],
    [false, 'none'],
  ] as const)('shows a saved capture_bodies of %p as %s', async (value, choice) => {
    const { bodies } = await renderEditor(saved({ capture_bodies: value }));
    expect(bodies.value).toBe(choice);
  });

  it.each([
    ['none', false],
    ['blocked', 'blocked'],
    ['all', true],
  ] as const)('saves the body capture choice %s as %p', async (choice, value) => {
    const { bodies, lastSaved } = await renderEditor(
      saved({ capture_bodies: choice === 'all' ? false : true })
    );
    fireEvent.change(bodies, { target: { value: choice } });
    expect(lastSaved().capture_bodies).toBe(value);
    expect(bodies.value).toBe(choice);
  });

  it.each(['blocked', 'blocked_and_failed', 'all'] as const)(
    'saves and shows the recorded outcomes %s',
    async outcome => {
      const { outcomes, lastSaved } = await renderEditor(
        saved({ record_outcomes: outcome === 'all' ? 'blocked' : 'all' })
      );
      fireEvent.change(outcomes, { target: { value: outcome } });
      expect(lastSaved().record_outcomes).toBe(outcome);
      expect(outcomes.value).toBe(outcome);
    }
  );

  it('shows an absent record_outcomes as every interaction', async () => {
    const { outcomes } = await renderEditor(saved({}));
    expect(outcomes.value).toBe('all');
  });

  it('keeps blocked-only capture and recording through an unrelated edit', async () => {
    const { lastSaved } = await renderEditor(
      saved({ capture_bodies: 'blocked', record_outcomes: 'blocked_and_failed' })
    );
    fireEvent.click(screen.getByTestId('surface-governance-include-streaming'));
    expect(lastSaved()).toEqual(
      expect.objectContaining({
        include_streaming: false,
        capture_bodies: 'blocked',
        record_outcomes: 'blocked_and_failed',
      })
    );
  });
});

describe('GovernanceRecordingControls export integrations', () => {
  beforeEach(() => {
    apiClient.get.mockReset();
    apiClient.get.mockResolvedValue({
      data: [{ id: 'gov-1', name: 'Gov', type: 'webhook', category: 'llm_governance' }],
    });
  });

  afterEach(() => {
    mockPermissions = { 'integrations.view': true };
  });

  it('lists governance integrations for callers with integrations.view', async () => {
    render(<Editor initial={saved({})} onSave={jest.fn()} />);

    expect(await screen.findByTestId('surface-governance-integration-gov-1')).toBeInTheDocument();
    expect(screen.queryByTestId('surface-governance-integrations-admin-only')).toBeNull();
  });

  it('shows the administrators notice and never reads integrations without integrations.view', async () => {
    mockPermissions = {};
    const onSave = jest.fn();
    render(
      <Editor
        initial={saved({ export: { otel: false, integrations: ['gov-1'] } })}
        onSave={onSave}
      />
    );

    expect(screen.getByTestId('surface-governance-integrations-admin-only')).toHaveTextContent(
      'Integrations are managed by administrators.'
    );
    expect(screen.queryByTestId('surface-governance-no-integrations')).toBeNull();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(apiClient.get).not.toHaveBeenCalled();
    expect(onSave).not.toHaveBeenCalled();
  });
});
