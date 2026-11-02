import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SystemTab from '../SystemTab';
import { showToast } from '../../../utils/toaster';

jest.mock('../../../api', () => ({ apiClient: {} }));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

function renderSystemTab(canTruncate: boolean) {
  render(
    <SystemTab
      isSubmitting={false}
      canTruncate={canTruncate}
      onTruncateMetrics={jest.fn()}
      settings={null}
      updateSettings={jest.fn()}
    />
  );
}

describe('SystemTab truncate actions', () => {
  it('offers both truncate buttons to a holder of settings.edit', () => {
    renderSystemTab(true);

    expect(screen.getByText('Truncate Old Metrics Now')).toBeInTheDocument();
    expect(screen.getByText('Truncate Old Logs')).toBeInTheDocument();
  });

  it('hides both truncate buttons without settings.edit', () => {
    renderSystemTab(false);

    expect(screen.queryByText('Truncate Old Metrics Now')).not.toBeInTheDocument();
    expect(screen.queryByText('Truncate Old Logs')).not.toBeInTheDocument();
  });
});

describe('SystemTab restore upload', () => {
  const selectFile = (name: string) => {
    renderSystemTab(true);
    fireEvent.change(screen.getByTestId('system-restore-file-input'), {
      target: { files: [new File(['x'], name)] },
    });
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(window, 'confirm').mockReturnValue(false);
  });

  it.each(['backup.asbak', 'backup.tgwbak'])('accepts %s', name => {
    selectFile(name);

    expect(window.confirm).toHaveBeenCalled();
    expect(showToast).not.toHaveBeenCalled();
  });

  it('rejects a file with another extension', () => {
    selectFile('backup.zip');

    expect(window.confirm).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith('error', 'Please select a .asbak backup file');
  });
});
