import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PipeActivityViewer from '../PipeActivityViewer';
import { usePermissions } from '../../../context/PermissionsContext';
import { LogEntry } from '../../../types';

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: jest.fn(),
}));

let mockLogEntries: LogEntry[] = [];

jest.mock('../../../context/AppContext', () => ({
  useApp: () => ({
    getCurrentStats: () => ({ proxy_info: { log_entries: mockLogEntries } }),
  }),
}));

afterEach(() => {
  mockLogEntries = [];
});

function withPermissions(granted: string[]) {
  (usePermissions as jest.Mock).mockReturnValue({
    hasPermission: (feature: string) => granted.includes(feature),
  });
}

describe('PipeActivityViewer', () => {
  it('shows pipeline activity to a holder of logs.view', () => {
    withPermissions(['pipes.edit', 'logs.view']);

    render(<PipeActivityViewer pipeId="pipe-1" pipeName="Chat" />);

    expect(screen.getByText(/Activity details will appear here/)).toBeInTheDocument();
    expect(screen.getByTitle('Toggle raw log view')).toBeInTheDocument();
    expect(screen.queryByTestId('pipe-activity-logs-required')).not.toBeInTheDocument();
  });

  it('says logs.view is required instead of promising activity without it', () => {
    withPermissions(['pipes.edit']);

    render(<PipeActivityViewer pipeId="pipe-1" pipeName="Chat" />);

    expect(screen.getByTestId('pipe-activity-logs-required')).toHaveTextContent(
      'requires the logs.view permission'
    );
    expect(screen.queryByText(/Activity details will appear here/)).not.toBeInTheDocument();
    expect(screen.queryByTitle('Toggle raw log view')).not.toBeInTheDocument();
  });

  it('still shows a failed request to a user without logs.view', () => {
    withPermissions(['pipes.edit']);

    render(
      <PipeActivityViewer
        pipeId="pipe-1"
        pendingError={{
          since: Date.now(),
          httpStatus: 429,
          message: 'Too many requests',
          label: 'Rate limited',
        }}
      />
    );

    expect(screen.getByTestId('pipe-activity-logs-required')).toBeInTheDocument();
    expect(screen.getByText(/Too many requests/)).toBeInTheDocument();
  });

  it('shows raw log levels and messages as text, never as markup', () => {
    withPermissions(['pipes.edit', 'logs.view']);
    const level = '<img/src=x/onerror=alert(1)>';
    const message = '<img src=x onerror=alert(2)><a href="javascript:alert(3)">x</a>';
    mockLogEntries = [
      { timestamp: Date.now(), level, message: `[PIPE:pipe-1] ${message}`, file_position: 1 },
    ];

    render(<PipeActivityViewer pipeId="pipe-1" pipeName="Chat" />);
    fireEvent.click(screen.getByTitle('Toggle raw log view'));

    expect(screen.getByText(level)).toBeInTheDocument();
    expect(screen.getByText(message, { exact: false })).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
