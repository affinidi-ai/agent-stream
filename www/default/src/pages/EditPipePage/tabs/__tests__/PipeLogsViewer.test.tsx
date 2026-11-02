import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PipeLogsViewer from '../PipeLogsViewer';
import { usePermissions } from '../../../../context/PermissionsContext';

jest.mock('../../../../context/PermissionsContext', () => ({
  usePermissions: jest.fn(),
}));

jest.mock('../../../../components/shared/LogsViewer', () => ({
  __esModule: true,
  default: ({ filterPrefix }: { filterPrefix: string }) => (
    <div data-testid="logs-viewer">{filterPrefix}</div>
  ),
}));

function withPermissions(granted: string[]) {
  (usePermissions as jest.Mock).mockReturnValue({
    hasPermission: (feature: string) => granted.includes(feature),
  });
}

describe('PipeLogsViewer', () => {
  it('shows the surface log tail to a holder of logs.view', () => {
    withPermissions(['logs.view']);

    render(<PipeLogsViewer pipeId="pipe-1" pipeName="Chat" />);

    expect(screen.getByTestId('logs-viewer')).toHaveTextContent('[PIPE:pipe-1]');
  });

  it('shows nothing without logs.view', () => {
    withPermissions(['pipes.view']);

    const { container } = render(<PipeLogsViewer pipeId="pipe-1" pipeName="Chat" />);

    expect(screen.queryByTestId('logs-viewer')).not.toBeInTheDocument();
    expect(container).toBeEmptyDOMElement();
  });
});
