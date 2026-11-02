import React from 'react';
import { render, screen } from '@testing-library/react';
import LogsViewer from '../LogsViewer';

jest.mock('../../../context/AppContext', () => ({
  useApp: () => ({
    state: { settings: {} },
    actions: { loadDashboardStats: jest.fn() },
    getCurrentStats: () => ({ proxy_info: { log_entries: [] } }),
  }),
}));

describe('LogsViewer', () => {
  it('shows a Surface name in the empty state as text, never as markup', () => {
    const name = '<img src=x onerror=alert(1)><a href="javascript:alert(1)">x</a>';

    render(<LogsViewer title="Surface Logs" subtitle={name} />);

    expect(screen.getByText(`No logs available for ${name}`)).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
