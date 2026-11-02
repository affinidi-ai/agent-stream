import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import type { RequiredHeader } from '../../types';
import AccessTokenResourceScope from './AccessTokenResourceScope';

const placeholder = (name: string) => `\${${name}}`;

function Harness({ pattern, headers }: { pattern: string; headers: RequiredHeader[] }) {
  const [resourcePattern, setResourcePattern] = useState(pattern);
  const [requiredHeaders, setRequiredHeaders] = useState(headers);
  return (
    <>
      <AccessTokenResourceScope
        pattern={resourcePattern}
        onPatternChange={setResourcePattern}
        headers={requiredHeaders}
        onHeadersChange={setRequiredHeaders}
      />
      <output data-testid="saved-pattern">{resourcePattern}</output>
      <output data-testid="saved-headers">{JSON.stringify(requiredHeaders)}</output>
    </>
  );
}

describe('AccessTokenResourceScope', () => {
  it('opens preset scoping and preserves and directly edits an existing canonical pattern', () => {
    const pattern = `TENANT:${placeholder('account')}:pipes:resource-.*`;
    const headers = [{ name: 'account', pattern: 'tenant-a' }];
    render(<Harness pattern={pattern} headers={headers} />);

    expect(screen.getByTestId('access-token-resource-scope-toggle')).toHaveAttribute(
      'aria-expanded',
      'true'
    );
    expect(screen.getByText('Tenant selected by account')).toBeInTheDocument();
    expect(screen.getByTestId('access-token-resource-pattern')).toHaveValue(pattern);
    expect(screen.getByTestId('saved-pattern')).toHaveTextContent(pattern);
    expect(screen.getByTestId('saved-headers')).toHaveTextContent(JSON.stringify(headers));

    fireEvent.change(screen.getByTestId('access-token-resource-pattern'), {
      target: { value: `TENANT:${placeholder('account')}:secrets:.*` },
    });
    expect(screen.getByTestId('saved-pattern')).toHaveTextContent(
      `TENANT:${placeholder('account')}:secrets:.*`
    );
  });

  it('adds the required tenant header without generating authority implicitly', () => {
    render(<Harness pattern="" headers={[]} />);
    fireEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    expect(screen.getByText('Appliance-wide')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('access-token-add-header'));
    expect(screen.getByTestId('saved-headers')).toHaveTextContent(
      JSON.stringify([{ name: '', pattern: '' }])
    );

    fireEvent.change(screen.getByTestId('access-token-header-name-0'), {
      target: { value: 'x-tenant-id' },
    });
    fireEvent.change(screen.getByTestId('access-token-header-pattern-0'), {
      target: { value: 'tenant-a' },
    });
    expect(screen.getByTestId('saved-headers')).toHaveTextContent(
      JSON.stringify([{ name: 'x-tenant-id', pattern: 'tenant-a' }])
    );
  });
});
