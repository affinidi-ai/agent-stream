import React from 'react';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { formatDateTime } from '../../utils/stringUtils';
import type { AccessTokenMeta } from '../../types';

function tokenStatus(t: AccessTokenMeta): { label: string; tone: string } {
  if (t.revoked_at) return { label: 'Revoked', tone: 'secondary' };
  if (!t.active) return { label: 'Expired', tone: 'warning' };
  return { label: 'Active', tone: 'success' };
}

interface AccessTokenRowProps {
  token: AccessTokenMeta;
  canDelete: boolean;
  onOpen: () => void;
  onRevoke: () => void;
}

const AccessTokenRow: React.FC<AccessTokenRowProps> = ({ token, canDelete, onOpen, onRevoke }) => {
  const st = tokenStatus(token);
  return (
    <tr style={{ cursor: 'pointer' }} onClick={onOpen}>
      <td>
        <strong>{token.name}</strong>
        {token.description && <div className="text-muted small">{token.description}</div>}
      </td>
      <td>
        {token.scopes.length === 0 ? (
          <span className="text-muted fst-italic" style={{ fontSize: '0.85rem' }}>
            Full role
          </span>
        ) : (
          <>
            {token.scopes.slice(0, 3).map(s => (
              <span key={s} className="badge text-bg-secondary me-1">
                {s}
              </span>
            ))}
            {token.scopes.length > 3 && (
              <span className="text-muted small">+{token.scopes.length - 3}</span>
            )}
          </>
        )}
      </td>
      <td>
        <span className={`badge text-bg-${st.tone}`}>{st.label}</span>
      </td>
      <td>
        <small>{token.last_used_at ? formatDateTime(token.last_used_at) : 'Never'}</small>
      </td>
      <td>
        <small>{token.expires_at ? formatDateTime(token.expires_at) : 'Never'}</small>
      </td>
      <td>
        <small>{formatDateTime(token.created_at)}</small>
      </td>
      {canDelete && (
        <td onClick={e => e.stopPropagation()}>
          <DeleteButton
            onDelete={onRevoke}
            className="btn-sm"
            title="Revoke access token"
            disabled={!!token.revoked_at}
          />
        </td>
      )}
    </tr>
  );
};

export default AccessTokenRow;
