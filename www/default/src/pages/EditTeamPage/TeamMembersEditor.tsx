import React, { useMemo, useState } from 'react';
import {
  IDENTIFIER_LABELS,
  memberLabel,
  primaryIdentifier,
  primaryIdentifierValue,
  type Member,
} from '../EditMemberPage/memberHelpers';

interface TeamMembersEditorProps {
  members: string[];
  registry: Member[];
  onAdd: (memberId: string) => void;
  onRemove: (memberId: string) => void;
}

/**
 * Picks members for a team from the shared Member registry. Teams store member
 * UUIDs; the per-member caps live on the Member itself, not the team.
 */
const TeamMembersEditor: React.FC<TeamMembersEditorProps> = ({
  members,
  registry,
  onAdd,
  onRemove,
}) => {
  const [selection, setSelection] = useState('');

  const byId = useMemo(() => {
    const map = new Map<string, Member>();
    registry.forEach(m => map.set(m.id, m));
    return map;
  }, [registry]);

  const available = useMemo(
    () => registry.filter(m => !members.includes(m.id)),
    [registry, members]
  );

  const handleAdd = () => {
    if (selection) {
      onAdd(selection);
      setSelection('');
    }
  };

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mt-2">
        <h6 className="text-primary mb-0">Members</h6>
      </div>
      <p className="text-muted">
        <small>
          Add members from the registry. Per-member caps are configured on the member, not here.
        </small>
      </p>

      <div className="input-group mb-3">
        <select
          className="form-select"
          value={selection}
          onChange={e => setSelection(e.target.value)}
        >
          <option value="">
            {available.length === 0 ? 'No more members to add' : 'Select a member to add…'}
          </option>
          {available.map(m => (
            <option key={m.id} value={m.id}>
              {memberLabel(m)} — {primaryIdentifierValue(m)}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="btn btn-outline-primary"
          onClick={handleAdd}
          disabled={!selection}
        >
          <i className="fas fa-plus"></i> Add
        </button>
      </div>

      {members.length === 0 ? (
        <p className="text-muted">
          <small>No members yet.</small>
        </p>
      ) : (
        <div className="table-responsive">
          <table className="table table-sm align-middle">
            <thead>
              <tr>
                <th>Member</th>
                <th>Identity</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {members.map(memberId => {
                const member = byId.get(memberId);
                return (
                  <tr key={memberId}>
                    <td>
                      {member ? (
                        <strong>{memberLabel(member)}</strong>
                      ) : (
                        <span className="text-danger">
                          <i className="fas fa-exclamation-triangle me-1"></i> Unknown member
                        </span>
                      )}
                      <div className="text-muted">
                        <small>{memberId}</small>
                      </div>
                    </td>
                    <td>
                      {member ? (
                        <>
                          <span className="badge text-bg-secondary me-1">
                            {primaryIdentifier(member)
                              ? IDENTIFIER_LABELS[primaryIdentifier(member)!.kind]
                              : '—'}
                          </span>
                          <small>{primaryIdentifierValue(member)}</small>
                        </>
                      ) : (
                        <small className="text-muted">—</small>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-sm btn-outline-danger"
                        onClick={() => onRemove(memberId)}
                        title="Remove member"
                      >
                        <i className="fas fa-trash"></i>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
};

export default TeamMembersEditor;
