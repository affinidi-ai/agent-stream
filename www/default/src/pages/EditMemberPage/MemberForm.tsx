import React from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { formatDateTime } from '../../utils/stringUtils';
import MemberLimitsTab from './MemberLimitsTab';
import MemberUsageTab from './MemberUsageTab';
import {
  IDENTIFIER_LABELS,
  IDENTIFIER_PLACEHOLDERS,
  identifierValue,
  makeIdentifier,
  primaryIdentifierValue,
  type Member,
  type MemberIdentifier,
  type MemberIdentifierKind,
} from './memberHelpers';

interface MemberFormProps {
  member: Member;
  isNew: boolean;
  saving: boolean;
  error: string | null;
  canDelete: boolean;
  onSubmit: (e: React.FormEvent) => void;
  onUpdate: (patch: Partial<Member>) => void;
  onDelete: () => void;
}

const IDENTIFIER_KINDS: MemberIdentifierKind[] = ['email', 'subject', 'api_key', 'custom'];

const MemberForm: React.FC<MemberFormProps> = ({
  member,
  isNew,
  saving,
  error,
  canDelete,
  onSubmit,
  onUpdate,
  onDelete,
}) => {
  const identifiers: MemberIdentifier[] =
    member.identifiers && member.identifiers.length > 0
      ? member.identifiers
      : [{ kind: 'email', email: '' }];
  const primaryValue = primaryIdentifierValue(member);

  const updateIdentifier = (index: number, next: MemberIdentifier) => {
    const list = identifiers.map((item, i) => (i === index ? next : item));
    onUpdate({ identifiers: list });
  };

  const addIdentifier = () => {
    onUpdate({ identifiers: [...identifiers, { kind: 'email', email: '' }] });
  };

  const removeIdentifier = (index: number) => {
    const list = identifiers.filter((_, i) => i !== index);
    onUpdate({ identifiers: list.length > 0 ? list : [{ kind: 'email', email: '' }] });
  };

  return (
    <form onSubmit={onSubmit}>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-user-friends"></i>{' '}
            {isNew ? 'New Member' : `Edit Member — ${member.name || primaryValue || member.id}`}
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}

          <Tabs defaultActiveKey="details" className="mb-3">
            <Tab eventKey="details" title="Details">
              <div className="row">
                <div className="col-md-6 mb-3">
                  <label className="form-label">Name</label>
                  <input
                    type="text"
                    className="form-control"
                    value={member.name ?? ''}
                    onChange={e => onUpdate({ name: e.target.value })}
                    placeholder="Alice Example"
                  />
                </div>
                <div className="col-md-6 mb-3">
                  <label className="form-label">Description</label>
                  <input
                    type="text"
                    className="form-control"
                    value={member.description ?? ''}
                    onChange={e => onUpdate({ description: e.target.value })}
                  />
                </div>
              </div>

              {!isNew && (
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Created</label>
                    <input
                      type="text"
                      className="form-control"
                      value={formatDateTime(member.created_at, true)}
                      disabled
                      readOnly
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label className="form-label">Member ID</label>
                    <input
                      type="text"
                      className="form-control"
                      value={member.id}
                      disabled
                      readOnly
                    />
                    <small className="text-muted">
                      Server-assigned identifier. Teams reference members by this ID.
                    </small>
                  </div>
                </div>
              )}

              <div className="form-check form-switch mb-3">
                <input
                  className="form-check-input"
                  type="checkbox"
                  id="member-enabled"
                  checked={member.status === 'enabled'}
                  onChange={e => onUpdate({ status: e.target.checked ? 'enabled' : 'disabled' })}
                />
                <label className="form-check-label" htmlFor="member-enabled">
                  Enabled (only enabled members are matched at request time)
                </label>
              </div>

              <h6 className="text-primary mt-2">Identity</h6>
              <p className="text-muted">
                <small>
                  How this member is recognised on an inbound request. A member may carry several
                  identifiers and is matched under any of them; each value must be unique across all
                  members.
                </small>
              </p>
              {identifiers.map((identifier, index) => {
                const kind = identifier.kind;
                const value = identifierValue(identifier);
                return (
                  <div className="row align-items-end" key={index}>
                    <div className="col-md-4 mb-3">
                      <label className="form-label">Match by</label>
                      <select
                        className="form-select"
                        data-testid={`member-identifier-kind-${index}`}
                        value={kind}
                        onChange={e =>
                          updateIdentifier(
                            index,
                            makeIdentifier(e.target.value as MemberIdentifierKind, value)
                          )
                        }
                      >
                        {IDENTIFIER_KINDS.map(k => (
                          <option key={k} value={k}>
                            {IDENTIFIER_LABELS[k]}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="col-md-7 mb-3">
                      <label className="form-label">{IDENTIFIER_LABELS[kind]}</label>
                      <input
                        type={kind === 'email' ? 'email' : 'text'}
                        className="form-control"
                        data-testid={`member-identifier-value-${index}`}
                        value={value}
                        onChange={e =>
                          updateIdentifier(index, makeIdentifier(kind, e.target.value))
                        }
                        placeholder={IDENTIFIER_PLACEHOLDERS[kind]}
                      />
                    </div>
                    <div className="col-md-1 mb-3">
                      <button
                        type="button"
                        className="btn btn-outline-danger btn-sm w-100"
                        data-testid={`member-identifier-remove-${index}`}
                        title="Remove this identifier"
                        disabled={identifiers.length === 1}
                        onClick={() => removeIdentifier(index)}
                      >
                        <i className="fas fa-times"></i>
                      </button>
                    </div>
                  </div>
                );
              })}
              <button
                type="button"
                className="btn btn-outline-primary btn-sm"
                data-testid="member-identifier-add"
                onClick={addIdentifier}
              >
                <i className="fas fa-plus me-1"></i> Add identifier
              </button>
            </Tab>
            <Tab eventKey="limits" title="Caps & Limits">
              <MemberLimitsTab member={member} onUpdate={onUpdate} />
            </Tab>
            <Tab eventKey="usage" title="Usage" disabled={isNew}>
              <MemberUsageTab memberId={member.id} />
            </Tab>
          </Tabs>

          <hr />

          <div className="d-flex justify-content-between align-items-center">
            {!isNew && canDelete && (
              <DeleteButton
                onDelete={onDelete}
                title="Delete this member"
                disabled={saving}
                variant="danger"
              >
                Delete Member
              </DeleteButton>
            )}
            <div className={isNew || !canDelete ? 'ms-auto' : ''}>
              <button type="submit" className="btn btn-sm btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Saving...
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-1"></i> Save
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </form>
  );
};

export default MemberForm;
