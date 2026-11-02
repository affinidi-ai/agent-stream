import React, { useState } from 'react';
import { apiClient } from '../../api';
import InfoTooltip from './InfoTooltip';
import { AppButton } from '../../components/shared/AppButton';
import {
  parseList,
  type MemberProvisioningConfig,
  type PreviewIdentityRequest,
  type PreviewIdentityType,
  type ProvisionPreview,
} from './provisioningHelpers';

const IDENTITY_TYPES: PreviewIdentityType[] = ['jwt', 'api_key', 'mtls'];

const IDENTITY_TYPE_LABELS: Record<PreviewIdentityType, string> = {
  jwt: 'JWT bearer',
  api_key: 'API key',
  mtls: 'mTLS certificate',
};

interface ProvisioningPreviewPanelProps {
  /** The live editor config, so the dry-run reflects unsaved changes. */
  config: MemberProvisioningConfig;
}

const ProvisioningPreviewPanel: React.FC<ProvisioningPreviewPanelProps> = ({ config }) => {
  const [identityType, setIdentityType] = useState<PreviewIdentityType>('jwt');
  const [subject, setSubject] = useState('');
  const [claimsText, setClaimsText] = useState('{\n  "email": "alice@example.com"\n}');
  const [keyName, setKeyName] = useState('');
  const [subjectDn, setSubjectDn] = useState('');
  const [emailSans, setEmailSans] = useState('');

  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProvisionPreview | null>(null);

  const buildRequest = (): PreviewIdentityRequest | null => {
    if (identityType === 'jwt') {
      let claims: Record<string, unknown> = {};
      if (claimsText.trim()) {
        const parsed = JSON.parse(claimsText);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('Claims must be a JSON object');
        }
        claims = parsed as Record<string, unknown>;
      }
      return { type: 'jwt', subject: subject.trim(), claims };
    }
    if (identityType === 'api_key') {
      return { type: 'api_key', key_name: keyName.trim() };
    }
    return {
      type: 'mtls',
      subject_dn: subjectDn.trim(),
      sans: { dns: [], uri: [], email: parseList(emailSans), ip: [] },
    };
  };

  const runPreview = async () => {
    setError(null);
    setResult(null);
    let request: PreviewIdentityRequest | null;
    try {
      request = buildRequest();
    } catch (err: any) {
      setError(err.message || 'Invalid claims JSON');
      return;
    }
    if (!request) return;
    try {
      setRunning(true);
      const response = await apiClient.post<ProvisionPreview>('/member-provisioning/preview', {
        ...request,
        config,
      });
      setResult(response.data);
    } catch (err: any) {
      setError(err.message || 'Preview failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-vial"></i> Dry-run preview
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted small">
          Describe a caller identity and see exactly what the rules currently on screen would mint —
          including unsaved edits. No member is created.
        </p>

        <div className="mb-3">
          <label className="form-label small mb-1">
            Identity type
            <InfoTooltip
              title="Dry-run preview"
              text="Describe a hypothetical verified caller (a JWT with claims, a named API key, or an mTLS certificate) and see exactly what the rules on screen would do — the identifiers derived and the teams joined or created. It reflects unsaved edits and never creates anything."
            />
          </label>
          <select
            className="form-select"
            value={identityType}
            data-testid="preview-identity-type"
            onChange={e => setIdentityType(e.target.value as PreviewIdentityType)}
          >
            {IDENTITY_TYPES.map(type => (
              <option key={type} value={type}>
                {IDENTITY_TYPE_LABELS[type]}
              </option>
            ))}
          </select>
        </div>

        {identityType === 'jwt' && (
          <>
            <div className="mb-3">
              <label className="form-label small mb-1">Subject (sub)</label>
              <input
                type="text"
                className="form-control"
                value={subject}
                data-testid="preview-subject"
                onChange={e => setSubject(e.target.value)}
              />
            </div>
            <div className="mb-3">
              <label className="form-label small mb-1">Claims (JSON)</label>
              <textarea
                className="form-control font-monospace"
                rows={6}
                value={claimsText}
                data-testid="preview-claims"
                onChange={e => setClaimsText(e.target.value)}
              />
            </div>
          </>
        )}

        {identityType === 'api_key' && (
          <div className="mb-3">
            <label className="form-label small mb-1">Key name</label>
            <input
              type="text"
              className="form-control"
              value={keyName}
              data-testid="preview-key-name"
              onChange={e => setKeyName(e.target.value)}
            />
          </div>
        )}

        {identityType === 'mtls' && (
          <>
            <div className="mb-3">
              <label className="form-label small mb-1">Subject DN</label>
              <input
                type="text"
                className="form-control"
                placeholder="CN=alice,O=Example"
                value={subjectDn}
                data-testid="preview-subject-dn"
                onChange={e => setSubjectDn(e.target.value)}
              />
            </div>
            <div className="mb-3">
              <label className="form-label small mb-1">Email SANs</label>
              <input
                type="text"
                className="form-control"
                placeholder="comma-separated"
                value={emailSans}
                data-testid="preview-email-sans"
                onChange={e => setEmailSans(e.target.value)}
              />
            </div>
          </>
        )}

        <AppButton
          type="button"
          variant="primary"
          disabled={running}
          loading={running}
          loadingLabel="Running..."
          data-testid="preview-run"
          onClick={runPreview}
          iconStart={<i className="fas fa-play me-1"></i>}
        >
          Run preview
        </AppButton>

        {error && (
          <div className="alert alert-danger mt-3 mb-0" role="alert">
            {error}
          </div>
        )}

        {result && (
          <div className="mt-3" data-testid="preview-result">
            <div className="mb-2">
              {result.would_provision ? (
                <span className="badge text-bg-success">
                  <i className="fas fa-check me-1"></i>Would provision
                </span>
              ) : (
                <span className="badge text-bg-secondary">
                  <i className="fas fa-ban me-1"></i>Would not provision
                </span>
              )}
            </div>
            {result.reason && <p className="text-muted small">{result.reason}</p>}
            {result.name && (
              <p className="mb-1">
                <strong>Name:</strong> {result.name}
              </p>
            )}
            {result.identifiers.length > 0 && (
              <div className="mb-2">
                <strong>Identifiers:</strong>{' '}
                {result.identifiers.map((id, i) => (
                  <span key={i} className="badge text-bg-secondary me-1">
                    {id.kind}: {id.value}
                  </span>
                ))}
              </div>
            )}
            {result.teams.length > 0 && (
              <div>
                <strong>Teams:</strong>{' '}
                {result.teams.map((team, i) => (
                  <span key={i} className="badge text-bg-info me-1">
                    {team.name || team.team_id}
                    {team.would_create && ' (new)'}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ProvisioningPreviewPanel;
