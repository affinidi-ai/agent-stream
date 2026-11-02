import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';

interface Mediator {
  id: string;
  name: string;
  description: string;
  did: string;
  our_did?: string;
  status: 'active' | 'disabled';
  did_document?: any;
  created_at: string;
  updated_at: string;
}

function hasDIDCommMessaging(doc: any): boolean {
  if (!doc || !doc.service || !Array.isArray(doc.service)) return false;
  return doc.service.some(
    (service: any) =>
      service.type === 'DIDCommMessaging' ||
      (Array.isArray(service.type) && service.type.includes('DIDCommMessaging'))
  );
}

interface MediatorsPageProps {
  externalSearchTerm?: string;
  onCountChange?: (filtered: number, total: number) => void;
}

const MediatorsPage: React.FC<MediatorsPageProps> = ({ externalSearchTerm, onCountChange }) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const { id: idParam } = useParams<{ id?: string }>();
  const [mediators, setMediators] = useState<Mediator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [expandedMediatorIds, setExpandedMediatorIds] = useState<Set<string>>(new Set());
  const [expandedSections, setExpandedSections] = useState<Record<string, Set<string>>>({});
  const [authChecking, setAuthChecking] = useState<Record<string, boolean>>({});
  const [authCompatible, setAuthCompatible] = useState<Record<string, boolean | null>>({});
  const [authCheckError, setAuthCheckError] = useState<Record<string, string>>({});
  const mediatorRefs = useRef<Record<string, HTMLTableRowElement | null>>({});
  const [pingStatus, setPingStatus] = useState<{ [key: string]: 'pinging' | 'success' | 'failed' }>(
    {}
  );
  const [searchTerm, setSearchTerm] = useState('');
  const effectiveSearchTerm = externalSearchTerm ?? searchTerm;

  // Handle deep linking to a specific mediator
  useEffect(() => {
    if (idParam && mediators.length > 0) {
      const decodedId = decodeURIComponent(idParam);
      const mediator = mediators.find(m => m.id === decodedId);
      if (mediator) {
        setExpandedMediatorIds(new Set([decodedId]));
        setExpandedSections({
          [decodedId]: new Set(['summary']),
        });
        // Check auth if needed
        if (mediator.did_document && hasDIDCommMessaging(mediator.did_document)) {
          checkAuthEndpoints(decodedId, mediator.did, mediator.did_document);
        }
        // Scroll to the mediator after a short delay
        setTimeout(() => {
          const element = mediatorRefs.current[decodedId];
          if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        }, 100);
      }
    }
  }, [idParam, mediators]);

  const fetchMediators = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/mediators');
      setMediators(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load mediators');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMediators();
  }, [fetchMediators]);

  // Check if authentication endpoints are accessible
  const checkAuthEndpoints = async (mediatorId: string, mediatorDid: string, doc: any) => {
    setAuthChecking(prev => ({ ...prev, [mediatorId]: true }));
    setAuthCheckError(prev => ({ ...prev, [mediatorId]: '' }));

    try {
      const response = await apiClient.post('/mediators/check-auth', {
        did: mediatorDid,
        did_document: doc,
      });

      if (response.data.compatible) {
        setAuthCompatible(prev => ({ ...prev, [mediatorId]: true }));
      } else {
        setAuthCompatible(prev => ({ ...prev, [mediatorId]: false }));
        setAuthCheckError(prev => ({
          ...prev,
          [mediatorId]: response.data.error || 'Authentication endpoint check failed',
        }));
      }
    } catch (err: any) {
      setAuthCompatible(prev => ({ ...prev, [mediatorId]: false }));
      setAuthCheckError(prev => ({
        ...prev,
        [mediatorId]: err.message || 'Failed to check authentication endpoints',
      }));
    } finally {
      setAuthChecking(prev => ({ ...prev, [mediatorId]: false }));
    }
  };

  const toggleMediatorDetails = (mediatorId: string, mediator: Mediator) => {
    setExpandedMediatorIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(mediatorId)) {
        newSet.delete(mediatorId);
        // Clean up expanded sections
        setExpandedSections(prevSections => {
          const newSections = { ...prevSections };
          delete newSections[mediatorId];
          return newSections;
        });
        // Navigate back to mediators when closing
        navigate('/connections?tab=mediators');
      } else {
        newSet.add(mediatorId);
        // Initialize with summary section open
        setExpandedSections(prevSections => ({
          ...prevSections,
          [mediatorId]: new Set(['summary']),
        }));
        // Check auth if needed
        if (mediator.did_document && hasDIDCommMessaging(mediator.did_document)) {
          checkAuthEndpoints(mediatorId, mediator.did, mediator.did_document);
        }
        // Navigate to deep link URL
        navigate(`/mediators/view/${encodeURIComponent(mediatorId)}`);
      }
      return newSet;
    });
  };

  const toggleSection = (mediatorId: string, section: string) => {
    setExpandedSections(prev => {
      const sections = prev[mediatorId] || new Set();
      const newSections = new Set(sections);
      if (newSections.has(section)) {
        newSections.delete(section);
      } else {
        newSections.add(section);
      }
      return {
        ...prev,
        [mediatorId]: newSections,
      };
    });
  };

  const isSectionExpanded = (mediatorId: string, section: string) => {
    return expandedSections[mediatorId]?.has(section) || false;
  };

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/mediators/${id}`);
      setSuccess('Mediator deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      fetchMediators();
    } catch (error: any) {
      setError(error.message || 'Failed to delete mediator');
    }
  };

  const handleTrustPing = async (id: string, name: string, event: React.MouseEvent) => {
    event.stopPropagation();

    setPingStatus(prev => ({ ...prev, [id]: 'pinging' }));

    try {
      const response = await apiClient.post(`/mediators/${id}/trust-ping`);

      if (response.data.success) {
        setPingStatus(prev => ({ ...prev, [id]: 'success' }));
        setSuccess(`Trust ping to "${name}" successful (${response.data.round_trip_ms}ms)`);
        setTimeout(() => {
          setPingStatus(prev => {
            const newStatus = { ...prev };
            delete newStatus[id];
            return newStatus;
          });
          setSuccess(null);
        }, 3000);
      } else {
        setPingStatus(prev => ({ ...prev, [id]: 'failed' }));
        setError(`Trust ping to "${name}" failed: ${response.data.message}`);
        setTimeout(() => {
          setPingStatus(prev => {
            const newStatus = { ...prev };
            delete newStatus[id];
            return newStatus;
          });
        }, 3000);
      }
    } catch (error: any) {
      setPingStatus(prev => ({ ...prev, [id]: 'failed' }));
      setError(error.message || `Failed to ping mediator "${name}"`);
      setTimeout(() => {
        setPingStatus(prev => {
          const newStatus = { ...prev };
          delete newStatus[id];
          return newStatus;
        });
      }, 3000);
    }
  };

  // Filter mediators based on search term
  const filteredMediators = useMemo(() => {
    const trimmedSearch = effectiveSearchTerm.trim();
    if (!trimmedSearch) return mediators;

    const searchLower = trimmedSearch.toLowerCase();
    return mediators.filter(
      mediator =>
        mediator.name?.toLowerCase().includes(searchLower) ||
        mediator.description?.toLowerCase().includes(searchLower) ||
        mediator.id?.toLowerCase().includes(searchLower) ||
        mediator.did?.toLowerCase().includes(searchLower)
    );
  }, [mediators, effectiveSearchTerm]);

  useEffect(() => {
    if (onCountChange) onCountChange(filteredMediators.length, mediators.length);
  }, [filteredMediators.length, mediators.length, onCountChange]);

  const isEmbedded = externalSearchTerm !== undefined;

  return (
    <div className={isEmbedded ? '' : 'container-fluid'}>
      {!isEmbedded && (
        <div className="d-sm-flex align-items-center justify-content-between mb-4">
          <div>
            <SearchInput
              value={searchTerm}
              onChange={setSearchTerm}
              placeholder="Filter Mediators...."
            />
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      {loading ? (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-exchange-alt"></i> All Mediators
              {mediators.length > 0 && (
                <Badge
                  value={filteredMediators.length}
                  suffix={effectiveSearchTerm ? ` of ${mediators.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${filteredMediators.length}${effectiveSearchTerm ? ` of ${mediators.length}` : ''} mediators`}
                />
              )}
            </h6>
            {hasPermission('mediators.edit') && mediators.length > 0 && (
              <>
                <AppButton
                  variant="primary"
                  size="sm"
                  onClick={e =>
                    guard('connections.mediators', () => navigate('/mediators/wizard'), e)
                  }
                  iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                >
                  Add Mediator
                </AppButton>
                {balloonNode}
              </>
            )}
          </div>
          <div className="card-body">
            {mediators.length === 0 && !effectiveSearchTerm ? (
              <EmptyState
                icon="fa-exchange-alt"
                title="Add your first mediator"
                body="Route messages to agents behind a firewall."
                ctaLabel={hasPermission('mediators.edit') ? 'Add Mediator' : undefined}
                ctaIcon="fa-plus"
                onCtaClick={
                  hasPermission('mediators.edit') ? () => navigate('/mediators/wizard') : undefined
                }
              />
            ) : filteredMediators.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p
                  className={
                    mediators.length === 0 && hasPermission('mediators.edit') ? 'mb-3' : 'mb-0'
                  }
                >
                  No mediators match your search.
                </p>
                {mediators.length === 0 && hasPermission('mediators.edit') && (
                  <AppButton
                    variant="primary"
                    size="sm"
                    onClick={() => navigate('/mediators/wizard')}
                    iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
                  >
                    Add Mediator
                  </AppButton>
                )}
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>DID</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMediators.map(mediator => {
                      const isExpanded = expandedMediatorIds.has(mediator.id);
                      const didDocument = mediator.did_document;

                      return (
                        <React.Fragment key={mediator.id}>
                          <tr
                            ref={el => (mediatorRefs.current[mediator.id] = el)}
                            onClick={() => toggleMediatorDetails(mediator.id, mediator)}
                            style={{ cursor: 'pointer' }}
                          >
                            <td>
                              <i
                                className={`fas fa-chevron-${isExpanded ? 'down' : 'right'} me-2`}
                              ></i>
                              {mediator.name}
                            </td>
                            <td>
                              <small>{mediator.description}</small>
                            </td>
                            <td>
                              <code style={{ fontSize: '0.75rem' }}>{mediator.did}</code>
                            </td>
                            <td>
                              <span
                                className={`badge ${mediator.status === 'active' ? 'text-bg-success' : 'text-bg-secondary'}`}
                              >
                                {mediator.status.toUpperCase()}
                              </span>
                            </td>
                            <td className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                              <button
                                title="Trust Ping - Test connectivity"
                                className={`btn btn-sm ${
                                  pingStatus[mediator.id] === 'pinging'
                                    ? 'btn-secondary'
                                    : pingStatus[mediator.id] === 'success'
                                      ? 'btn-success'
                                      : pingStatus[mediator.id] === 'failed'
                                        ? 'btn-danger'
                                        : 'btn-info'
                                }`}
                                onClick={e => handleTrustPing(mediator.id, mediator.name, e)}
                                disabled={pingStatus[mediator.id] === 'pinging'}
                              >
                                {pingStatus[mediator.id] === 'pinging' ? (
                                  <span
                                    className="spinner-border spinner-border-sm"
                                    role="status"
                                    aria-hidden="true"
                                  ></span>
                                ) : pingStatus[mediator.id] === 'success' ? (
                                  <i className="fas fa-check"></i>
                                ) : pingStatus[mediator.id] === 'failed' ? (
                                  <i className="fas fa-times"></i>
                                ) : (
                                  <i className="fas fa-heartbeat"></i>
                                )}
                              </button>
                              {hasPermission('mediators.edit') && (
                                <button
                                  title="Edit Mediator"
                                  className="btn btn-sm btn-primary"
                                  onClick={() => navigate(`/mediators/${mediator.id}`)}
                                >
                                  <i className="fas fa-edit"></i>
                                </button>
                              )}
                              {hasPermission('mediators.delete') && (
                                <DeleteButton
                                  onDelete={() => handleDelete(mediator.id)}
                                  size="sm"
                                  title="Delete Mediator"
                                />
                              )}
                            </td>
                          </tr>

                          {/* Expandable Details Row */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={5} className="p-0">
                                <div className="bg-light p-3 border-top">
                                  {/* Summary Section */}
                                  <div className="mb-2">
                                    <div
                                      onClick={() => toggleSection(mediator.id, 'summary')}
                                      style={{ cursor: 'pointer' }}
                                      className="bg-white border rounded py-1 px-3"
                                    >
                                      <i
                                        className={`fas fa-chevron-${isSectionExpanded(mediator.id, 'summary') ? 'down' : 'right'} me-2`}
                                      ></i>
                                      <small className="text-muted">Summary</small>
                                    </div>
                                    {isSectionExpanded(mediator.id, 'summary') && (
                                      <div className="bg-white border border-top-0 rounded-bottom p-3">
                                        <dl className="row mb-0" style={{ fontSize: '0.875rem' }}>
                                          <dt className="col-sm-3">Name:</dt>
                                          <dd className="col-sm-9">{mediator.name}</dd>

                                          <dt className="col-sm-3">Description:</dt>
                                          <dd className="col-sm-9">{mediator.description}</dd>

                                          <dt className="col-sm-3">Mediator DID:</dt>
                                          <dd className="col-sm-9">
                                            <code style={{ fontSize: '0.75rem' }}>
                                              {mediator.did}
                                            </code>
                                          </dd>

                                          {mediator.our_did && (
                                            <>
                                              <dt className="col-sm-3">Our DID:</dt>
                                              <dd className="col-sm-9">
                                                <code style={{ fontSize: '0.75rem' }}>
                                                  {mediator.our_did}
                                                </code>
                                                <div>
                                                  <small className="text-muted">
                                                    <i className="fas fa-info-circle me-1"></i>
                                                    Persistent did:peer for admin communications
                                                  </small>
                                                </div>
                                              </dd>
                                            </>
                                          )}

                                          <dt className="col-sm-3">Status:</dt>
                                          <dd className="col-sm-9">
                                            <span
                                              className={`badge badge-${mediator.status === 'active' ? 'success' : 'secondary'}`}
                                            >
                                              {mediator.status}
                                            </span>
                                          </dd>

                                          <dt className="col-sm-3">Created:</dt>
                                          <dd className="col-sm-9">
                                            {formatDateTime(mediator.created_at, true)}
                                          </dd>

                                          <dt className="col-sm-3">Updated:</dt>
                                          <dd className="col-sm-9">
                                            {formatDateTime(mediator.updated_at)}
                                          </dd>
                                        </dl>
                                      </div>
                                    )}
                                  </div>

                                  {/* DID Document Section */}
                                  {didDocument && (
                                    <div className="mb-2">
                                      <div
                                        onClick={() => toggleSection(mediator.id, 'did-document')}
                                        style={{ cursor: 'pointer' }}
                                        className="bg-white border rounded py-1 px-3"
                                      >
                                        <i
                                          className={`fas fa-chevron-${isSectionExpanded(mediator.id, 'did-document') ? 'down' : 'right'} me-2`}
                                        ></i>
                                        <small className="text-muted">DID Document</small>
                                      </div>
                                      {isSectionExpanded(mediator.id, 'did-document') && (
                                        <div className="bg-white border border-top-0 rounded-bottom p-3">
                                          {hasDIDCommMessaging(didDocument) ? (
                                            <div className="alert alert-success mb-3">
                                              <i className="fas fa-check-circle me-2"></i>
                                              <strong>Compatible Mediator!</strong> This DID has a
                                              DIDCommMessaging service.
                                            </div>
                                          ) : (
                                            <div className="alert alert-warning mb-3">
                                              <i className="fas fa-exclamation-triangle me-2"></i>
                                              <strong>Warning:</strong> This DID does not have a
                                              DIDCommMessaging service.
                                            </div>
                                          )}

                                          {/* Authentication Check */}
                                          {authChecking[mediator.id] && (
                                            <div className="alert alert-info mb-3">
                                              <div className="d-flex align-items-center">
                                                <div
                                                  className="spinner-border spinner-border-sm me-2"
                                                  role="status"
                                                ></div>
                                                <span>
                                                  Checking authentication endpoint compatibility...
                                                </span>
                                              </div>
                                            </div>
                                          )}

                                          {!authChecking[mediator.id] &&
                                            authCompatible[mediator.id] === true && (
                                              <div className="alert alert-success mb-3">
                                                <i className="fas fa-check-circle me-2"></i>
                                                <strong>Authentication Compatible!</strong> The
                                                mediator's authentication endpoints are accessible.
                                              </div>
                                            )}

                                          {!authChecking[mediator.id] &&
                                            authCompatible[mediator.id] === false && (
                                              <div className="alert alert-danger mb-3">
                                                <i className="fas fa-exclamation-triangle me-2"></i>
                                                <strong>Authentication Incompatible!</strong> The
                                                mediator's authentication endpoints cannot be
                                                reached.
                                                {authCheckError[mediator.id] && (
                                                  <div className="mt-2">
                                                    <small>
                                                      <strong>Details:</strong>{' '}
                                                      {authCheckError[mediator.id]}
                                                    </small>
                                                  </div>
                                                )}
                                                <div className="mt-2">
                                                  <small>
                                                    This mediator will not work for creating
                                                    connection points with authenticated OOB
                                                    invitations.
                                                  </small>
                                                </div>
                                              </div>
                                            )}

                                          {/* Services */}
                                          {didDocument.service &&
                                            didDocument.service.length > 0 && (
                                              <div className="mb-3">
                                                <strong className="text-muted small">
                                                  Services ({didDocument.service.length})
                                                </strong>
                                                <div className="mt-2">
                                                  {didDocument.service.map(
                                                    (service: any, index: number) => {
                                                      const isDIDComm =
                                                        service.type === 'DIDCommMessaging' ||
                                                        (Array.isArray(service.type) &&
                                                          service.type.includes(
                                                            'DIDCommMessaging'
                                                          ));
                                                      return (
                                                        <div
                                                          key={index}
                                                          className={`mb-3 pb-2 ${index < didDocument.service.length - 1 ? 'border-bottom' : ''}`}
                                                        >
                                                          <div
                                                            className="row"
                                                            style={{ fontSize: '0.875rem' }}
                                                          >
                                                            <div className="col-sm-3 text-muted small">
                                                              ID:
                                                            </div>
                                                            <div className="col-sm-9">
                                                              <code style={{ fontSize: '0.7rem' }}>
                                                                {service.id}
                                                              </code>
                                                            </div>
                                                          </div>
                                                          <div
                                                            className="row mt-1"
                                                            style={{ fontSize: '0.875rem' }}
                                                          >
                                                            <div className="col-sm-3 text-muted small">
                                                              Type:
                                                            </div>
                                                            <div className="col-sm-9">
                                                              <span
                                                                className={`badge ${isDIDComm ? 'text-bg-success' : 'text-bg-secondary'}`}
                                                                style={{ fontSize: '0.7rem' }}
                                                              >
                                                                {Array.isArray(service.type)
                                                                  ? service.type.join(', ')
                                                                  : service.type}
                                                              </span>
                                                              {isDIDComm && (
                                                                <span className="ms-2 text-success small">
                                                                  <i className="fas fa-check-circle"></i>{' '}
                                                                  Mediator Compatible
                                                                </span>
                                                              )}
                                                            </div>
                                                          </div>
                                                          {service.serviceEndpoint && (
                                                            <div
                                                              className="row mt-1"
                                                              style={{ fontSize: '0.875rem' }}
                                                            >
                                                              <div className="col-sm-3 text-muted small">
                                                                Endpoint:
                                                              </div>
                                                              <div className="col-sm-9">
                                                                {typeof service.serviceEndpoint ===
                                                                'string' ? (
                                                                  <code
                                                                    style={{ fontSize: '0.7rem' }}
                                                                  >
                                                                    {service.serviceEndpoint}
                                                                  </code>
                                                                ) : (
                                                                  <details>
                                                                    <summary
                                                                      className="cursor-pointer text-primary"
                                                                      style={{
                                                                        cursor: 'pointer',
                                                                        fontSize: '0.7rem',
                                                                      }}
                                                                    >
                                                                      View endpoint details
                                                                    </summary>
                                                                    <pre
                                                                      className="mt-1 p-2 bg-white border rounded"
                                                                      style={{
                                                                        fontSize: '0.65rem',
                                                                      }}
                                                                    >
                                                                      {JSON.stringify(
                                                                        service.serviceEndpoint,
                                                                        null,
                                                                        2
                                                                      )}
                                                                    </pre>
                                                                  </details>
                                                                )}
                                                              </div>
                                                            </div>
                                                          )}
                                                        </div>
                                                      );
                                                    }
                                                  )}
                                                </div>
                                              </div>
                                            )}

                                          {/* Verification Methods */}
                                          {didDocument.verificationMethod &&
                                            didDocument.verificationMethod.length > 0 && (
                                              <div className="mb-3">
                                                <strong className="text-muted small">
                                                  Verification Methods (
                                                  {didDocument.verificationMethod.length})
                                                </strong>
                                                <div className="mt-2">
                                                  {didDocument.verificationMethod.map(
                                                    (method: any, index: number) => (
                                                      <div
                                                        key={index}
                                                        className={`mb-3 pb-2 ${index < didDocument.verificationMethod.length - 1 ? 'border-bottom' : ''}`}
                                                      >
                                                        <div
                                                          className="row"
                                                          style={{ fontSize: '0.875rem' }}
                                                        >
                                                          <div className="col-sm-3 text-muted small">
                                                            ID:
                                                          </div>
                                                          <div className="col-sm-9">
                                                            <code style={{ fontSize: '0.7rem' }}>
                                                              {method.id}
                                                            </code>
                                                          </div>
                                                        </div>
                                                        <div
                                                          className="row mt-1"
                                                          style={{ fontSize: '0.875rem' }}
                                                        >
                                                          <div className="col-sm-3 text-muted small">
                                                            Type:
                                                          </div>
                                                          <div className="col-sm-9">
                                                            <span
                                                              className="badge text-bg-primary"
                                                              style={{ fontSize: '0.7rem' }}
                                                            >
                                                              {method.type}
                                                            </span>
                                                          </div>
                                                        </div>
                                                        {method.controller && (
                                                          <div
                                                            className="row mt-1"
                                                            style={{ fontSize: '0.875rem' }}
                                                          >
                                                            <div className="col-sm-3 text-muted small">
                                                              Controller:
                                                            </div>
                                                            <div className="col-sm-9">
                                                              <code style={{ fontSize: '0.7rem' }}>
                                                                {method.controller}
                                                              </code>
                                                            </div>
                                                          </div>
                                                        )}
                                                        {method.publicKeyJwk && (
                                                          <div
                                                            className="row mt-1"
                                                            style={{ fontSize: '0.875rem' }}
                                                          >
                                                            <div className="col-sm-3 text-muted small">
                                                              Public Key:
                                                            </div>
                                                            <div className="col-sm-9">
                                                              <details>
                                                                <summary
                                                                  className="cursor-pointer text-primary"
                                                                  style={{
                                                                    cursor: 'pointer',
                                                                    fontSize: '0.7rem',
                                                                  }}
                                                                >
                                                                  View JWK
                                                                </summary>
                                                                <pre
                                                                  className="mt-1 p-2 bg-white border rounded"
                                                                  style={{ fontSize: '0.65rem' }}
                                                                >
                                                                  {JSON.stringify(
                                                                    method.publicKeyJwk,
                                                                    null,
                                                                    2
                                                                  )}
                                                                </pre>
                                                              </details>
                                                            </div>
                                                          </div>
                                                        )}
                                                      </div>
                                                    )
                                                  )}
                                                </div>
                                              </div>
                                            )}

                                          {/* Full DID Document */}
                                          <div>
                                            <strong className="text-muted small">
                                              Full DID Document
                                            </strong>
                                            <details className="mt-2">
                                              <summary
                                                className="cursor-pointer text-primary"
                                                style={{ cursor: 'pointer', fontSize: '0.875rem' }}
                                              >
                                                View full DID document
                                              </summary>
                                              <pre
                                                className="mt-2 p-2 bg-white border rounded"
                                                style={{
                                                  fontSize: '0.7rem',
                                                  maxHeight: '300px',
                                                  overflow: 'auto',
                                                }}
                                              >
                                                {JSON.stringify(didDocument, null, 2)}
                                              </pre>
                                            </details>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default MediatorsPage;
