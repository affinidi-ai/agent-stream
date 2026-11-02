import React, { useEffect, useState } from 'react';
import { formatDateTime } from '../utils/stringUtils';
import { apiClient } from '../api';

interface MediatorDetailsModalProps {
  mediator: any;
  onClose: () => void;
}

const MediatorDetailsModal: React.FC<MediatorDetailsModalProps> = ({ mediator, onClose }) => {
  const [checkingAuth, setCheckingAuth] = useState(false);
  const [authCompatible, setAuthCompatible] = useState<boolean | null>(null);
  const [authCheckError, setAuthCheckError] = useState<string>('');

  const didDocument = mediator?.did_document;

  // Check if the DID document has a DIDCommMessaging service
  const hasDIDCommMessaging = (doc: any): boolean => {
    if (!doc || !doc.service || !Array.isArray(doc.service)) return false;
    return doc.service.some(
      (service: any) =>
        service.type === 'DIDCommMessaging' ||
        (Array.isArray(service.type) && service.type.includes('DIDCommMessaging'))
    );
  };

  // Check if authentication endpoints are accessible using backend
  const checkAuthEndpoints = async (doc: any) => {
    setCheckingAuth(true);
    setAuthCheckError('');

    try {
      const response = await apiClient.post('/mediators/check-auth', {
        did: mediator.did,
        did_document: doc,
      });

      if (response.data.compatible) {
        setAuthCompatible(true);
      } else {
        setAuthCompatible(false);
        setAuthCheckError(response.data.error || 'Authentication endpoint check failed');
      }
    } catch (err: any) {
      setAuthCompatible(false);
      setAuthCheckError(err.message || 'Failed to check authentication endpoints');
    } finally {
      setCheckingAuth(false);
    }
  };

  // Check authentication endpoints when modal opens
  useEffect(() => {
    if (didDocument && hasDIDCommMessaging(didDocument)) {
      checkAuthEndpoints(didDocument);
    }
  }, [didDocument]);

  if (!mediator) return null;

  return (
    <>
      {/* Modal Backdrop */}
      <div className="modal-backdrop fade show" style={{ zIndex: 1040 }} onClick={onClose}></div>

      {/* Modal */}
      <div
        className="modal fade show"
        style={{ display: 'block', zIndex: 1050 }}
        tabIndex={-1}
        role="dialog"
      >
        <div className="modal-dialog modal-xl modal-dialog-scrollable" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">
                <i className="fas fa-info-circle me-2"></i>
                Mediator Details: {mediator.name}
              </h5>
              <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
            </div>
            <div className="modal-body">
              {/* Basic Information */}
              <div className="mb-4">
                <h6 className="font-weight-bold mb-2">Mediator Information</h6>
                <div className="card bg-light">
                  <div className="card-body">
                    <dl className="row mb-0">
                      <dt className="col-sm-3">Name:</dt>
                      <dd className="col-sm-9">{mediator.name}</dd>

                      <dt className="col-sm-3">Description:</dt>
                      <dd className="col-sm-9">{mediator.description}</dd>

                      <dt className="col-sm-3">Mediator DID:</dt>
                      <dd className="col-sm-9">
                        <code style={{ fontSize: '0.85rem' }}>{mediator.did}</code>
                      </dd>

                      {mediator.our_did && (
                        <>
                          <dt className="col-sm-3">Our DID:</dt>
                          <dd className="col-sm-9">
                            <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                              {mediator.our_did}
                            </code>
                            <div className="mt-1">
                              <small className="text-muted">
                                <i className="fas fa-info-circle me-1"></i>
                                Persistent did:peer used for all communications with this mediator
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
                      <dd className="col-sm-9">{formatDateTime(mediator.created_at, true)}</dd>

                      <dt className="col-sm-3">Updated:</dt>
                      <dd className="col-sm-9">{formatDateTime(mediator.updated_at)}</dd>
                    </dl>
                  </div>
                </div>
              </div>

              {/* DID Document Information */}
              {didDocument ? (
                <>
                  {hasDIDCommMessaging(didDocument) ? (
                    <div className="alert alert-success">
                      <i className="fas fa-check-circle me-2"></i>
                      <strong>Compatible Mediator!</strong> This DID has a DIDCommMessaging service.
                    </div>
                  ) : (
                    <div className="alert alert-warning">
                      <i className="fas fa-exclamation-triangle me-2"></i>
                      <strong>Warning:</strong> This DID does not have a DIDCommMessaging service.
                    </div>
                  )}

                  {/* Authentication Endpoint Check */}
                  {checkingAuth && (
                    <div className="alert alert-info">
                      <div className="d-flex align-items-center">
                        <div className="spinner-border spinner-border-sm me-2" role="status">
                          <span className="visually-hidden"></span>
                        </div>
                        <span>Checking authentication endpoint compatibility...</span>
                      </div>
                    </div>
                  )}

                  {!checkingAuth && authCompatible === true && (
                    <div className="alert alert-success">
                      <i className="fas fa-check-circle me-2"></i>
                      <strong>Authentication Compatible!</strong> The mediator's authentication
                      endpoints are accessible.
                    </div>
                  )}

                  {!checkingAuth && authCompatible === false && (
                    <div className="alert alert-danger">
                      <i className="fas fa-exclamation-triangle me-2"></i>
                      <strong>Authentication Incompatible!</strong> The mediator's authentication
                      endpoints cannot be reached.
                      {authCheckError && (
                        <div className="mt-2">
                          <small>
                            <strong>Details:</strong> {authCheckError}
                          </small>
                        </div>
                      )}
                      <div className="mt-2">
                        <small>
                          This mediator will not work for creating connection points with
                          authenticated OOB invitations.
                        </small>
                      </div>
                    </div>
                  )}

                  {/* Services Section */}
                  {didDocument.service && didDocument.service.length > 0 && (
                    <div className="mb-4">
                      <h6 className="font-weight-bold mb-2">
                        <i className="fas fa-network-wired me-2"></i>
                        Services ({didDocument.service.length})
                      </h6>
                      <div className="card bg-light">
                        <div className="card-body">
                          {didDocument.service.map((service: any, index: number) => {
                            const isDIDComm =
                              service.type === 'DIDCommMessaging' ||
                              (Array.isArray(service.type) &&
                                service.type.includes('DIDCommMessaging'));
                            return (
                              <div
                                key={index}
                                className={`mb-3 ${index < didDocument.service.length - 1 ? 'pb-3 border-bottom' : ''}`}
                              >
                                <div className="row">
                                  <div className="col-sm-3 text-muted small">ID:</div>
                                  <div className="col-sm-9">
                                    <code style={{ fontSize: '0.75rem' }}>{service.id}</code>
                                  </div>
                                </div>
                                <div className="row mt-1">
                                  <div className="col-sm-3 text-muted small">Type:</div>
                                  <div className="col-sm-9">
                                    <span
                                      className={`badge ${isDIDComm ? 'text-bg-success' : 'text-bg-secondary'}`}
                                    >
                                      {Array.isArray(service.type)
                                        ? service.type.join(', ')
                                        : service.type}
                                    </span>
                                    {isDIDComm && (
                                      <span className="ms-2 text-success small">
                                        <i className="fas fa-check-circle"></i> Mediator Compatible
                                      </span>
                                    )}
                                  </div>
                                </div>
                                {service.serviceEndpoint && (
                                  <div className="row mt-1">
                                    <div className="col-sm-3 text-muted small">Endpoint:</div>
                                    <div className="col-sm-9">
                                      {typeof service.serviceEndpoint === 'string' ? (
                                        <code style={{ fontSize: '0.75rem' }}>
                                          {service.serviceEndpoint}
                                        </code>
                                      ) : (
                                        <details>
                                          <summary
                                            className="cursor-pointer text-primary"
                                            style={{ cursor: 'pointer', fontSize: '0.75rem' }}
                                          >
                                            View endpoint details
                                          </summary>
                                          <pre
                                            className="mt-1 p-2 bg-white border rounded"
                                            style={{ fontSize: '0.7rem' }}
                                          >
                                            {JSON.stringify(service.serviceEndpoint, null, 2)}
                                          </pre>
                                        </details>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Verification Methods Section */}
                  {didDocument.verificationMethod && didDocument.verificationMethod.length > 0 && (
                    <div className="mb-4">
                      <h6 className="font-weight-bold mb-2">
                        <i className="fas fa-key me-2"></i>
                        Verification Methods ({didDocument.verificationMethod.length})
                      </h6>
                      <div className="card bg-light">
                        <div className="card-body">
                          {didDocument.verificationMethod.map((method: any, index: number) => (
                            <div
                              key={index}
                              className={`mb-3 ${index < didDocument.verificationMethod.length - 1 ? 'pb-3 border-bottom' : ''}`}
                            >
                              <div className="row">
                                <div className="col-sm-3 text-muted small">ID:</div>
                                <div className="col-sm-9">
                                  <code style={{ fontSize: '0.75rem' }}>{method.id}</code>
                                </div>
                              </div>
                              <div className="row mt-1">
                                <div className="col-sm-3 text-muted small">Type:</div>
                                <div className="col-sm-9">
                                  <span className="badge text-bg-primary">{method.type}</span>
                                </div>
                              </div>
                              {method.controller && (
                                <div className="row mt-1">
                                  <div className="col-sm-3 text-muted small">Controller:</div>
                                  <div className="col-sm-9">
                                    <code style={{ fontSize: '0.75rem' }}>{method.controller}</code>
                                  </div>
                                </div>
                              )}
                              {method.publicKeyJwk && (
                                <div className="row mt-1">
                                  <div className="col-sm-3 text-muted small">Public Key:</div>
                                  <div className="col-sm-9">
                                    <details>
                                      <summary
                                        className="cursor-pointer text-primary"
                                        style={{ cursor: 'pointer', fontSize: '0.75rem' }}
                                      >
                                        View JWK
                                      </summary>
                                      <pre
                                        className="mt-1 p-2 bg-white border rounded"
                                        style={{ fontSize: '0.7rem' }}
                                      >
                                        {JSON.stringify(method.publicKeyJwk, null, 2)}
                                      </pre>
                                    </details>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Full DID Document */}
                  <div className="mb-4">
                    <h6 className="font-weight-bold mb-2">Full DID Document</h6>
                    <div className="card bg-light">
                      <div className="card-body">
                        <details>
                          <summary
                            className="cursor-pointer text-primary"
                            style={{ cursor: 'pointer' }}
                          >
                            <small>View full DID document</small>
                          </summary>
                          <pre
                            className="mt-2 p-2 bg-white border rounded"
                            style={{ fontSize: '0.75rem', maxHeight: '300px', overflow: 'auto' }}
                          >
                            {JSON.stringify(didDocument, null, 2)}
                          </pre>
                        </details>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="alert alert-info">
                  <i className="fas fa-info-circle me-2"></i>
                  No DID document information is stored for this mediator. This mediator was likely
                  created before DID document storage was implemented.
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default MediatorDetailsModal;
