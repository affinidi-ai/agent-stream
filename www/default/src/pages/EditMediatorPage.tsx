import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';

interface MediatorForm {
  name: string;
  description: string;
  did: string;
  status: 'active' | 'disabled';
}

const EditMediatorPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = id !== undefined && id !== 'new';

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<MediatorForm>({
    name: '',
    description: '',
    did: '',
    status: 'active',
  });
  const [error, setError] = useState<string>('');

  useEffect(() => {
    if (isEditMode && id) {
      fetchMediator();
    }
  }, [id, isEditMode]);

  const fetchMediator = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/mediators/${id}`);
      setForm({
        name: response.data.name,
        description: response.data.description,
        did: response.data.did,
        status: response.data.status,
      });
    } catch (error: any) {
      setError(error.message || 'Failed to load mediator');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');

      if (!form.name || !form.did) {
        setError('Name and DID are required');
        return;
      }

      try {
        setSaving(true);
        if (isEditMode) {
          await apiClient.put(`/mediators/${id}`, form);
        } else {
          await apiClient.post('/mediators', form);
        }
        navigate('/connections?tab=mediators');
      } catch (error: any) {
        setError(error.message || 'Failed to save mediator');
      } finally {
        setSaving(false);
      }
    },
    [form, isEditMode, id, navigate]
  );

  const handleDelete = async () => {
    try {
      setSaving(true);
      await apiClient.delete(`/mediators/${id}`);
      navigate('/connections?tab=mediators');
    } catch (error: any) {
      setError(error.message || 'Failed to delete mediator');
    } finally {
      setSaving(false);
    }
  };

  // Add keyboard shortcut support for save (Ctrl+S / Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      // Check for Ctrl+S (Windows/Linux) or Cmd+S (Mac)
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault(); // Prevent browser's default save behavior

        // Only trigger save if not currently saving and form is valid
        if (!saving && form.name && form.did) {
          handleSubmit(event as any);
        }
      }
    };

    // Add event listener when component mounts
    document.addEventListener('keydown', handleKeyboardSave);

    // Cleanup: remove event listener when component unmounts
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [saving, form.name, form.did, handleSubmit]);

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/connections?tab=mediators')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className={`fas fa-${isEditMode ? 'edit' : 'plus'}`}></i>{' '}
            {isEditMode ? `Edit Mediator: ${form.name}` : 'Add New DIDComm v2.1 Mediator'}
            {form.status === 'disabled' && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off"></i> DISABLED
              </span>
            )}
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="name" className="form-label">
                Name *
              </label>
              <input
                type="text"
                className="form-control"
                id="name"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                required
                autoFocus={!isEditMode}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="description" className="form-label">
                Description
              </label>
              <input
                className="form-control"
                id="description"
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="did" className="form-label">
                DID *
              </label>
              <input
                type="text"
                className="form-control"
                id="did"
                value={form.did}
                onChange={e => setForm({ ...form, did: e.target.value })}
                required
                disabled={isEditMode}
                readOnly={isEditMode}
              />
              {isEditMode && (
                <small className="form-text text-muted">
                  DID cannot be changed. To use a different DID, create a new mediator using the
                  wizard.
                </small>
              )}
            </div>
            <div className="mb-4">
              <div className="form-check">
                <input
                  type="checkbox"
                  className="form-check-input"
                  id="status"
                  checked={form.status === 'active'}
                  onChange={e =>
                    setForm({ ...form, status: e.target.checked ? 'active' : 'disabled' })
                  }
                />
                <label className="form-check-label" htmlFor="status">
                  <strong>Mediator Enabled</strong> - When unchecked, the mediator will be disabled
                  {form.status === 'disabled' && (
                    <span className="badge text-bg-warning ms-2">
                      <i className="fas fa-power-off"></i> DISABLED
                    </span>
                  )}
                </label>
              </div>
            </div>
            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    {isEditMode ? 'Saving...' : 'Creating...'}
                  </>
                ) : (
                  <>
                    <i className={`fas fa-${isEditMode ? 'save' : 'plus'} me-2`}></i>
                    {isEditMode ? ' Save' : ' Create'}
                  </>
                )}
              </button>
              {isEditMode && (
                <DeleteButton onDelete={handleDelete} disabled={saving} variant="danger">
                  Delete
                </DeleteButton>
              )}
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/connections?tab=mediators')}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditMediatorPage;
