import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { usePermissions } from '../context/PermissionsContext';
import MemberForm from './EditMemberPage/MemberForm';
import {
  EMPTY_MEMBER,
  identifierValue,
  makeIdentifier,
  memberIdentifiers,
  type Member,
} from './EditMemberPage/memberHelpers';

const EditMemberPage: React.FC = () => {
  const navigate = useNavigate();
  const { memberId } = useParams<{ memberId: string }>();
  const isNew = !memberId;
  const { hasPermission } = usePermissions();
  const canDelete = hasPermission('members.delete');

  const [member, setMember] = useState<Member>(EMPTY_MEMBER());
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMember = useCallback(async () => {
    if (!memberId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Member>(`/members/${encodeURIComponent(memberId)}`);
      const data = response.data;
      // Normalise legacy single-identifier payloads into the array shape.
      const normalized: Member = Array.isArray(data.identifiers)
        ? data
        : {
            ...data,
            identifiers: memberIdentifiers(data),
          };
      setMember(normalized);
    } catch (err: any) {
      setError(err.message || 'Failed to load member');
    } finally {
      setLoading(false);
    }
  }, [memberId]);

  useEffect(() => {
    if (!isNew) fetchMember();
  }, [isNew, fetchMember]);

  const updateMember = useCallback((patch: Partial<Member>) => {
    setMember(prev => ({ ...prev, ...patch }));
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      const cleaned = (member.identifiers ?? [])
        .map(identifier => makeIdentifier(identifier.kind, identifierValue(identifier).trim()))
        .filter(identifier => identifierValue(identifier).length > 0);
      if (cleaned.length === 0) {
        setError('At least one identity value is required');
        return;
      }
      const payload: Member = {
        ...member,
        name: member.name?.trim() || null,
        description: member.description?.trim() || null,
        identifiers: cleaned,
      };
      try {
        setSaving(true);
        if (isNew) {
          await apiClient.post('/members', payload);
        } else {
          await apiClient.put(`/members/${encodeURIComponent(member.id)}`, payload);
        }
        navigate('/teams?tab=members');
      } catch (err: any) {
        setError(err.message || 'Failed to save member');
      } finally {
        setSaving(false);
      }
    },
    [member, isNew, navigate]
  );

  const handleDelete = useCallback(async () => {
    if (!memberId) return;
    try {
      setSaving(true);
      await apiClient.delete(`/members/${encodeURIComponent(memberId)}`);
      navigate('/teams?tab=members');
    } catch (err: any) {
      setError(err.message || 'Failed to delete member');
    } finally {
      setSaving(false);
    }
  }, [memberId, navigate]);

  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!saving) handleSubmit(event as any);
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => document.removeEventListener('keydown', handleKeyboardSave);
  }, [handleSubmit, saving]);

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/teams?tab=members')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>

      <MemberForm
        member={member}
        isNew={isNew}
        saving={saving}
        error={error}
        canDelete={canDelete}
        onSubmit={handleSubmit}
        onUpdate={updateMember}
        onDelete={handleDelete}
      />
    </div>
  );
};

export default EditMemberPage;
