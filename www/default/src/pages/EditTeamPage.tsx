import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { usePermissions } from '../context/PermissionsContext';
import TeamForm from './EditTeamPage/TeamForm';
import { EMPTY_TEAM, type Team, type TeamUsageReport } from './EditTeamPage/teamHelpers';
import { type Member } from './EditMemberPage/memberHelpers';

const EditTeamPage: React.FC = () => {
  const navigate = useNavigate();
  const { teamId } = useParams<{ teamId: string }>();
  const isNew = !teamId;
  const { hasPermission } = usePermissions();
  const canDelete = hasPermission('teams.delete');

  const [team, setTeam] = useState<Team>(EMPTY_TEAM());
  const [registry, setRegistry] = useState<Member[]>([]);
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [usage, setUsage] = useState<TeamUsageReport | null>(null);
  const [usageLoading, setUsageLoading] = useState(false);

  const fetchTeam = useCallback(async () => {
    if (!teamId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Team>(`/teams/${encodeURIComponent(teamId)}`);
      setTeam(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load team');
    } finally {
      setLoading(false);
    }
  }, [teamId]);

  const fetchRegistry = useCallback(async () => {
    try {
      const response = await apiClient.get<Member[]>('/members');
      setRegistry(response.data);
    } catch {
      // The picker degrades to showing raw IDs if the registry is unavailable.
    }
  }, []);

  const fetchUsage = useCallback(async () => {
    if (!teamId) return;
    try {
      setUsageLoading(true);
      const response = await apiClient.get<TeamUsageReport>(
        `/teams/${encodeURIComponent(teamId)}/usage`
      );
      setUsage(response.data);
    } catch {
      // Usage is best-effort; a missing report should not block editing.
    } finally {
      setUsageLoading(false);
    }
  }, [teamId]);

  useEffect(() => {
    fetchRegistry();
    if (!isNew) {
      fetchTeam();
      fetchUsage();
    }
  }, [isNew, fetchTeam, fetchUsage, fetchRegistry]);

  const updateTeam = useCallback((patch: Partial<Team>) => {
    setTeam(prev => ({ ...prev, ...patch }));
  }, []);

  const addMember = useCallback((memberId: string) => {
    setTeam(prev =>
      prev.members.includes(memberId) ? prev : { ...prev, members: [...prev.members, memberId] }
    );
  }, []);

  const removeMember = useCallback((memberId: string) => {
    setTeam(prev => ({ ...prev, members: prev.members.filter(id => id !== memberId) }));
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      const payload: Team = {
        ...team,
        name: team.name.trim(),
        description: team.description?.trim() || null,
      };
      if (!payload.name) {
        setError('Team name is required');
        return;
      }
      try {
        setSaving(true);
        if (isNew) {
          await apiClient.post('/teams', payload);
        } else {
          await apiClient.put(`/teams/${encodeURIComponent(team.id)}`, payload);
        }
        navigate('/teams?tab=teams');
      } catch (err: any) {
        setError(err.message || 'Failed to save team');
      } finally {
        setSaving(false);
      }
    },
    [team, isNew, navigate]
  );

  const handleDelete = useCallback(async () => {
    if (!teamId) return;
    try {
      setSaving(true);
      await apiClient.delete(`/teams/${encodeURIComponent(teamId)}`);
      navigate('/teams?tab=teams');
    } catch (err: any) {
      setError(err.message || 'Failed to delete team');
    } finally {
      setSaving(false);
    }
  }, [teamId, navigate]);

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
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/teams?tab=teams')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>

      <TeamForm
        team={team}
        registry={registry}
        isNew={isNew}
        saving={saving}
        error={error}
        canDelete={canDelete}
        usage={usage}
        usageLoading={usageLoading}
        onSubmit={handleSubmit}
        onUpdate={updateTeam}
        onAddMember={addMember}
        onRemoveMember={removeMember}
        onDelete={handleDelete}
      />
    </div>
  );
};

export default EditTeamPage;
