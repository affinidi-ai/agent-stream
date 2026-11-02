import React from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { type Member } from '../EditMemberPage/memberHelpers';
import TeamDetailsTab from './TeamDetailsTab';
import TeamLimitsTab from './TeamLimitsTab';
import TeamMembersEditor from './TeamMembersEditor';
import TeamUsageTab from './TeamUsageTab';
import { type Team, type TeamUsageReport } from './teamHelpers';

interface TeamFormProps {
  team: Team;
  registry: Member[];
  isNew: boolean;
  saving: boolean;
  error: string | null;
  canDelete: boolean;
  usage: TeamUsageReport | null;
  usageLoading: boolean;
  onSubmit: (e: React.FormEvent) => void;
  onUpdate: (patch: Partial<Team>) => void;
  onAddMember: (memberId: string) => void;
  onRemoveMember: (memberId: string) => void;
  onDelete: () => void;
}

const TeamForm: React.FC<TeamFormProps> = ({
  team,
  registry,
  isNew,
  saving,
  error,
  canDelete,
  usage,
  usageLoading,
  onSubmit,
  onUpdate,
  onAddMember,
  onRemoveMember,
  onDelete,
}) => (
  <form onSubmit={onSubmit}>
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-users"></i>{' '}
          {isNew ? 'New Team' : `Edit Team — ${team.name || team.id}`}
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
            <TeamDetailsTab team={team} isNew={isNew} onUpdate={onUpdate} />
          </Tab>
          <Tab eventKey="members" title="Members">
            <TeamMembersEditor
              members={team.members}
              registry={registry}
              onAdd={onAddMember}
              onRemove={onRemoveMember}
            />
          </Tab>
          <Tab eventKey="limits" title="Caps & Limits">
            <TeamLimitsTab team={team} onUpdate={onUpdate} />
          </Tab>
          <Tab eventKey="usage" title="Usage" disabled={isNew}>
            <TeamUsageTab teamId={team.id} usage={usage} usageLoading={usageLoading} />
          </Tab>
        </Tabs>

        <hr />

        <div className="d-flex justify-content-between align-items-center">
          {!isNew && canDelete && (
            <DeleteButton
              onDelete={onDelete}
              title="Delete this team"
              disabled={saving}
              variant="danger"
            >
              Delete Team
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

export default TeamForm;
