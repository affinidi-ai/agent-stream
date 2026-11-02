import React from 'react';
import { formatDateTime } from '../../utils/stringUtils';
import { type Team } from './teamHelpers';

interface TeamDetailsTabProps {
  team: Team;
  isNew: boolean;
  onUpdate: (patch: Partial<Team>) => void;
}

const TeamDetailsTab: React.FC<TeamDetailsTabProps> = ({ team, isNew, onUpdate }) => (
  <>
    <div className="row">
      <div className="col-md-6 mb-3">
        <label className="form-label">Name</label>
        <input
          type="text"
          className="form-control"
          value={team.name}
          onChange={e => onUpdate({ name: e.target.value })}
          placeholder="Engineering"
        />
      </div>
      <div className="col-md-6 mb-3">
        <label className="form-label">Description</label>
        <input
          type="text"
          className="form-control"
          value={team.description ?? ''}
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
            value={formatDateTime(team.created_at, true)}
            disabled
            readOnly
          />
        </div>
        <div className="col-md-6 mb-3">
          <label className="form-label">Team ID</label>
          <input type="text" className="form-control" value={team.id} disabled readOnly />
          <small className="text-muted">
            Server-assigned identifier. Members are linked to this team by it.
          </small>
        </div>
      </div>
    )}

    <div className="form-check form-switch mb-3">
      <input
        className="form-check-input"
        type="checkbox"
        id="team-enabled"
        checked={team.status === 'enabled'}
        onChange={e => onUpdate({ status: e.target.checked ? 'enabled' : 'disabled' })}
      />
      <label className="form-check-label" htmlFor="team-enabled">
        Enabled (teams must be enabled to be counted at request time)
      </label>
    </div>
  </>
);

export default TeamDetailsTab;
