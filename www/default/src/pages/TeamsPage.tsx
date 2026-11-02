import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import SearchInput from '../components/shared/SearchInput';
import { usePermissions } from '../context/PermissionsContext';
import EnrolmentTab from './EnrolmentTab';
import MembersPage from './MembersPage';
import TeamsListPage from './TeamsListPage';

type TabKey = 'teams' | 'members' | 'enrolment';

const TeamsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { hasPermission } = usePermissions();
  const canViewMembers = hasPermission('members.view');
  const canViewEnrolment = hasPermission('enrolment.view');

  const requestedTab = (searchParams.get('tab') as TabKey) || 'teams';
  const tabAvailable = (tab: TabKey): boolean =>
    tab === 'teams' ||
    (tab === 'members' && canViewMembers) ||
    (tab === 'enrolment' && canViewEnrolment);
  const initialTab: TabKey = tabAvailable(requestedTab) ? requestedTab : 'teams';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);

  const [searchTerm, setSearchTerm] = useState('');
  const [membersCount, setMembersCount] = useState(0);
  const [teamsCount, setTeamsCount] = useState(0);

  const filterActive = searchTerm.trim().length > 0;
  const tabBadge = (count: number) =>
    filterActive ? (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    ) : null;

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter members and teams..."
            width="384px"
          />
        </div>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const next = (k as TabKey) || 'teams';
          setActiveTab(next);
          setSearchParams({ tab: next }, { replace: true });
        }}
        className="mb-4 custom-channel-tabs"
      >
        <Tab
          eventKey="teams"
          title={
            <>
              <i className="fas fa-users"></i> Teams {tabBadge(teamsCount)}
            </>
          }
        >
          <TeamsListPage searchTerm={searchTerm} onFilteredCountChange={setTeamsCount} />
        </Tab>
        {canViewMembers && (
          <Tab
            eventKey="members"
            title={
              <>
                <i className="fas fa-user-friends"></i> Members {tabBadge(membersCount)}
              </>
            }
          >
            <MembersPage searchTerm={searchTerm} onFilteredCountChange={setMembersCount} />
          </Tab>
        )}
        {canViewEnrolment && (
          <Tab
            eventKey="enrolment"
            title={
              <>
                <i className="fas fa-users-cog"></i> Enrolment
              </>
            }
          >
            <EnrolmentTab active={activeTab === 'enrolment'} />
          </Tab>
        )}
      </Tabs>
    </div>
  );
};

export default TeamsPage;
