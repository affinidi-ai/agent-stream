import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { usePageTitleContext } from '../context/PageTitleContext';
import { apiClient } from '../api';
import { ROUTES } from '../routes';
import { TopbarActionButton } from './shared/TopbarActionButton';
import { UserAvatar } from './shared/UserAvatar';

interface HeaderProps {
  onLogout?: () => void;
}

interface UserProfile {
  username: string;
  user_id: string;
  role: string;
  avatar_path?: string;
  first_name?: string;
  last_name?: string;
}

const Header: React.FC<HeaderProps> = ({ onLogout }) => {
  const { state, actions, getCurrentStats } = useApp();
  const { title: pageTitleOverride } = usePageTitleContext();
  const location = useLocation();
  const navigate = useNavigate();
  const [userProfile, setUserProfile] = React.useState<UserProfile | null>(null);
  const [showUserMenu, setShowUserMenu] = React.useState(false);
  const userMenuRef = React.useRef<HTMLLIElement>(null);
  const [fullscreen, setFullscreen] = React.useState(false);

  const toggleFullscreen = React.useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  }, []);

  React.useEffect(() => {
    const onChange = () => {
      const isFs = !!document.fullscreenElement;
      setFullscreen(isFs);
      document.documentElement.classList.toggle('app-fullscreen', isFs);
    };
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, []);

  React.useEffect(() => {
    document.documentElement.classList.toggle('dark-theme-fs', state.theme === 'dark');
  }, [state.theme]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const inInput =
        target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

      if (e.key === '[' && !inInput && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        actions.toggleSidebar();
        return;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [actions]);

  // Get unread count from dashboard stats (updated via delta sync)
  const stats = getCurrentStats();
  const unreadCount = stats?.unread_count || 0;

  // Close dropdown when clicking outside
  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };

    if (showUserMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showUserMenu]);

  // Fetch current user profile
  React.useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await apiClient.get('/profile');
        setUserProfile(response.data);
      } catch (error) {
        console.error('Failed to fetch user profile:', error);
      }
    };
    fetchProfile();
  }, []);

  const scrollToSection = (sectionId: string) => {
    // If we're not on dashboard, navigate there first
    if (location.pathname !== ROUTES.DASHBOARD) {
      navigate(ROUTES.DASHBOARD);
      setTimeout(() => {
        const element = document.querySelector(sectionId);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth' });
        }
      }, 100);
    } else {
      const element = document.querySelector(sectionId);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  const TITLE_PREFIX = '';

  const getPageTitle = () => {
    switch (location.pathname) {
      case ROUTES.DASHBOARD:
        return 'Dashboard';
      case '/connections':
        return `${TITLE_PREFIX}Connections`;
      case '/gateways':
        return `${TITLE_PREFIX}Linked Gateways`;
      case '/integrations':
        return `${TITLE_PREFIX}Integrations`;
      case '/mediators':
        return `${TITLE_PREFIX}Mediators`;
      case '/secrets':
        return `${TITLE_PREFIX}Secrets`;
      case '/credential-providers':
        return `${TITLE_PREFIX}Settings`;
      case '/credentials':
        return `${TITLE_PREFIX}Credentials`;
      case '/delegation-vault':
        return `${TITLE_PREFIX}Secrets`;
      case '/oidc-providers':
        return `${TITLE_PREFIX}OIDC Providers`;
      case '/llm-providers':
        return `${TITLE_PREFIX}Models`;
      case '/users':
        return `${TITLE_PREFIX}Users`;
      case '/profile':
        return `${TITLE_PREFIX}Profile`;
      case '/notifications':
        return `${TITLE_PREFIX}Notifications`;
      case '/tasks':
        return `${TITLE_PREFIX}Tasks`;
      case '/audit':
        return `${TITLE_PREFIX}Audit`;
      case '/governance':
        return `${TITLE_PREFIX}Governance Records`;
      case '/drift':
        return `${TITLE_PREFIX}LLM Drift`;
      case '/settings':
        return `${TITLE_PREFIX}Settings`;
      case '/logs':
        return `${TITLE_PREFIX}Logs`;
      case '/system-metrics':
        return `${TITLE_PREFIX}System`;
      case '/llm':
        return `${TITLE_PREFIX}LLM Surfaces`;
      case '/ide':
        return `${TITLE_PREFIX}IDE Surfaces`;
      case '/teams':
        return `${TITLE_PREFIX}Teams`;
      case '/prompts':
        return `${TITLE_PREFIX}Prompts`;
      case '/policies':
        return `${TITLE_PREFIX}Policies`;
      default:
        // Handle dynamic routes with pattern matching
        if (location.pathname.startsWith('/llm/')) {
          if (location.pathname === '/llm/new' || location.pathname.startsWith('/llm/new/')) {
            return `${TITLE_PREFIX}New LLM Surface`;
          }
          return `${TITLE_PREFIX}Edit LLM Surface`;
        }
        if (location.pathname.startsWith('/gateways/')) {
          if (location.pathname.endsWith('/publish')) {
            return `${TITLE_PREFIX}Publish Gateway`;
          }
          if (location.pathname.endsWith('/connect')) {
            return `${TITLE_PREFIX}Connect Gateway`;
          }
          return `${TITLE_PREFIX}Edit Gateway`;
        }
        if (location.pathname.startsWith('/mediators/')) {
          if (location.pathname.endsWith('/wizard')) {
            return `${TITLE_PREFIX}Add Mediator`;
          }
          return `${TITLE_PREFIX}Edit Mediator`;
        }
        if (location.pathname.startsWith('/users/')) {
          return `${TITLE_PREFIX}Edit User`;
        }
        if (location.pathname.startsWith('/notifications/')) {
          return `${TITLE_PREFIX}Edit Notification`;
        }
        if (location.pathname.startsWith('/credential-providers/')) {
          return `${TITLE_PREFIX}Edit Credential Provider`;
        }
        if (location.pathname.startsWith('/oidc-providers/')) {
          return `${TITLE_PREFIX}Edit OIDC Provider`;
        }
        if (location.pathname.startsWith('/llm-providers/')) {
          return `${TITLE_PREFIX}LLM Provider`;
        }
        if (location.pathname.startsWith('/apikeys/')) {
          return `${TITLE_PREFIX}API Key`;
        }
        if (location.pathname.startsWith('/ide/')) {
          if (location.pathname === '/ide/new') {
            return `${TITLE_PREFIX}New IDE Surface`;
          }
          return `${TITLE_PREFIX}Edit IDE Surface`;
        }
        if (location.pathname.startsWith('/prompts/')) {
          if (location.pathname === '/prompts/new') {
            return `${TITLE_PREFIX}New Prompt`;
          }
          return `${TITLE_PREFIX}Edit Prompt`;
        }
        if (location.pathname.startsWith('/teams/')) {
          if (location.pathname === '/teams/new') {
            return `${TITLE_PREFIX}New Team`;
          }
          return `${TITLE_PREFIX}Edit Team`;
        }
        if (location.pathname.startsWith('/members/')) {
          if (location.pathname === '/members/new') {
            return `${TITLE_PREFIX}New Member`;
          }
          return `${TITLE_PREFIX}Edit Member`;
        }
        if (
          location.pathname.startsWith('/policies') ||
          location.pathname.startsWith('/policy-definitions')
        ) {
          return `${TITLE_PREFIX}Policies`;
        }
        if (location.pathname === '/metrics/configure') {
          return `${TITLE_PREFIX}Metrics Configuration`;
        }
        if (location.pathname.startsWith('/access-tokens')) {
          return `${TITLE_PREFIX}Access Tokens`;
        }
        if (location.pathname.startsWith('/certificates')) {
          return `${TITLE_PREFIX}Certificates`;
        }
        return `${TITLE_PREFIX}Dashboard`;
    }
  };

  return (
    <nav
      className="navbar navbar-expand navbar-light topbar static-top shadow"
      style={{
        left: state.sidebarCollapsed ? '100px' : '220px',
        transition: 'left 250ms ease',
      }}
    >
      {/* Sidebar Toggle (Topbar) */}
      <button
        type="button"
        title="Toggle sidebar ( [ )"
        id="sidebarToggleTop"
        className="btn btn-link d-md-none rounded-circle me-3"
        onClick={actions.toggleSidebar}
      >
        <i className="fa fa-bars"></i>
      </button>

      {/* Topbar Title — pages can override via `usePageTitle(...)`;
          falls back to a route-derived default. Truncates with an
          ellipsis so long titles never push the right-side controls. */}
      <h1
        className="fw-semibold mb-0 me-auto ps-4 text-truncate"
        id="page-title"
        title={pageTitleOverride ?? getPageTitle()}
        style={{ minWidth: 0, maxWidth: 'calc(100vw - 520px)', fontSize: '18px' }}
      >
        {pageTitleOverride ?? getPageTitle()}
      </h1>

      {/* Topbar Navbar */}
      <ul
        className="navbar-nav ms-auto align-items-center"
        style={{ paddingLeft: '24px', paddingRight: '24px' }}
      >
        {/* Theme Toggle */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            id="themeToggle"
            title="Toggle Dark Mode"
            aria-label="Toggle dark mode"
            isActive={state.theme === 'dark'}
            iconClassName={`fas ${state.theme === 'dark' ? 'fa-sun' : 'fa-moon'}`}
            iconId="themeIcon"
            onClick={actions.toggleTheme}
          />
        </li>

        {/* Fullscreen Toggle */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            title={fullscreen ? 'Exit full screen (Esc)' : 'Enter full screen'}
            aria-label={fullscreen ? 'Exit full screen' : 'Enter full screen'}
            isActive={fullscreen}
            iconClassName={`fas fa-${fullscreen ? 'compress' : 'expand'}`}
            onClick={toggleFullscreen}
          />
        </li>

        {/* Notifications Badge */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            title="View notifications"
            aria-label="View notifications"
            isActive={location.pathname === '/notifications'}
            iconClassName="fas fa-bell"
            badge={unreadCount > 0 ? (unreadCount > 99 ? '99+' : unreadCount) : null}
            onClick={() => navigate('/notifications')}
          />
        </li>

        {/* User Avatar & Menu */}
        {onLogout && (
          <li className="nav-item dropdown topbar-action-item" ref={userMenuRef}>
            <TopbarActionButton
              appearance="avatar"
              shape="content"
              className="d-flex align-items-center gap-2"
              isOpen={showUserMenu}
              aria-haspopup="menu"
              aria-expanded={showUserMenu}
              onClick={() => setShowUserMenu(!showUserMenu)}
            >
              <UserAvatar
                alt="User avatar"
                src={userProfile?.avatar_path ? `/${userProfile.avatar_path}` : null}
                size="topbar"
                imageClassName="topbar-avatar-image"
                fallbackClassName="topbar-avatar-fallback d-flex align-items-center justify-content-center text-white fw-bold"
              />
              {userProfile && (
                <span className="topbar-user-name d-none d-lg-inline">
                  {userProfile.first_name || userProfile.username}
                </span>
              )}
            </TopbarActionButton>
            {showUserMenu && (
              <div
                className="dropdown-menu dropdown-menu-right shadow animated--grow-in show topbar-user-menu"
                style={{
                  position: 'absolute',
                  right: 0,
                  marginTop: '0.5rem',
                  minWidth: '200px',
                }}
              >
                <button
                  className="dropdown-item d-flex align-items-center lh-base topbar-user-menu-item"
                  onClick={() => {
                    setShowUserMenu(false);
                    navigate('/profile');
                  }}
                >
                  <i className="fas fa-user fa-sm fa-fw me-2 text-gray-400"></i>
                  Profile
                </button>
                <div className="dropdown-divider"></div>
                <button
                  className="dropdown-item d-flex align-items-center lh-base topbar-user-menu-item"
                  onClick={() => {
                    setShowUserMenu(false);
                    onLogout();
                  }}
                >
                  <i className="fas fa-sign-out-alt fa-sm fa-fw me-2 text-gray-400"></i>
                  Sign Out
                </button>
              </div>
            )}
          </li>
        )}
      </ul>
    </nav>
  );
};

export default Header;
