import React, { useEffect, useState } from 'react';
import { getRuntimeVariablesForCategories } from '../../utils/runtimeVariables';

const UserIntegrationsOverviewTab: React.FC = () => {
  const [variables, setVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchVariables = async () => {
      try {
        setLoading(true);
        // Fetch both general and user-specific variables
        const vars = await getRuntimeVariablesForCategories(['general', 'user']);
        setVariables(vars);
      } catch (error) {
        console.error('Failed to fetch runtime variables:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchVariables();
  }, []);

  return (
    <div className="container-fluid p-0">
      <div className="row mt-4">
        <div className="col-12">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle"></i> About User Integrations
              </h6>
            </div>
            <div className="card-body">
              <p className="mb-3">
                Configure integrations that will be triggered for user management events. These
                integrations allow you to connect external systems and services to be notified when
                user-related actions occur.
              </p>

              <h6 className="font-weight-bold mt-4 mb-2">Supported Events:</h6>
              <ul className="mb-3">
                <li>
                  <strong>User Created (user.created):</strong> Triggered when a new user completes
                  registration
                </li>
                <li>
                  <strong>User Approved (user.approved):</strong> Triggered when an administrator
                  approves a pending user account
                </li>
                <li>
                  <strong>User Updated (user.updated):</strong> Triggered when user details (role,
                  status, profile) are modified
                </li>
                <li>
                  <strong>User Deleted (user.deleted):</strong> Triggered when a user account is
                  permanently deleted
                </li>
                <li>
                  <strong>User Login (user.login):</strong> Triggered when a user successfully logs
                  in via passkey authentication
                </li>
              </ul>

              <div className="alert alert-warning">
                <i className="fas fa-info-circle me-2"></i>
                <strong>Integration Triggers:</strong> User integrations are automatically invoked
                for the above events. Ensure your integrations are configured with the{' '}
                <strong>"user"</strong> or <strong>"general"</strong> category to receive these
                events.
              </div>

              <h6 className="font-weight-bold mt-4 mb-2">Available Runtime Variables:</h6>
              {loading ? (
                <div className="text-center py-3">
                  <i className="fas fa-spinner fa-spin"></i> Loading variables...
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-sm table-bordered">
                    <thead>
                      <tr>
                        <th>Variable</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(variables).map(([name, info]) => (
                        <tr key={name}>
                          <td>
                            <code>{`\${${name}}`}</code>
                          </td>
                          <td>{info.description}</td>
                        </tr>
                      ))}
                      {Object.keys(variables).length === 0 && (
                        <tr>
                          <td colSpan={2} className="text-center text-muted">
                            No variables available
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="alert alert-info mt-4">
                <i className="fas fa-lightbulb me-2"></i>
                <strong>Tip:</strong> Use the <strong>Integrations</strong> tab to configure
                integrations and map runtime variables to their templates. These variables will be
                automatically populated when events occur.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserIntegrationsOverviewTab;
