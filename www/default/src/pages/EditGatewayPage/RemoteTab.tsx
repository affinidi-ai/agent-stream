import React from 'react';

interface RemoteChannel {
  config_id: string;
  name: string;
  description?: string;
  listen_address: string;
  protocol: string;
}

interface RemoteTabProps {
  remoteChannels: RemoteChannel[];
  loadingChannels: boolean;
  channelsError: string;
  fetchRemoteChannels: (forceRefresh: boolean) => void;
}

const RemoteTab: React.FC<RemoteTabProps> = ({
  remoteChannels,
  loadingChannels,
  channelsError,
  fetchRemoteChannels,
}) => {
  return (
    <>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-network-wired"></i> Available Channels from Remote Gateway{' '}
              <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
                {remoteChannels.length}
              </span>
            </h6>
            <button
              className="btn btn-sm btn-outline-primary"
              onClick={() => fetchRemoteChannels(true)}
              disabled={loadingChannels}
            >
              <i className={`fas ${loadingChannels ? 'fa-spinner fa-spin' : 'fa-sync-alt'}`}></i>
              {loadingChannels ? ' Refreshing...' : ' Refresh'}
            </button>
          </div>
        </div>
        <div className="card-body">
          {channelsError && (
            <div className="alert alert-warning" role="alert">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {channelsError}
            </div>
          )}

          {loadingChannels && !remoteChannels.length ? (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden"></span>
              </div>
              <p className="text-muted mt-2">Querying remote gateway for available channels...</p>
            </div>
          ) : remoteChannels.length === 0 ? (
            <div className="alert alert-info mb-0">
              <i className="fas fa-info-circle me-2"></i>
              No channels available from this gateway. Click "Refresh Channels" to query the remote
              gateway.
            </div>
          ) : (
            <>
              <p className="text-muted mb-3">
                <i className="fas fa-info-circle me-2"></i> This Gateway exposes{' '}
                <strong>{remoteChannels.length}</strong> channel
                {remoteChannels.length !== 1 ? 's' : ''}
                that can be used for routing requests.
              </p>
              <div className="table-responsive">
                <table className="table table-sm table-hover">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>Protocol</th>
                      <th>Listen Address</th>
                      <th>Channel ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {remoteChannels.map(channel => (
                      <tr key={channel.config_id}>
                        <td>
                          <strong>{channel.name}</strong>
                        </td>
                        <td>
                          <small className="text-muted">{channel.description || '-'}</small>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              channel.protocol === 'a2a'
                                ? 'text-bg-primary'
                                : channel.protocol === 'mcp'
                                  ? 'text-bg-success'
                                  : 'text-bg-secondary'
                            }`}
                          >
                            {channel.protocol.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <code style={{ fontSize: '0.85rem' }}>{channel.listen_address}</code>
                        </td>
                        <td>
                          <code className="text-muted" style={{ fontSize: '0.75rem' }}>
                            {channel.config_id}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="mt-3 pt-3 border-top">
                <small className="text-muted">
                  <i className="fas fa-clock me-2"></i> Channel information is cached - click
                  "Refresh Channels" to get the latest list of channels.
                </small>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default RemoteTab;
