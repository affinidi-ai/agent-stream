import React from 'react';

interface CommitStepProps {
  channelConfig: any;
  onFinish: () => void;
  onBack: () => void;
  onConfigureChannel: () => void;
}

const CommitStep: React.FC<CommitStepProps> = ({
  channelConfig,
  onFinish,
  onBack,
  onConfigureChannel,
}) => {
  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="commit-screen">
          <div className="success-icon">
            <i className="fas fa-check-circle"></i>
          </div>

          <h2>Channel Created Successfully!</h2>

          <p>
            Your new channel <strong>{channelConfig?.name}</strong> has been created and is ready to
            use. The channel is now active and will start processing requests as they arrive on the
            listen endpoint. You can further customize the channel settings and extension rules as
            needed by editing the channel.
          </p>

          {/* Action Buttons */}
          <div className="mt-4">
            <button className="btn btn-primary me-3" onClick={onConfigureChannel}>
              <i className="fas fa-cog me-2"></i>
              Configure Channel
            </button>
            <button className="btn btn-outline-primary me-3" onClick={onFinish}>
              <i className="fas fa-list me-2"></i>
              List all channels
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommitStep;
