import React from 'react';
import ProtocolSelector from '../builder/ProtocolSelector';
import type { Protocol } from '../builder/elements/types';

interface StartStepProps {
  onProtocolSelect: (protocol: 'a2a' | 'mcp') => void;
}

const ONBOARD_PROTOCOLS: Protocol[] = ['a2a', 'mcp'];

const StartStep: React.FC<StartStepProps> = ({ onProtocolSelect }) => {
  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="welcome-screen">
          <h2>Welcome to Channel Onboarding</h2>
          <p>
            You're about to configure a new channel based on a payload coming from an agent. This
            wizard will guide you through capturing the payload, configuring the channel, and
            finalizing the setup.
          </p>
          <p>
            <strong>First, please select the protocol type for your new channel:</strong>
          </p>

          <ProtocolSelector
            options={ONBOARD_PROTOCOLS}
            value={null}
            onChange={p => {
              if (p === 'a2a' || p === 'mcp') onProtocolSelect(p);
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default StartStep;
