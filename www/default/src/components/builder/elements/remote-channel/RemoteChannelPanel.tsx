import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';

/**
 * Sidebar panel for the synthesised `remote-channel` external actor.
 *
 * The panel describes what the element represents — the channel name is
 * already surfaced via the default Name field above.
 */
const RemoteChannelPanel: React.FC<ConfigPanelProps> = () => {
  return (
    <div className="config-section">
      <Form.Text className="text-muted" style={{ fontSize: '11px' }}>
        Represents the channel on the remote gateway that this <code>fabric://</code> route targets.
        The display name above is pre-filled with the channel&apos;s name on the remote gateway —
        edit it to give it a meaningful name on this surface.
      </Form.Text>
    </div>
  );
};

export default RemoteChannelPanel;
