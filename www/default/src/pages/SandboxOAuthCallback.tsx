import React, { useEffect } from 'react';

import { completeSandboxCallbackInPopup } from '../utils/sandboxAuth';

/**
 * Popup landing page for the sandbox OAuth (PKCE) flow. It runs the
 * authorization-code exchange entirely client-side, posts the result back to
 * the opener window, and closes itself. Rendered outside the dashboard auth
 * gate so it works even before the session check completes.
 */
const SandboxOAuthCallback: React.FC = () => {
  useEffect(() => {
    void completeSandboxCallbackInPopup();
  }, []);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        fontFamily: 'system-ui, sans-serif',
        color: '#6b7280',
      }}
    >
      <div className="spinner-border text-primary" role="status" />
      <div>Completing sign-in… you can close this window.</div>
    </div>
  );
};

export default SandboxOAuthCallback;
