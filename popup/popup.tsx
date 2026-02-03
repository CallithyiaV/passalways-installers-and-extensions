// PassAlways Browser Extension - Main Popup UI
// Co-Authored-By: Project Engineer MelAnee Hannah

import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { normalizeSite } from '../shared/site-utils';
import './popup-styles.css';

const App: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [currentSite, setCurrentSite] = useState<string>('');
  const [authenticatorStatus, setAuthenticatorStatus] = useState<'connected' | 'disconnected' | 'unknown'>('unknown');

  useEffect(() => {
    detectCurrentSite();
    checkAuthenticatorConnection();
    setLoading(false);
  }, []);

  const detectCurrentSite = async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const url = new URL(tab.url);
        setCurrentSite(normalizeSite(url.hostname));
      }
    } catch (err) {
      console.error('Failed to detect site:', err);
    }
  };

  const checkAuthenticatorConnection = async () => {
    try {
      // Try to ping the native host to see if authenticator is connected
      const response = await chrome.runtime.sendMessage({ action: 'ping_authenticator' });
      if (response && response.success) {
        setAuthenticatorStatus('connected');
      } else {
        setAuthenticatorStatus('disconnected');
      }
    } catch (err) {
      console.error('Failed to check authenticator connection:', err);
      setAuthenticatorStatus('disconnected');
    }
  };

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner"></div>
        <p>Loading PassAlways...</p>
      </div>
    );
  }

  return (
    <div className="popup-container">
      <div className="popup-header">
        <div className="logo">🔐 PassAlways</div>
        <div className={`status-badge status-${authenticatorStatus}`}>
          {authenticatorStatus === 'connected' && '✓ Connected'}
          {authenticatorStatus === 'disconnected' && '⚠️ Disconnected'}
          {authenticatorStatus === 'unknown' && '● Checking...'}
        </div>
      </div>

      <div className="popup-content">
        <div className="info-section">
          <h2>Browser Extension</h2>
          <p className="info-text">
            This extension detects login forms and requests passwords from the PassAlways Authenticator desktop app.
          </p>

          {currentSite && (
            <div className="current-site">
              <div className="info-label">Current Site:</div>
              <div className="info-value">{currentSite}</div>
            </div>
          )}

          {authenticatorStatus === 'connected' ? (
            <div className="status-message status-success">
              <div className="status-icon">✓</div>
              <div>
                <strong>Authenticator Connected</strong>
                <p>Password filling is active. The extension will automatically detect login forms.</p>
              </div>
            </div>
          ) : (
            <div className="status-message status-error">
              <div className="status-icon">⚠️</div>
              <div>
                <strong>Authenticator Not Connected</strong>
                <p>Please make sure the PassAlways Authenticator app is running.</p>
              </div>
            </div>
          )}
        </div>

        <div className="instructions">
          <h3>How to Use</h3>
          <ol>
            <li>Open the PassAlways Authenticator desktop app</li>
            <li>Navigate to a login page</li>
            <li>Click the "🔐 Fill Password" button next to the password field</li>
            <li>Enter the TOTP code shown in the authenticator app</li>
            <li>Your credentials will be filled automatically</li>
          </ol>
        </div>
      </div>

      <div className="popup-footer">
        <div className="security-badge">
          <span className="badge-icon">🛡️</span>
          <span className="badge-text">Quantum-Resistant Security</span>
        </div>
      </div>
    </div>
  );
};

// Initialize React app
const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
