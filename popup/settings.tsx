// PassAlways Browser Extension - Settings UI
// Co-Authored-By: Project Engineer MelAnee Hannah

import React, { useState, useEffect } from 'react';
import type { PassmemoConfig, SaveConfigRequest, SaveConfigResponse, GetSiteUsernamesRequest, GetSiteUsernamesResponse, DeleteSiteDataRequest, DeleteSiteDataResponse, IncrementPasswordVersionRequest, IncrementPasswordVersionResponse } from '../shared/types';
import { normalizeSite } from '../shared/site-utils';

interface SettingsProps {
  config: PassmemoConfig;
  onClose: () => void;
  onConfigUpdate: (config: PassmemoConfig) => void;
}

export const Settings: React.FC<SettingsProps> = ({ config, onClose, onConfigUpdate }) => {
  const [editedConfig, setEditedConfig] = useState<PassmemoConfig>({ ...config });
  const [error, setError] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Password Management state
  const [currentSite, setCurrentSite] = useState<string>('');
  const [siteUsernames, setSiteUsernames] = useState<string[]>([]);
  const [selectedUsername, setSelectedUsername] = useState<string>('');
  const [managementMessage, setManagementMessage] = useState<string>('');

  const handleSave = async () => {
    setSaving(true);
    setError('');

    try {
      const request: SaveConfigRequest = {
        action: 'save_config',
        config: editedConfig,
      };

      // Use Promise wrapper for Firefox compatibility
      const response = await new Promise<SaveConfigResponse>((resolve, reject) => {
        chrome.runtime.sendMessage(request, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else if (!response) {
            reject(new Error('No response from background script'));
          } else {
            resolve(response as SaveConfigResponse);
          }
        });
      });

      if (response.success) {
        onConfigUpdate(editedConfig);
        onClose();
      } else {
        setError(response.error || 'Failed to save configuration');
      }
    } catch (err) {
      console.error('Settings save error:', err);
      setError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  // Load current site and usernames on mount
  useEffect(() => {
    const loadCurrentSite = async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) {
          const url = new URL(tab.url);
          const site = normalizeSite(url.hostname);
          setCurrentSite(site);

          // Load usernames for this site
          const request: GetSiteUsernamesRequest = {
            action: 'get_site_usernames',
            site,
          };
          const response = await chrome.runtime.sendMessage(request) as GetSiteUsernamesResponse;
          if (response.success && response.usernames) {
            setSiteUsernames(response.usernames);
            if (response.usernames.length > 0) {
              setSelectedUsername(response.usernames[0]);
            }
          }
        }
      } catch (err) {
        console.error('Failed to load current site:', err);
      }
    };

    loadCurrentSite();
  }, []);

  const handleDeleteSiteData = async () => {
    if (!currentSite || !selectedUsername) {
      setManagementMessage('Please select a username to delete');
      return;
    }

    if (!confirm(`Are you sure you want to delete password data for ${selectedUsername} on ${currentSite}?`)) {
      return;
    }

    try {
      const request: DeleteSiteDataRequest = {
        action: 'delete_site_data',
        site: currentSite,
        username: selectedUsername,
      };

      const response = await chrome.runtime.sendMessage(request) as DeleteSiteDataResponse;

      if (response.success) {
        setManagementMessage(`✓ Deleted data for ${selectedUsername} on ${currentSite}`);
        // Refresh username list
        const updatedUsernames = siteUsernames.filter(u => u !== selectedUsername);
        setSiteUsernames(updatedUsernames);
        if (updatedUsernames.length > 0) {
          setSelectedUsername(updatedUsernames[0]);
        } else {
          setSelectedUsername('');
        }
      } else {
        setManagementMessage(`✗ Failed to delete: ${response.error}`);
      }
    } catch (err) {
      setManagementMessage(`✗ Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const handleIncrementVersion = async () => {
    if (!currentSite || !selectedUsername) {
      setManagementMessage('Please select a username');
      return;
    }

    if (!confirm(`This will increment the password version for ${selectedUsername} on ${currentSite}. The next time you generate a password, it will be different. Continue?`)) {
      return;
    }

    try {
      const request: IncrementPasswordVersionRequest = {
        action: 'increment_password_version',
        site: currentSite,
        username: selectedUsername,
      };

      const response = await chrome.runtime.sendMessage(request) as IncrementPasswordVersionResponse;

      if (response.success) {
        setManagementMessage(`✓ Password version incremented to ${response.new_version} for ${selectedUsername}`);
      } else {
        setManagementMessage(`✗ Failed: ${response.error}`);
      }
    } catch (err) {
      setManagementMessage(`✗ Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  return (
    <div className="settings-container">
      <div className="settings-header">
        <h2>⚙️ Settings</h2>
        <button onClick={onClose} className="close-btn" disabled={saving}>
          ✕
        </button>
      </div>

      <div className="settings-content">
        {/* Default Username */}
        <div className="form-group">
          <label htmlFor="default_username">Default Email/Username</label>
          <input
            id="default_username"
            type="email"
            placeholder="your.email@example.com"
            value={editedConfig.default_username}
            onChange={(e) => setEditedConfig({ ...editedConfig, default_username: e.target.value })}
            className="input"
          />
          <span className="input-hint">Used as default when generating passwords</span>
        </div>

        {/* Password Length */}
        <div className="form-group">
          <label htmlFor="password_length">Default Password Length</label>
          <div className="radio-group">
            <label className="radio-option">
              <input
                type="radio"
                name="length"
                value="32"
                checked={editedConfig.password_length === 32}
                onChange={(e) => setEditedConfig({ ...editedConfig, password_length: parseInt(e.target.value, 10) })}
              />
              <div className="radio-content">
                <div className="radio-label">32 characters (Recommended)</div>
                <div className="radio-description">Maximum security</div>
              </div>
            </label>

            <label className="radio-option">
              <input
                type="radio"
                name="length"
                value="20"
                checked={editedConfig.password_length === 20}
                onChange={(e) => setEditedConfig({ ...editedConfig, password_length: parseInt(e.target.value, 10) })}
              />
              <div className="radio-content">
                <div className="radio-label">20 characters</div>
                <div className="radio-description">Balanced security</div>
              </div>
            </label>
          </div>
        </div>

        {/* Advanced Settings Toggle */}
        <div className="form-group">
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="btn btn-secondary"
            type="button"
          >
            {showAdvanced ? '▼' : '▶'} Advanced Settings
          </button>
        </div>

        {showAdvanced && (
          <div className="advanced-settings">
            <div className="warning-box">
              <div className="warning-icon">⚠️</div>
              <div className="warning-content">
                <p className="warning-title">Warning: Advanced Settings</p>
                <p>Changing these values will regenerate ALL your passwords. Only modify if you know what you're doing!</p>
              </div>
            </div>

            {/* ISBN */}
            <div className="form-group">
              <label htmlFor="isbn">ISBN Number</label>
              <input
                id="isbn"
                type="text"
                placeholder="9780770118686"
                value={editedConfig.isbn}
                onChange={(e) => setEditedConfig({ ...editedConfig, isbn: e.target.value })}
                className="input"
              />
              <span className="input-hint">From your master book</span>
            </div>

            {/* Page Numbers */}
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="page1">Page 1</label>
                <input
                  id="page1"
                  type="number"
                  min="1"
                  value={editedConfig.page1}
                  onChange={(e) => setEditedConfig({ ...editedConfig, page1: parseInt(e.target.value, 10) || 0 })}
                  className="input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="page2">Page 2</label>
                <input
                  id="page2"
                  type="number"
                  min="1"
                  value={editedConfig.page2}
                  onChange={(e) => setEditedConfig({ ...editedConfig, page2: parseInt(e.target.value, 10) || 0 })}
                  className="input"
                />
              </div>
            </div>

            {/* Passphrases */}
            <div className="form-group">
              <label htmlFor="passphrase1">Passphrase 1</label>
              <textarea
                id="passphrase1"
                value={editedConfig.passphrase1_template}
                onChange={(e) => setEditedConfig({ ...editedConfig, passphrase1_template: e.target.value })}
                className="input textarea"
                rows={3}
              />
              <span className="input-hint">Must contain {'{USERNAME}'} placeholder</span>
            </div>

            <div className="form-group">
              <label htmlFor="passphrase2">Passphrase 2</label>
              <textarea
                id="passphrase2"
                value={editedConfig.passphrase2_template}
                onChange={(e) => setEditedConfig({ ...editedConfig, passphrase2_template: e.target.value })}
                className="input textarea"
                rows={3}
              />
              <span className="input-hint">Must contain {'{SITE}'} placeholder</span>
            </div>

            {/* Book Author */}
            <div className="form-group">
              <label htmlFor="author_fullname">Book Author's Full Name</label>
              <input
                id="author_fullname"
                type="text"
                value={editedConfig.author_fullname}
                onChange={(e) => setEditedConfig({ ...editedConfig, author_fullname: e.target.value })}
                className="input"
              />
            </div>

            {/* Password Management Section */}
            <div className="form-group" style={{ marginTop: '2rem', borderTop: '1px solid #e5e7eb', paddingTop: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem' }}>Password Management</h3>

              {currentSite && (
                <div className="info-box" style={{ padding: '0.75rem', backgroundColor: '#f3f4f6', borderRadius: '0.375rem', marginBottom: '1rem' }}>
                  <p style={{ fontSize: '0.875rem', color: '#374151' }}>
                    Current site: <strong>{currentSite}</strong>
                  </p>
                </div>
              )}

              {siteUsernames.length > 0 ? (
                <>
                  <div className="form-group">
                    <label htmlFor="manage_username">Select Username</label>
                    <select
                      id="manage_username"
                      className="input"
                      value={selectedUsername}
                      onChange={(e) => setSelectedUsername(e.target.value)}
                    >
                      {siteUsernames.map((username) => (
                        <option key={username} value={username}>
                          {username}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-row" style={{ gap: '0.75rem' }}>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={handleIncrementVersion}
                      style={{ flex: 1 }}
                    >
                      🔄 Increment Password Version
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={handleDeleteSiteData}
                      style={{ flex: 1, backgroundColor: '#ef4444', color: 'white' }}
                    >
                      🗑️ Delete Site Data
                    </button>
                  </div>

                  {managementMessage && (
                    <div className="message-box" style={{
                      marginTop: '0.75rem',
                      padding: '0.75rem',
                      borderRadius: '0.375rem',
                      fontSize: '0.875rem',
                      backgroundColor: managementMessage.startsWith('✓') ? '#d1fae5' : '#fee2e2',
                      color: managementMessage.startsWith('✓') ? '#065f46' : '#991b1b'
                    }}>
                      {managementMessage}
                    </div>
                  )}
                </>
              ) : (
                <div className="info-box" style={{ padding: '0.75rem', backgroundColor: '#f3f4f6', borderRadius: '0.375rem' }}>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                    No saved passwords for this site
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="error-message">
            ⚠️ {error}
          </div>
        )}
      </div>

      <div className="settings-footer">
        <button onClick={onClose} className="btn btn-secondary" disabled={saving}>
          Cancel
        </button>
        <button onClick={handleSave} className="btn btn-primary" disabled={saving}>
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  );
};
