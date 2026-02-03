// PassAlways Browser Extension - Setup Wizard
// Co-Authored-By: Project Engineer MelAnee Hannah

import React, { useState } from 'react';
import type { PassmemoConfig, SaveConfigRequest, SaveConfigResponse } from '../shared/types';

interface SetupWizardProps {
  onComplete: () => void;
}

export const SetupWizard: React.FC<SetupWizardProps> = ({ onComplete }) => {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState<Partial<PassmemoConfig>>({
    isbn: '',
    page1: 0,
    page2: 0,
    passphrase1_template: '',
    passphrase2_template: '',
    default_username: '',
    author_fullname: '',
    password_length: 32,
  });
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const totalSteps = 5;

  const validateStep = (): boolean => {
    switch (step) {
      case 1:
        if (!config.isbn || config.isbn.length < 10) {
          setError('ISBN must be at least 10 digits');
          return false;
        }
        if (!config.page1 || config.page1 <= 0) {
          setError('Page numbers must be greater than 0');
          return false;
        }
        if (!config.page2 || config.page2 <= 0) {
          setError('Page numbers must be greater than 0');
          return false;
        }
        break;
      case 2:
        if (!config.passphrase1_template || !config.passphrase1_template.includes('{USERNAME}')) {
          setError('Passphrase 1 must contain {USERNAME} placeholder');
          return false;
        }
        break;
      case 3:
        if (!config.passphrase2_template || !config.passphrase2_template.includes('{SITE}')) {
          setError('Passphrase 2 must contain {SITE} placeholder');
          return false;
        }
        break;
      case 4:
        if (!config.default_username || !config.default_username.includes('@')) {
          setError('Please enter a valid email address');
          return false;
        }
        if (!config.author_fullname || config.author_fullname.length < 5) {
          setError('Please enter the author\'s full name');
          return false;
        }
        break;
    }
    return true;
  };

  const handleNext = () => {
    setError('');

    if (!validateStep()) {
      return;
    }

    if (step < totalSteps) {
      setStep(step + 1);
    } else {
      handleComplete();
    }
  };

  const handleBack = () => {
    if (step > 1) {
      setStep(step - 1);
      setError('');
    }
  };

  const handleComplete = async () => {
    setLoading(true);
    setError('');

    try {
      const request: SaveConfigRequest = {
        action: 'save_config',
        config: config as PassmemoConfig,
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
        onComplete();
      } else {
        console.error('[Setup Wizard] Failed:', response.error);
        setError(response.error || 'Failed to save configuration');
      }
    } catch (err) {
      console.error('[Setup Wizard] Exception:', err);
      setError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setLoading(false);
    }
  };

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="wizard-step">
            <div className="step-icon">📚</div>
            <h2>Master Seed</h2>
            <p className="step-description">
              Choose your favorite book and select two random page numbers. This creates your unique master seed.
            </p>

            <div className="form-group">
              <label htmlFor="isbn">ISBN Number (10 or 13 digits)</label>
              <input
                id="isbn"
                type="text"
                placeholder="9780770118686"
                value={config.isbn}
                onChange={(e) => setConfig({ ...config, isbn: e.target.value })}
                className="input"
              />
              <span className="input-hint">From your favorite book (13-digit ISBNs will have 978 prefix removed)</span>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="page1">Page 1</label>
                <input
                  id="page1"
                  type="number"
                  min="1"
                  placeholder="112"
                  value={config.page1 || ''}
                  onChange={(e) => setConfig({ ...config, page1: parseInt(e.target.value, 10) || 0 })}
                  className="input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="page2">Page 2</label>
                <input
                  id="page2"
                  type="number"
                  min="1"
                  placeholder="57"
                  value={config.page2 || ''}
                  onChange={(e) => setConfig({ ...config, page2: parseInt(e.target.value, 10) || 0 })}
                  className="input"
                />
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="wizard-step">
            <div className="step-icon">🔑</div>
            <h2>First Passphrase</h2>

            <div className="info-box">
              <div className="info-icon">ℹ️</div>
              <div className="info-content">
                <p className="info-title">Instructions:</p>
                <p>Choose a phrase from page {config.page1} and replace the last noun with <code>{'{USERNAME}'}</code></p>
                <p className="info-example">Example: "Nothing can be real until you can imagine like a {'{USERNAME}'}"</p>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="passphrase1">Passphrase 1 (with {'{USERNAME}'} placeholder)</label>
              <textarea
                id="passphrase1"
                placeholder="Your phrase with {USERNAME} placeholder..."
                value={config.passphrase1_template}
                onChange={(e) => setConfig({ ...config, passphrase1_template: e.target.value })}
                className="input textarea"
                rows={3}
              />
            </div>
          </div>
        );

      case 3:
        return (
          <div className="wizard-step">
            <div className="step-icon">🌐</div>
            <h2>Second Passphrase</h2>

            <div className="info-box">
              <div className="info-icon">ℹ️</div>
              <div className="info-content">
                <p className="info-title">Instructions:</p>
                <p>Choose a phrase from page {config.page2} and replace the last noun with <code>{'{SITE}'}</code></p>
                <p className="info-example">Example: "Only under a blue sky, the {'{SITE}'} cry"</p>
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="passphrase2">Passphrase 2 (with {'{SITE}'} placeholder)</label>
              <textarea
                id="passphrase2"
                placeholder="Your phrase with {SITE} placeholder..."
                value={config.passphrase2_template}
                onChange={(e) => setConfig({ ...config, passphrase2_template: e.target.value })}
                className="input textarea"
                rows={3}
              />
            </div>
          </div>
        );

      case 4:
        return (
          <div className="wizard-step">
            <div className="step-icon">👤</div>
            <h2>Default Username & Book Author</h2>
            <p className="step-description">
              Enter your default email and the author of your chosen book.
            </p>

            <div className="form-group">
              <label htmlFor="default_username">Default Email/Username</label>
              <input
                id="default_username"
                type="email"
                placeholder="your.email@example.com"
                value={config.default_username}
                onChange={(e) => setConfig({ ...config, default_username: e.target.value })}
                className="input"
              />
              <span className="input-hint">This will replace {'{USERNAME}'} in your first passphrase</span>
            </div>

            <div className="form-group">
              <label htmlFor="author_fullname">Book Author's Full Name</label>
              <input
                id="author_fullname"
                type="text"
                placeholder="Gabriel García Márquez"
                value={config.author_fullname}
                onChange={(e) => setConfig({ ...config, author_fullname: e.target.value })}
                className="input"
              />
              <span className="input-hint">The author of the book with ISBN {config.isbn}</span>
            </div>
          </div>
        );

      case 5:
        return (
          <div className="wizard-step">
            <div className="step-icon">🔒</div>
            <h2>Password Length</h2>
            <p className="step-description">
              Choose your default password length. You can adjust this per-site later.
            </p>

            <div className="radio-group">
              <label className="radio-option">
                <input
                  type="radio"
                  name="length"
                  value="32"
                  checked={config.password_length === 32}
                  onChange={(e) => setConfig({ ...config, password_length: parseInt(e.target.value, 10) })}
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
                  checked={config.password_length === 20}
                  onChange={(e) => setConfig({ ...config, password_length: parseInt(e.target.value, 10) })}
                />
                <div className="radio-content">
                  <div className="radio-label">20 characters</div>
                  <div className="radio-description">Balanced security</div>
                </div>
              </label>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="setup-wizard">
      <div className="wizard-header">
        <div className="logo">🔐 PassAlways Setup</div>
        <p className="wizard-subtitle">Quantum-resistant password generator</p>

        {/* Progress bar */}
        <div className="progress-container">
          <div className="progress-steps">
            {[1, 2, 3, 4, 5].map((s) => (
              <div
                key={s}
                className={`progress-step ${s === step ? 'active' : ''} ${s < step ? 'completed' : ''}`}
              >
                {s}
              </div>
            ))}
          </div>
          <div className="progress-bar-container">
            <div
              className="progress-bar-fill"
              style={{ width: `${(step / totalSteps) * 100}%` }}
            />
          </div>
        </div>
      </div>

      <div className="wizard-content">
        {renderStep()}

        {error && (
          <div className="error-message">
            ⚠️ {error}
          </div>
        )}
      </div>

      <div className="wizard-footer">
        {step > 1 && (
          <button onClick={handleBack} className="btn btn-secondary" disabled={loading}>
            Back
          </button>
        )}
        <button
          onClick={handleNext}
          className="btn btn-primary"
          disabled={loading}
        >
          {loading ? 'Setting up...' : step === totalSteps ? 'Complete Setup' : 'Next'}
        </button>
      </div>
    </div>
  );
};
