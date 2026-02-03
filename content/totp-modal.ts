// PassAlways - TOTP Modal UI
// Co-Authored-By: Project Engineer MelAnee Hannah
//
// Displays TOTP authentication modal for first-time password generation
// Modal shows the 6-digit TOTP code and prompts user to enter it

export class TotpModal {
  private modal: HTMLElement | null = null;
  private overlay: HTMLElement | null = null;
  private totpCode: string = '';
  private sessionId: string = '';
  private onValidateCallback: ((totp: string) => Promise<void>) | null = null;
  private onCancelCallback: (() => void) | null = null;

  /**
   * Show TOTP modal with the generated code
   * @param totpCode The 6-digit TOTP code to display
   * @param sessionId The session ID for validation
   * @param site The site name to display
   * @param onValidate Callback when user enters TOTP
   * @param onCancel Callback when user cancels
   */
  show(
    totpCode: string,
    sessionId: string,
    site: string,
    onValidate: (totp: string) => Promise<void>,
    onCancel: () => void
  ): void {
    this.totpCode = totpCode;
    this.sessionId = sessionId;
    this.onValidateCallback = onValidate;
    this.onCancelCallback = onCancel;

    // Create overlay
    this.overlay = document.createElement('div');
    this.overlay.id = 'passalways-totp-overlay';
    this.overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      z-index: 2147483646;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    `;

    // Create modal
    this.modal = document.createElement('div');
    this.modal.id = 'passalways-totp-modal';
    this.modal.style.cssText = `
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 480px;
      width: 90%;
      padding: 32px;
      position: relative;
      animation: passalways-modal-fade-in 0.3s ease-out;
    `;

    this.modal.innerHTML = `
      <style>
        @keyframes passalways-modal-fade-in {
          from {
            opacity: 0;
            transform: scale(0.95) translateY(-10px);
          }
          to {
            opacity: 1;
            transform: scale(1) translateY(0);
          }
        }

        #passalways-totp-modal * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        .passalways-modal-header {
          text-align: center;
          margin-bottom: 24px;
        }

        .passalways-modal-title {
          font-size: 24px;
          font-weight: 600;
          color: #1a1a1a;
          margin-bottom: 8px;
        }

        .passalways-modal-subtitle {
          font-size: 14px;
          color: #666;
        }

        .passalways-totp-input-group {
          margin: 24px 0;
        }

        .passalways-totp-input-label {
          display: block;
          font-size: 14px;
          font-weight: 500;
          color: #333;
          margin-bottom: 8px;
        }

        .passalways-totp-input {
          width: 100%;
          padding: 12px 16px;
          font-size: 18px;
          font-family: 'Courier New', monospace;
          border: 2px solid #e5e5e5;
          border-radius: 8px;
          outline: none;
          transition: border-color 0.2s;
          letter-spacing: 4px;
          text-align: center;
        }

        .passalways-totp-input:focus {
          border-color: #2563eb;
        }

        .passalways-totp-input.error {
          border-color: #dc2626;
          animation: passalways-shake 0.4s;
        }

        @keyframes passalways-shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-10px); }
          75% { transform: translateX(10px); }
        }

        .passalways-error-message {
          color: #dc2626;
          font-size: 14px;
          margin-top: 8px;
          text-align: center;
          min-height: 20px;
        }

        .passalways-modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 24px;
        }

        .passalways-btn {
          flex: 1;
          padding: 12px 24px;
          font-size: 16px;
          font-weight: 500;
          border-radius: 8px;
          border: none;
          cursor: pointer;
          transition: all 0.2s;
        }

        .passalways-btn-primary {
          background: #2563eb;
          color: white;
        }

        .passalways-btn-primary:hover {
          background: #1d4ed8;
        }

        .passalways-btn-primary:active {
          transform: scale(0.98);
        }

        .passalways-btn-primary:disabled {
          background: #cbd5e1;
          cursor: not-allowed;
        }

        .passalways-btn-secondary {
          background: #f5f5f5;
          color: #666;
        }

        .passalways-btn-secondary:hover {
          background: #e5e5e5;
        }

        .passalways-help-text {
          font-size: 13px;
          color: #666;
          text-align: center;
          margin-top: 16px;
          line-height: 1.5;
        }
      </style>

      <div class="passalways-modal-header">
        <div class="passalways-modal-title">🔐 PassAlways Authentication</div>
        <div class="passalways-modal-subtitle">${this.escapeHtml(site)}</div>
      </div>

      <div class="passalways-totp-input-group">
        <label class="passalways-totp-input-label">Enter TOTP Code</label>
        <input
          type="text"
          id="passalways-totp-input"
          class="passalways-totp-input"
          placeholder="000000"
          maxlength="6"
          pattern="[0-9]{6}"
          autocomplete="off"
        />
        <div class="passalways-error-message" id="passalways-totp-error"></div>
      </div>

      <div class="passalways-modal-actions">
        <button class="passalways-btn passalways-btn-secondary" id="passalways-totp-cancel">
          Cancel
        </button>
        <button class="passalways-btn passalways-btn-primary" id="passalways-totp-submit">
          Verify & Continue
        </button>
      </div>

      <div class="passalways-help-text">
        Check your system notifications for the TOTP code from PassAlways. The code is valid for 3 minutes.
      </div>
    `;

    this.overlay.appendChild(this.modal);
    document.body.appendChild(this.overlay);

    // Setup event listeners
    this.setupEventListeners();

    // Focus input
    const input = document.getElementById('passalways-totp-input') as HTMLInputElement;
    if (input) {
      setTimeout(() => input.focus(), 100);
    }
  }

  private setupEventListeners(): void {
    const input = document.getElementById('passalways-totp-input') as HTMLInputElement;
    const submitBtn = document.getElementById('passalways-totp-submit') as HTMLButtonElement;
    const cancelBtn = document.getElementById('passalways-totp-cancel') as HTMLButtonElement;
    const errorDiv = document.getElementById('passalways-totp-error') as HTMLDivElement;

    if (!input || !submitBtn || !cancelBtn || !errorDiv) return;

    // Auto-format input (digits only)
    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').substring(0, 6);
      input.classList.remove('error');
      errorDiv.textContent = '';
    });

    // Submit on Enter
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && input.value.length === 6) {
        this.handleSubmit(input, submitBtn, errorDiv);
      }
    });

    // Submit button
    submitBtn.addEventListener('click', () => {
      this.handleSubmit(input, submitBtn, errorDiv);
    });

    // Cancel button
    cancelBtn.addEventListener('click', () => {
      this.hide();
      if (this.onCancelCallback) {
        this.onCancelCallback();
      }
    });

    // Close on overlay click
    this.overlay?.addEventListener('click', (e) => {
      if (e.target === this.overlay) {
        this.hide();
        if (this.onCancelCallback) {
          this.onCancelCallback();
        }
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal) {
        this.hide();
        if (this.onCancelCallback) {
          this.onCancelCallback();
        }
      }
    });
  }

  private async handleSubmit(
    input: HTMLInputElement,
    submitBtn: HTMLButtonElement,
    errorDiv: HTMLDivElement
  ): Promise<void> {
    const enteredCode = input.value.trim();

    if (enteredCode.length !== 6) {
      this.showError('Please enter a 6-digit code', input, errorDiv);
      return;
    }

    // Disable input and button
    input.disabled = true;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying...';

    try {
      if (this.onValidateCallback) {
        await this.onValidateCallback(enteredCode);
        // Success - modal will be closed by the callback
      }
    } catch (error) {
      // Re-enable on error
      input.disabled = false;
      submitBtn.disabled = false;
      submitBtn.textContent = 'Verify & Continue';

      const errorMessage = error instanceof Error ? error.message : 'Verification failed';
      this.showError(errorMessage, input, errorDiv);

      // Clear input and refocus
      input.value = '';
      input.focus();
    }
  }

  private showError(message: string, input: HTMLInputElement, errorDiv: HTMLDivElement): void {
    errorDiv.textContent = message;
    input.classList.add('error');
  }

  /**
   * Hide and remove the modal
   */
  hide(): void {
    if (this.overlay) {
      this.overlay.remove();
      this.overlay = null;
    }
    this.modal = null;
    this.totpCode = '';
    this.sessionId = '';
    this.onValidateCallback = null;
    this.onCancelCallback = null;
  }

  /**
   * Format TOTP code with spacing (e.g., "123 456")
   */
  private formatTotpCode(code: string): string {
    if (code.length === 6) {
      return `${code.substring(0, 3)} ${code.substring(3, 6)}`;
    }
    return code;
  }

  /**
   * Escape HTML to prevent XSS
   */
  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Check if modal is currently shown
   */
  isShown(): boolean {
    return this.modal !== null && document.body.contains(this.modal);
  }
}
