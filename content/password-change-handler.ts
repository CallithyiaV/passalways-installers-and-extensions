// PassAlways Browser Extension - Password Change Handler
// Co-Authored-By: Project Engineer MelAnee Hannah

import type { FormContext, GeneratePasswordRequest, GeneratePasswordResponse, GetSiteAttributesRequest, GetSiteAttributesResponse } from '../shared/types';
import { sendMessageSafe } from './utils';

// Inline utility functions to avoid code splitting
function normalizeSite(hostname: string): string {
  if (!hostname) return hostname;
  const commonPrefixes = ['www', 'm', 'mobile', 'wap'];
  const parts = hostname.split('.');
  if (parts.length >= 3 && commonPrefixes.includes(parts[0].toLowerCase())) {
    parts.shift();
    return parts.join('.');
  }
  return hostname;
}

function getCurrentSite(): string {
  return normalizeSite(window.location.hostname);
}

function normalizeUsername(username: string): string {
  if (!username) return username;
  return username.trim().toLowerCase();
}

/**
 * Handles Flow 2: Password Change (Migrate to PassAlways)
 * Trigger: Three password fields detected + /settings URL
 */
export class PasswordChangeHandler {
  private context: FormContext;
  private banner: HTMLDivElement | null = null;

  constructor(context: FormContext) {
    this.context = context;
  }

  /**
   * Initialize password change flow - inject UI and set up event handlers
   */
  async initialize(): Promise<void> {
    // Only handle if we have exactly 3 password fields
    if (this.context.passwordFields.length !== 3) {
      return;
    }

    const site = getCurrentSite();
    const rawUsername = await this.detectUsername();

    // Normalize username for consistent password generation
    const username = rawUsername ? normalizeUsername(rawUsername) : '';

    // Check if already using PassAlways
    const metadata = await this.getSiteMetadata(site, username);
    const isExistingUser = metadata.success && metadata.attributes !== undefined;

    // Show banner offering to secure account or update password
    this.banner = this.createBanner(isExistingUser);
    document.body.insertAdjacentElement('afterbegin', this.banner);
  }

  /**
   * Create banner offering password change
   */
  private createBanner(isExistingUser: boolean): HTMLDivElement {
    const banner = document.createElement('div');
    banner.className = 'passmemo-banner passmemo-password-change-banner';
    banner.innerHTML = `
      <div class="passmemo-banner-content">
        <div class="passmemo-banner-icon">🔐</div>
        <div class="passmemo-banner-text">
          <strong>${isExistingUser ? 'Update your PassAlways password?' : 'Secure this account with PassAlways?'}</strong>
          <p>${isExistingUser
            ? 'Generate a new PassAlways password for this site.'
            : 'Generate a quantum-resistant password for enhanced security.'
          }</p>
        </div>
        <div class="passmemo-banner-actions">
          <button class="passmemo-banner-btn passmemo-banner-btn-primary" data-action="generate">
            ${isExistingUser ? 'Generate New Password' : 'Yes, Generate'}
          </button>
          <button class="passmemo-banner-btn passmemo-banner-btn-secondary" data-action="dismiss">
            ${isExistingUser ? 'Not Now' : 'No Thanks'}
          </button>
        </div>
      </div>
    `;

    // Add event handlers
    banner.addEventListener('click', async (e) => {
      const target = e.target as HTMLElement;
      const action = target.getAttribute('data-action');

      if (action === 'generate') {
        await this.handleGenerate(isExistingUser);
      } else if (action === 'dismiss') {
        banner.remove();
      }
    });

    return banner;
  }

  /**
   * Handle password generation for password change
   */
  private async handleGenerate(isExistingUser: boolean): Promise<void> {
    try {
      const site = getCurrentSite();
      const rawUsername = await this.detectUsername();

      if (!rawUsername) {
        this.showError('Could not detect username. Please ensure you are logged in.');
        return;
      }

      // Normalize username for consistent password generation
      const username = normalizeUsername(rawUsername);

      // Get existing metadata to determine version
      const metadata = await this.getSiteMetadata(site, username);
      const currentVersion = metadata.attributes?.version ?? 0;
      const newVersion = isExistingUser ? currentVersion + 1 : 0;

      // Show loading in banner
      this.setBannerLoading(true);

      // Generate new password
      const request: GeneratePasswordRequest = {
        action: 'generate_password',
        site,
        username,
        version: newVersion,
        autoRetry: true,
      };

      const response = await sendMessageSafe<GeneratePasswordResponse>(request);

      if (response.success && response.password) {
        // Identify the three fields: [current, new, confirm]
        const [currentField, newField, confirmField] = this.context.passwordFields;

        // Fill ONLY new password and confirm fields
        newField.value = response.password;
        confirmField.value = response.password;

        // Trigger events
        newField.dispatchEvent(new Event('input', { bubbles: true }));
        newField.dispatchEvent(new Event('change', { bubbles: true }));
        confirmField.dispatchEvent(new Event('input', { bubbles: true }));
        confirmField.dispatchEvent(new Event('change', { bubbles: true }));

        // Highlight current password field with warning
        this.highlightField(
          currentField,
          'warning',
          '⚠️ Enter your CURRENT password here manually'
        );

        // Update banner to show success
        this.showSuccessBanner(newVersion);

        this.showNotification(
          'Password generated!',
          `New password (version ${newVersion}) filled. Enter your current password manually to complete the change.`,
          'success'
        );
      } else {
        throw new Error(response.error || 'Failed to generate password');
      }
    } catch (error) {
      console.error('Password change handler error:', error);
      this.showError(error instanceof Error ? error.message : 'Failed to generate password');
      this.setBannerLoading(false);
    }
  }

  /**
   * Detect username from page context
   */
  private async detectUsername(): Promise<string | null> {
    // Try to get from form fields first
    const usernameField = this.context.usernameField;
    const emailField = this.context.emailField;

    if (usernameField?.value) {
      return usernameField.value.trim();
    }

    if (emailField?.value) {
      return emailField.value.trim();
    }

    // Try to detect from page content (common patterns)
    const pageText = document.body.innerText;

    // Look for email patterns in visible text
    const emailMatch = pageText.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) {
      return emailMatch[1];
    }

    // Try to get from account/profile info
    const accountElements = document.querySelectorAll('[class*="account"], [class*="profile"], [class*="user"]');
    for (const elem of accountElements) {
      const text = elem.textContent || '';
      const emailMatch = text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailMatch) {
        return emailMatch[1];
      }
    }

    // Prompt user to enter username
    return await this.promptForUsername();
  }

  /**
   * Prompt user to enter username
   */
  private async promptForUsername(): Promise<string | null> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'passmemo-overlay';
      overlay.innerHTML = `
        <div class="passmemo-dialog">
          <div class="passmemo-dialog-header">
            <h3>Enter Username</h3>
          </div>
          <div class="passmemo-dialog-content">
            <p>Please enter your username or email for this site:</p>
            <input type="text" class="passmemo-input" placeholder="username@example.com" />
          </div>
          <div class="passmemo-dialog-actions">
            <button class="passmemo-dialog-btn passmemo-dialog-btn-secondary" data-action="cancel">Cancel</button>
            <button class="passmemo-dialog-btn passmemo-dialog-btn-primary" data-action="confirm">Continue</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      const input = overlay.querySelector('.passmemo-input') as HTMLInputElement;
      input.focus();

      const handleAction = (e: Event) => {
        const target = e.target as HTMLElement;
        const action = target.getAttribute('data-action');

        if (action === 'confirm') {
          const username = input.value.trim();
          overlay.remove();
          resolve(username || null);
        } else if (action === 'cancel') {
          overlay.remove();
          resolve(null);
        }
      };

      overlay.addEventListener('click', handleAction);

      // Allow Enter key to submit
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          const username = input.value.trim();
          overlay.remove();
          resolve(username || null);
        }
      });
    });
  }

  /**
   * Get site metadata from storage
   */
  private async getSiteMetadata(site: string, username: string): Promise<GetSiteAttributesResponse> {
    const request: GetSiteAttributesRequest = {
      action: 'get_site_attributes',
      site,
      username,
    };

    return await sendMessageSafe<GetSiteAttributesResponse>(request);
  }

  /**
   * Highlight a field with a message
   */
  private highlightField(field: HTMLInputElement, type: 'warning' | 'success', message: string): void {
    // Remove existing highlight
    const existing = field.parentElement?.querySelector('.passmemo-field-highlight');
    if (existing) {
      existing.remove();
    }

    // Create highlight element
    const highlight = document.createElement('div');
    highlight.className = `passmemo-field-highlight passmemo-field-highlight-${type}`;
    highlight.textContent = message;

    // Insert after field
    field.insertAdjacentElement('afterend', highlight);

    // Add visual highlight to field
    field.classList.add(`passmemo-field-${type}`);
  }

  /**
   * Set banner loading state
   */
  private setBannerLoading(loading: boolean): void {
    if (!this.banner) return;

    const button = this.banner.querySelector('[data-action="generate"]') as HTMLButtonElement;
    if (button) {
      button.disabled = loading;
      button.textContent = loading ? 'Generating...' : 'Generate Password';
    }
  }

  /**
   * Show success banner
   */
  private showSuccessBanner(version: number): void {
    if (!this.banner) return;

    this.banner.innerHTML = `
      <div class="passmemo-banner-content">
        <div class="passmemo-banner-icon">✓</div>
        <div class="passmemo-banner-text">
          <strong>Password Generated!</strong>
          <p>New password (version ${version}) has been filled. Enter your current password to complete the change.</p>
        </div>
        <div class="passmemo-banner-actions">
          <button class="passmemo-banner-btn passmemo-banner-btn-secondary" data-action="dismiss">
            Dismiss
          </button>
        </div>
      </div>
    `;

    // Update dismiss handler
    this.banner.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.getAttribute('data-action') === 'dismiss') {
        this.banner?.remove();
      }
    });
  }

  /**
   * Show error message
   */
  private showError(message: string): void {
    this.showNotification('Error', message, 'error');
  }

  /**
   * Show notification banner
   */
  private showNotification(title: string, message: string, type: 'success' | 'error' | 'info'): void {
    // Remove existing notification if present
    const existing = document.querySelector('.passmemo-notification');
    if (existing) {
      existing.remove();
    }

    const notification = document.createElement('div');
    notification.className = `passmemo-notification passmemo-notification-${type}`;
    notification.innerHTML = `
      <div class="passmemo-notification-content">
        <div class="passmemo-notification-title">${title}</div>
        <div class="passmemo-notification-message">${message}</div>
      </div>
      <button class="passmemo-notification-close" aria-label="Close">×</button>
    `;

    // Add close handler
    const closeBtn = notification.querySelector('.passmemo-notification-close');
    closeBtn?.addEventListener('click', () => {
      notification.remove();
    });

    // Insert at top of page
    document.body.insertAdjacentElement('afterbegin', notification);

    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      notification.remove();
    }, 5000);
  }

  /**
   * Cleanup when form type changes
   */
  destroy(): void {
    if (this.banner) {
      this.banner.remove();
      this.banner = null;
    }
  }
}
