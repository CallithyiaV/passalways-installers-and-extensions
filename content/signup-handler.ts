// PassAlways Browser Extension - Signup Handler
// Co-Authored-By: Project Engineer MelAnee Hannah

import type { FormContext, GeneratePasswordRequest, GeneratePasswordResponse } from '../shared/types';
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
 * Handles Flow 1: Sign-On (New Account Registration)
 * Trigger: Two password fields + email field detected
 */
export class SignupHandler {
  private context: FormContext;
  private button: HTMLButtonElement | null = null;

  constructor(context: FormContext) {
    this.context = context;
  }

  /**
   * Initialize signup flow - inject UI and set up event handlers
   */
  async initialize(): Promise<void> {
    // Only handle if we have at least 2 password fields
    if (this.context.passwordFields.length < 2) {
      return;
    }

    // Create and inject inline button next to first password field
    this.button = this.createInlineButton();
    const firstPasswordField = this.context.passwordFields[0];

    // Insert button after the password field
    const container = firstPasswordField.parentElement;
    if (container) {
      // Check if button already exists
      if (!container.querySelector('.passmemo-generate-btn')) {
        firstPasswordField.insertAdjacentElement('afterend', this.button);
      }
    }
  }

  /**
   * Create the inline "Generate Password" button
   */
  private createInlineButton(): HTMLButtonElement {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'passmemo-generate-btn passmemo-signup-btn';
    button.innerHTML = '🔐 Generate Password';
    button.title = 'Generate secure password with PassAlways';

    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.handleGenerate();
    });

    return button;
  }

  /**
   * Handle password generation and form filling
   */
  private async handleGenerate(): Promise<void> {
    try {
      if (!this.button) return;

      // Show loading state
      this.setButtonState('loading', 'Generating...');

      const site = getCurrentSite();
      const rawUsername = this.getUsername();

      if (!rawUsername) {
        this.showError('Please enter your email or username first');
        return;
      }

      // Normalize username for consistent password generation
      const username = normalizeUsername(rawUsername);

      // Generate password via background script
      const request: GeneratePasswordRequest = {
        action: 'generate_password',
        site,
        username,
        autoRetry: true,
      };

      const response = await sendMessageSafe<GeneratePasswordResponse>(request);

      if (response.success && response.password) {
        // Fill BOTH password and confirm password fields
        this.context.passwordFields.forEach((field) => {
          field.value = response.password!;
          // Trigger input events for frameworks like React/Vue
          field.dispatchEvent(new Event('input', { bubbles: true }));
          field.dispatchEvent(new Event('change', { bubbles: true }));
        });

        this.setButtonState('success', '✓ Password Generated');

        // Show success notification
        this.showNotification(
          'Password generated and filled!',
          'Both password fields have been filled with a secure quantum-resistant password.',
          'success'
        );

        // Reset button after 3 seconds
        setTimeout(() => {
          this.setButtonState('default', '🔐 Generate Password');
        }, 3000);
      } else {
        throw new Error(response.error || 'Failed to generate password');
      }
    } catch (error) {
      console.error('Signup handler error:', error);
      this.showError(error instanceof Error ? error.message : 'Failed to generate password');
      this.setButtonState('default', '🔐 Generate Password');
    }
  }

  /**
   * Get username from email or username field
   */
  private getUsername(): string {
    const emailField = this.context.emailField;
    const usernameField = this.context.usernameField;

    if (emailField?.value) {
      return emailField.value.trim();
    }

    if (usernameField?.value) {
      return usernameField.value.trim();
    }

    return '';
  }

  /**
   * Set button state (loading, success, error)
   */
  private setButtonState(state: 'default' | 'loading' | 'success' | 'error', text: string): void {
    if (!this.button) return;

    this.button.textContent = text;
    this.button.className = `passmemo-generate-btn passmemo-signup-btn passmemo-btn-${state}`;
    this.button.disabled = state === 'loading';
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
    if (this.button) {
      this.button.remove();
      this.button = null;
    }
  }
}
