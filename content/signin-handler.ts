// PassAlways Browser Extension - Signin Handler
// Co-Authored-By: Project Engineer MelAnee Hannah

import type { FormContext, GeneratePasswordRequest, GeneratePasswordResponse, GetSiteAttributesRequest, GetSiteAttributesResponse, GetSiteUsernamesRequest, GetSiteUsernamesResponse, EstablishSessionRequest, EstablishSessionResponse, ValidateSessionRequest, ValidateSessionResponse, GetSessionRequest, GetSessionResponse, GeneratePasswordViaIpcRequest, GeneratePasswordViaIpcResponse, SubmitTotpRequest, SubmitTotpResponse } from '../shared/types';
import { TotpModal } from './totp-modal';
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
 * Handles Flow 3: Sign-In (Use Existing Password)
 * Trigger: One or two password fields + login keywords
 */
export class SigninHandler {
  private context: FormContext;
  private button: HTMLButtonElement | null = null;
  private originalUrl: string;
  private usernameSelector: HTMLDivElement | null = null;
  private usernameSelectorVisible: boolean = false;
  private isAutoFilling: boolean = false; // Flag to prevent selector during auto-fill
  private passwordToggle: HTMLButtonElement | null = null;
  private totpModal: TotpModal;
  private currentPassword: string | null = null; // Phase 6: Store generated password
  private currentSite: string = '';
  private currentUsername: string = '';

  constructor(context: FormContext) {
    this.context = context;
    this.originalUrl = window.location.href;
    this.totpModal = new TotpModal();
  }

  /**
   * Initialize signin flow - inject UI and set up event handlers
   */
  async initialize(): Promise<void> {
    // Auto-populate username field with default username from config
    await this.autopopulateUsername();

    // Create and inject inline button next to password field
    this.button = this.createInlineButton();
    const passwordField = this.context.passwordFields[0];

    // Insert button after the password field
    const container = passwordField.parentElement;
    if (container) {
      // Check if button already exists
      if (!container.querySelector('.passmemo-fill-btn')) {
        passwordField.insertAdjacentElement('afterend', this.button);
      }
    }

    // Add event listeners to username/email fields to reset button state
    this.setupUsernameListeners();

    // Set up username selector dropdown (appears on focus)
    this.setupUsernameSelector();
  }

  /**
   * Auto-populate username field with default username from config
   */
  private async autopopulateUsername(): Promise<void> {
    try {
      const request = { action: 'get_config' };
      const response = await sendMessageSafe(request);


      if (response && response.success && response.config && response.config.default_username) {
        const usernameField = this.context.usernameField || this.context.emailField;


        // Only auto-fill if field is empty
        if (usernameField && !usernameField.value.trim()) {
          usernameField.value = response.config.default_username;
          usernameField.dispatchEvent(new Event('input', { bubbles: true }));
          usernameField.dispatchEvent(new Event('change', { bubbles: true }));
        } else {
        }
      } else {
      }
    } catch (error) {
      console.error('[PassAlways] Failed to auto-populate username:', error);
      // Non-critical error, continue initialization
    }
  }

  /**
   * Setup event listeners on username/email fields to reset button state
   */
  private setupUsernameListeners(): void {
    const fields = [this.context.usernameField, this.context.emailField].filter(Boolean);

    fields.forEach((field) => {
      field?.addEventListener('input', () => {
        // Reset button to default state when username changes
        if (this.button && this.button.disabled) {
          this.setButtonState('default', '🔐 Fill Password');
        }

        // Hide username selector when user starts typing
        this.hideUsernameSelector();
      });
    });
  }

  /**
   * Create the inline "Fill Password" button
   */
  private createInlineButton(): HTMLButtonElement {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'passmemo-generate-btn passmemo-fill-btn';
    button.innerHTML = '🔐 Fill Password';
    button.title = 'Fill password with PassAlways';

    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.handleFill();
    });

    return button;
  }

  /**
   * Handle password filling (Phase 6: New IPC flow)
   */
  private async handleFill(): Promise<void> {
    try {
      if (!this.button) return;

      // Check if this is a password reset page (no username field in context)
      const isPasswordResetPage = !this.context.usernameField && !this.context.emailField;

      if (isPasswordResetPage) {
        // On password reset pages, direct user to use Authenticator's Password Generator
        this.showPasswordResetHelp();
        return;
      }

      // Show loading state
      this.setButtonState('loading', 'Filling...');

      const site = getCurrentSite();
      const rawUsername = this.getUsername();

      if (!rawUsername) {
        this.showError('Please enter your username or email first');
        // Reset button state so it can be clicked again
        this.setButtonState('default', '🔐 Fill Password');
        return;
      }

      // Normalize username for consistent password generation
      const username = normalizeUsername(rawUsername);

      // Store for later use
      this.currentSite = site;
      this.currentUsername = username;

      // Store username in sessionStorage for TOTP auto-fill (after password entry, 2FA may appear)
      sessionStorage.setItem('passalways_last_username', username);
      sessionStorage.setItem('passalways_last_site', site);

      // Phase 6: Request password via new IPC flow
      await this.requestPasswordViaIpc(site, username);

      // If we reach here, password is in this.currentPassword
      console.log('[PassAlways] Current password status:', {
        hasPassword: !!this.currentPassword,
        passwordLength: this.currentPassword?.length || 0
      });

      if (this.currentPassword) {
        // Set flag to prevent username selector from showing during auto-fill
        this.isAutoFilling = true;

        // Fill both username and password fields
        console.log('[PassAlways] Filling fields with username:', rawUsername);
        console.log('[PassAlways] About to fill password (first 4 chars):', this.currentPassword.substring(0, 4) + '****');
        console.log('[PassAlways] Password field exists:', !!this.context.passwordFields[0]);

        this.fillUsernameField(rawUsername);
        this.fillPasswordField(this.context.passwordFields[0], this.currentPassword);

        console.log('[PassAlways] Fields filled successfully');

        // Hide username selector dropdown after filling credentials
        this.hideUsernameSelector();

        // Clear auto-fill flag after a short delay to ensure events have processed
        setTimeout(() => {
          this.isAutoFilling = false;
        }, 100);

        this.setButtonState('success', '✓ Credentials Filled');

        this.showNotification(
          'Credentials filled!',
          `Username (${rawUsername}) and password have been filled. You can now log in.`,
          'success'
        );

        // Check if site is known for monitoring
        const metadata = await this.getSiteMetadata(site, username);
        if (metadata && metadata.attributes) {
          // Monitor for login result
          this.monitorLoginResult(site, username, metadata.attributes.version);
        }

        // Reset button after 3 seconds
        setTimeout(() => {
          this.setButtonState('default', '🔐 Fill Password');
        }, 3000);
      } else {
        console.error('[PassAlways] ERROR: No password after requestPasswordViaIpc completed');
        this.showError('Password generation failed - no password returned');
        this.setButtonState('default', '🔐 Fill Password');
      }
    } catch (error) {
      console.error('Signin handler error:', error);
      this.showError(error instanceof Error ? error.message : 'Failed to fill password');
      this.setButtonState('default', '🔐 Fill Password');
    }
  }

  /**
   * Show help message for password reset pages
   */
  private showPasswordResetHelp(): void {
    this.showNotification(
      'Use PassAlways Authenticator',
      'For password reset, open the PassAlways Authenticator app and use the Password Generator to create a new password for this site. You can then copy and paste it here.',
      'info',
      10000 // Show for 10 seconds
    );

    // Change button to open Authenticator
    if (this.button) {
      this.button.innerHTML = '🔓 Open Authenticator';
      this.button.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.openAuthenticator();
      };
    }
  }

  /**
   * Open/focus the Authenticator app
   */
  private async openAuthenticator(): Promise<void> {
    try {
      const request = {
        action: 'open_authenticator',
        site: getCurrentSite(),
      };

      await sendMessageSafe(request);

      this.showNotification(
        'Authenticator Opened',
        'Use the Password Generator tab in the Authenticator to create a password for this site.',
        'success'
      );
    } catch (error) {
      console.error('[PassAlways] Failed to open Authenticator:', error);
      this.showNotification(
        'Please Open Authenticator Manually',
        'Open the PassAlways Authenticator app from your system tray or applications menu, then use the Password Generator.',
        'warning',
        8000
      );
    }
  }

  /**
   * Phase 6: Request password via new IPC flow
   * Desktop app handles TOTP frequency logic
   */
  private async requestPasswordViaIpc(site: string, username: string): Promise<void> {
    try {

      // Send password request to native host
      const request: GeneratePasswordViaIpcRequest = {
        action: 'generate_password_ipc',
        site: site,
        username: username,
      };

      const response = await sendMessageSafe<GeneratePasswordViaIpcResponse>(request);

      if (!response.success) {
        throw new Error(response.error || 'Password request failed');
      }

      // Handle different statuses
      switch (response.status) {
        case 'password_generated':
          // Success! Password ready
          this.currentPassword = response.password!;
          break;

        case 'session_locked':
          // Desktop app locked - inform user
          throw new Error('Desktop app is locked. Please unlock the PassAlways app first.');

        case 'totp_required':
          // TOTP needed - show modal and submit
          await this.handleTotpRequired(site, username);
          break;

        default:
          throw new Error('Unknown response status from desktop app');
      }
    } catch (error) {
      console.error('[PassAlways] Password request error:', error);
      throw error;
    }
  }

  /**
   * Phase 6: Handle TOTP requirement by showing modal and submitting code
   */
  private async handleTotpRequired(site: string, username: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.totpModal.show(
        '', // No TOTP code displayed anymore (desktop app shows via notification)
        '', // No session ID needed
        site,
        async (enteredCode: string) => {
          try {

            // Submit TOTP to desktop app via native host
            console.log('[PassAlways] Submitting TOTP code:', enteredCode.substring(0, 2) + '****');
            const submitRequest: SubmitTotpRequest = {
              action: 'submit_totp',
              totp_code: enteredCode,
              site: site,
              username: username,
            };

            const submitResponse = await sendMessageSafe<SubmitTotpResponse>(submitRequest);
            console.log('[PassAlways] TOTP submit response:', submitResponse);

            if (!submitResponse.success) {
              console.error('[PassAlways] TOTP submission failed:', submitResponse.error);
              throw new Error(submitResponse.error || 'TOTP submission failed');
            }

            if (!submitResponse.password) {
              console.error('[PassAlways] No password in response');
              throw new Error('No password received after TOTP validation');
            }

            // Password generated after TOTP
            this.currentPassword = submitResponse.password!;
            console.log('[PassAlways] Password received, length:', this.currentPassword.length);

            // Set flag BEFORE hiding modal to prevent username selector from showing
            // when browser refocuses the username field after modal closes
            this.isAutoFilling = true;

            this.totpModal.hide();
            resolve();
          } catch (error) {
            console.error('[PassAlways] TOTP submission error:', error);
            this.totpModal.showError('TOTP submission failed. Please try again.');
            reject(error);
          }
        },
        () => {
          // User cancelled
          this.totpModal.hide();
          reject(new Error('User cancelled TOTP entry'));
        }
      );
    });
  }

  /**
   * Fill password for known site
   */
  private async fillKnownSite(site: string, username: string, version: number): Promise<void> {
    const request: GeneratePasswordRequest = {
      action: 'generate_password',
      site,
      username,
      version,
      autoRetry: true,
    };

    const response = await sendMessageSafe<GeneratePasswordResponse>(request);

    if (response.success && response.password) {
      // Fill password field with comprehensive event triggering
      this.fillPasswordField(this.context.passwordFields[0], response.password);

      this.setButtonState('success', '✓ Password Filled');

      this.showNotification(
        'Password filled!',
        'Your PassAlways password has been filled. You can now log in.',
        'success'
      );

      // Monitor for login result
      this.monitorLoginResult(site, username, version);

      // Reset button after 3 seconds
      setTimeout(() => {
        this.setButtonState('default', '🔐 Fill Password');
      }, 3000);
    } else {
      throw new Error(response.error || 'Failed to generate password');
    }
  }

  /**
   * Fill password for new/unknown site
   */
  private async fillNewSite(site: string, username: string): Promise<void> {
    // Show first-time warning
    const confirmed = await this.showFirstTimeWarning(site, username);

    if (!confirmed) {
      this.setButtonState('default', '🔐 Fill Password');
      return;
    }

    // Generate password with version 0
    const request: GeneratePasswordRequest = {
      action: 'generate_password',
      site,
      username,
      version: 0,
      autoRetry: true,
    };

    const response = await sendMessageSafe<GeneratePasswordResponse>(request);

    if (response.success && response.password) {
      // Fill password field with comprehensive event triggering
      this.fillPasswordField(this.context.passwordFields[0], response.password);

      this.setButtonState('success', '✓ Password Filled');

      this.showNotification(
        'Password generated for first time',
        'This is the first time using PassAlways on this site. If login fails, you may need to register first.',
        'info'
      );

      // Reset button after 3 seconds
      setTimeout(() => {
        this.setButtonState('default', '🔐 Fill Password');
      }, 3000);
    } else {
      throw new Error(response.error || 'Failed to generate password');
    }
  }

  /**
   * Fill username field with comprehensive event triggering for framework compatibility
   */
  private fillUsernameField(username: string): void {
    const usernameField = this.context.usernameField || this.context.emailField;
    if (!usernameField) {
      return;
    }

    // Set the value using native setter to bypass React/Vue's event system
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      'value'
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(usernameField, username);
    } else {
      usernameField.value = username;
    }

    // Trigger all events that frameworks might listen to
    usernameField.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
    usernameField.dispatchEvent(new Event('blur', { bubbles: true, composed: true }));

    // Note: Not dispatching focus event to prevent triggering username selector dropdown

  }

  /**
   * Fill password field with comprehensive event triggering for framework compatibility
   */
  private fillPasswordField(field: HTMLInputElement, password: string): void {
    // Set the value using native setter to bypass React/Vue's event system
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      'value'
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(field, password);
    } else {
      field.value = password;
    }

    // Trigger all events that frameworks might listen to
    // Using 'composed: true' allows events to cross shadow DOM boundaries
    field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('blur', { bubbles: true, composed: true }));

    // Keyboard events for frameworks that track user interaction
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, composed: true, key: 'Enter' }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, composed: true, key: 'Enter' }));
    field.dispatchEvent(new KeyboardEvent('keypress', { bubbles: true, composed: true, key: 'Enter' }));

    // Focus event to simulate user interaction
    field.dispatchEvent(new FocusEvent('focus', { bubbles: true, composed: true }));

    // Add password visibility toggle
    this.addPasswordToggle(field);
  }

  /**
   * Add password visibility toggle button next to password field
   */
  private addPasswordToggle(field: HTMLInputElement): void {
    // Remove existing toggle if present (instance variable)
    if (this.passwordToggle) {
      this.passwordToggle.remove();
      this.passwordToggle = null;
    }

    // Remove any orphaned toggles in the DOM (from previous instances)
    const existingToggles = document.querySelectorAll('.passmemo-password-toggle');
    existingToggles.forEach(toggle => toggle.remove());

    // Create toggle button
    this.passwordToggle = document.createElement('button');
    this.passwordToggle.type = 'button';
    this.passwordToggle.className = 'passmemo-password-toggle passmemo-password-toggle-hidden';
    this.passwordToggle.innerHTML = '👁️';
    this.passwordToggle.title = 'Show/hide password';
    this.passwordToggle.setAttribute('aria-label', 'Toggle password visibility');

    // Position it after the password field
    field.insertAdjacentElement('afterend', this.passwordToggle);

    // Add click handler
    this.passwordToggle.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.togglePasswordVisibility(field);
    });

  }

  /**
   * Toggle password visibility
   */
  private togglePasswordVisibility(field: HTMLInputElement): void {
    if (field.type === 'password') {
      field.type = 'text';
      if (this.passwordToggle) {
        this.passwordToggle.innerHTML = '🙈';
        this.passwordToggle.className = 'passmemo-password-toggle passmemo-password-toggle-visible';
        this.passwordToggle.title = 'Hide password';
      }
    } else {
      field.type = 'password';
      if (this.passwordToggle) {
        this.passwordToggle.innerHTML = '👁️';
        this.passwordToggle.className = 'passmemo-password-toggle passmemo-password-toggle-hidden';
        this.passwordToggle.title = 'Show password';
      }
    }
  }

  /**
   * Get username from form fields
   */
  private getUsername(): string {
    const usernameField = this.context.usernameField;
    const emailField = this.context.emailField;

    if (usernameField?.value) {
      return usernameField.value.trim();
    }

    if (emailField?.value) {
      return emailField.value.trim();
    }

    return '';
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
   * Show first-time warning dialog
   */
  private async showFirstTimeWarning(site: string, username: string): Promise<boolean> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'passmemo-overlay';
      overlay.innerHTML = `
        <div class="passmemo-dialog">
          <div class="passmemo-dialog-header">
            <h3>First Time on ${site}</h3>
          </div>
          <div class="passmemo-dialog-content">
            <p>This is the first time using PassAlways on this site with username <strong>${username}</strong>.</p>
            <p>If you haven't registered with PassAlways on this site before, the login will fail.</p>
            <p>Do you want to continue?</p>
          </div>
          <div class="passmemo-dialog-actions">
            <button class="passmemo-dialog-btn passmemo-dialog-btn-secondary" data-action="cancel">Cancel</button>
            <button class="passmemo-dialog-btn passmemo-dialog-btn-primary" data-action="confirm">Fill Password</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      const handleClick = (e: Event) => {
        const target = e.target as HTMLElement;
        const action = target.getAttribute('data-action');

        if (action === 'confirm') {
          overlay.remove();
          resolve(true);
        } else if (action === 'cancel') {
          overlay.remove();
          resolve(false);
        }
      };

      overlay.addEventListener('click', handleClick);
    });
  }

  /**
   * Monitor login result to detect success/failure
   */
  private monitorLoginResult(site: string, username: string, currentVersion: number): void {
    setTimeout(() => {
      // Check if URL changed (successful login)
      if (window.location.href !== this.originalUrl) {
        // Update last used timestamp (already done by background script)
        return;
      }

      // Check for error messages
      const bodyText = document.body.innerText.toLowerCase();
      const hasError = /(incorrect|invalid|wrong|failed|error).*password/.test(bodyText) ||
                      /password.*(incorrect|invalid|wrong|failed|error)/.test(bodyText);

      if (hasError) {
        this.showVersionSelector(site, username, currentVersion);
      }
    }, 2000);
  }

  /**
   * Show version selector dialog for failed logins
   */
  private showVersionSelector(site: string, username: string, currentVersion: number): void {
    const overlay = document.createElement('div');
    overlay.className = 'passmemo-overlay';
    overlay.innerHTML = `
      <div class="passmemo-dialog">
        <div class="passmemo-dialog-header">
          <h3>Login Failed - Try Different Version?</h3>
        </div>
        <div class="passmemo-dialog-content">
          <p>The login appears to have failed. You may have changed your password on this site.</p>
          <p>Current version: <strong>${currentVersion}</strong></p>
          <p>Select a different version to try:</p>
          <select class="passmemo-version-select">
            ${Array.from({ length: Math.max(5, currentVersion + 1) }, (_, i) => `
              <option value="${i}" ${i === currentVersion ? 'selected' : ''}>Version ${i}</option>
            `).join('')}
          </select>
        </div>
        <div class="passmemo-dialog-actions">
          <button class="passmemo-dialog-btn passmemo-dialog-btn-secondary" data-action="cancel">Cancel</button>
          <button class="passmemo-dialog-btn passmemo-dialog-btn-primary" data-action="retry">Retry with Selected Version</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const select = overlay.querySelector('.passmemo-version-select') as HTMLSelectElement;
    const handleClick = async (e: Event) => {
      const target = e.target as HTMLElement;
      const action = target.getAttribute('data-action');

      if (action === 'retry') {
        const selectedVersion = parseInt(select.value, 10);
        overlay.remove();
        await this.retryWithVersion(site, username, selectedVersion);
      } else if (action === 'cancel') {
        overlay.remove();
      }
    };

    overlay.addEventListener('click', handleClick);
  }

  /**
   * Retry filling password with different version
   */
  private async retryWithVersion(site: string, username: string, version: number): Promise<void> {
    try {
      const request: GeneratePasswordRequest = {
        action: 'generate_password',
        site,
        username,
        version,
        autoRetry: true,
      };

      const response = await sendMessageSafe<GeneratePasswordResponse>(request);

      if (response.success && response.password) {
        this.context.passwordFields[0].value = response.password;
        this.context.passwordFields[0].dispatchEvent(new Event('input', { bubbles: true }));
        this.context.passwordFields[0].dispatchEvent(new Event('change', { bubbles: true }));

        this.showNotification(
          `Password filled with version ${version}`,
          'Try logging in again with this version.',
          'success'
        );
      }
    } catch (error) {
      this.showError(error instanceof Error ? error.message : 'Failed to retry');
    }
  }

  /**
   * Set button state (loading, success, error)
   */
  private setButtonState(state: 'default' | 'loading' | 'success' | 'error', text: string): void {
    if (!this.button) return;

    this.button.textContent = text;
    this.button.className = `passmemo-generate-btn passmemo-fill-btn passmemo-btn-${state}`;
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
   * Set up username selector for multiple usernames
   */
  private setupUsernameSelector(): void {
    const usernameField = this.context.usernameField || this.context.emailField;
    if (!usernameField) return;

    // Add click listener to show username selector
    usernameField.addEventListener('click', async (e) => {
      e.stopPropagation();
      await this.showUsernameSelector();
    });

    // Add focus listener as well
    usernameField.addEventListener('focus', async (e) => {
      e.stopPropagation();
      await this.showUsernameSelector();
    });

    // Close selector when clicking outside
    document.addEventListener('click', (e) => {
      if (this.usernameSelectorVisible && this.usernameSelector) {
        const target = e.target as HTMLElement;
        if (!this.usernameSelector.contains(target) && target !== usernameField) {
          this.hideUsernameSelector();
        }
      }
    });
  }

  /**
   * Show username selector dropdown
   */
  private async showUsernameSelector(): Promise<void> {
    const usernameField = this.context.usernameField || this.context.emailField;
    if (!usernameField) return;

    // Don't show if already visible or during auto-fill
    if (this.usernameSelectorVisible || this.isAutoFilling) return;

    try {
      const site = getCurrentSite();
      const request = {
        action: 'get_site_usernames_ipc',
        site,
      };

      const response = await sendMessageSafe<any>(request);

      console.log('[PassAlways] Username selector response:', response);

      if (!response.success || !response.usernames || response.usernames.length === 0) {
        // No saved usernames for this site
        console.log('[PassAlways] No usernames found for site:', site);
        return;
      }

      // Only show selector if there are multiple usernames OR at least one saved username
      if (response.usernames.length === 0) {
        return;
      }

      console.log('[PassAlways] Creating username selector with', response.usernames.length, 'usernames');

      // Create selector dropdown
      this.usernameSelector = document.createElement('div');
      this.usernameSelector.className = 'passmemo-username-selector';

      // Add header
      const header = document.createElement('div');
      header.className = 'passmemo-username-selector-header';
      header.textContent = `Saved usernames for ${site}`;
      this.usernameSelector.appendChild(header);

      // Add username options
      response.usernames.forEach((username) => {
        const option = document.createElement('div');
        const isDefault = username === response.default_username;

        option.className = `passmemo-username-option ${isDefault ? 'passmemo-username-option-default' : ''}`;
        option.innerHTML = `
          <span class="passmemo-username-icon">👤</span>
          <span class="passmemo-username-text">${this.escapeHtml(username)}</span>
          ${isDefault ? '<span class="passmemo-username-badge">Default</span>' : ''}
        `;

        option.addEventListener('click', (e) => {
          e.stopPropagation();
          this.selectUsername(username);
        });

        this.usernameSelector.appendChild(option);
      });

      // Position the selector below the username field
      const rect = usernameField.getBoundingClientRect();
      this.usernameSelector.style.position = 'fixed';
      this.usernameSelector.style.top = `${rect.bottom + 4}px`;
      this.usernameSelector.style.left = `${rect.left}px`;
      this.usernameSelector.style.minWidth = `${rect.width}px`;

      document.body.appendChild(this.usernameSelector);
      this.usernameSelectorVisible = true;
    } catch (error) {
      console.error('[PassAlways] Failed to show username selector:', error);
    }
  }

  /**
   * Hide username selector
   */
  private hideUsernameSelector(): void {
    if (this.usernameSelector) {
      this.usernameSelector.remove();
      this.usernameSelector = null;
    }
    this.usernameSelectorVisible = false;
  }

  /**
   * Select a username from the dropdown
   */
  private selectUsername(username: string): void {
    const usernameField = this.context.usernameField || this.context.emailField;

    if (usernameField) {
      usernameField.value = username;
      usernameField.dispatchEvent(new Event('input', { bubbles: true }));
      usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    }
    this.hideUsernameSelector();
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
   * Cleanup when form type changes
   */
  destroy(): void {
    if (this.button) {
      this.button.remove();
      this.button = null;
    }
    if (this.passwordToggle) {
      this.passwordToggle.remove();
      this.passwordToggle = null;
    }
    this.hideUsernameSelector();
  }
}
