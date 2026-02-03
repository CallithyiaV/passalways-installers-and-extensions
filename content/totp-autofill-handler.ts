// PassAlways Browser Extension - TOTP Auto-Fill Handler
// Co-Authored-By: Project Engineer MelAnee Hannah

import type { FormContext } from '../shared/types';

// Firefox/Chrome API compatibility
declare const browser: typeof chrome | undefined;
const extensionAPI = typeof browser !== 'undefined' ? browser : chrome;

/**
 * Handles TOTP auto-fill for 2FA fields detected on websites
 */
export class TotpAutofillHandler {
  private context: FormContext;
  private fillButton: HTMLButtonElement | null = null;
  private site: string;
  private username: string;
  private destroyed = false;

  constructor(context: FormContext) {
    this.context = context;
    this.site = this.extractSite();
    this.username = ''; // Will be determined during initialization
  }

  /**
   * Initialize the TOTP auto-fill handler
   */
  async initialize(): Promise<void> {
    if (this.destroyed) return;

    // Determine username from form context or use default
    this.username = await this.determineUsername();

    if (!this.username) {
      console.log('[TOTP AutoFill] No username found, skipping TOTP auto-fill');
      console.log('[TOTP AutoFill] sessionStorage check:', {
        username: sessionStorage.getItem('passalways_last_username'),
        site: sessionStorage.getItem('passalways_last_site')
      });
      return;
    }

    console.log('[TOTP AutoFill] Using username:', this.username, 'for site:', this.site);

    // Check if TOTP is configured for this site/username
    console.log('[TOTP AutoFill] Checking TOTP config...');
    const hasTotpConfig = await this.checkTotpConfig(this.site, this.username);
    console.log('[TOTP AutoFill] TOTP config check result:', hasTotpConfig);

    if (!hasTotpConfig) {
      console.log('[TOTP AutoFill] No TOTP config for', this.site, this.username);
      return;
    }

    // Show authenticator window so user can see and manually enter TOTP code
    console.log('[TOTP AutoFill] Showing authenticator window for site:', this.site);
    await this.showAuthenticatorWindow();
  }

  /**
   * Extract site/domain from current URL
   */
  private extractSite(): string {
    const url = new URL(window.location.href);
    return this.normalizeSite(url.hostname);
  }

  /**
   * Normalize site by removing common prefixes (www, m, mobile, wap)
   */
  private normalizeSite(hostname: string): string {
    if (!hostname) return hostname;
    const commonPrefixes = ['www', 'm', 'mobile', 'wap'];
    const parts = hostname.split('.');
    if (parts.length >= 3 && commonPrefixes.includes(parts[0].toLowerCase())) {
      parts.shift();
      return parts.join('.');
    }
    return hostname;
  }

  /**
   * Determine username from form context
   */
  private async determineUsername(): Promise<string> {
    // Try to get username from form fields
    if (this.context.usernameField?.value) {
      return this.context.usernameField.value;
    }

    if (this.context.emailField?.value) {
      return this.context.emailField.value;
    }

    // Check sessionStorage for username (may have been saved during password entry)
    const storedUsername = sessionStorage.getItem('passalways_last_username');
    if (storedUsername) {
      console.log('[TOTP AutoFill] Found username in sessionStorage:', storedUsername);
      return storedUsername;
    }

    // Fallback: try to get default username from config
    try {
      const response = await extensionAPI.runtime.sendMessage({
        action: 'get_default_username',
      });

      if (response?.success && response.username) {
        return response.username;
      }
    } catch (error) {
      console.error('[TOTP AutoFill] Failed to get default username:', error);
    }

    return '';
  }

  /**
   * Check if TOTP is configured for this site/username
   */
  private async checkTotpConfig(site: string, username: string): Promise<boolean> {
    try {
      const response = await extensionAPI.runtime.sendMessage({
        action: 'has_totp_config',
        site,
        username,
      });

      return response?.success && response.has_config === true;
    } catch (error) {
      console.error('[TOTP AutoFill] Failed to check TOTP config:', error);
      return false;
    }
  }

  /**
   * Show the authenticator window in PassAlways desktop app
   * User can then view the TOTP codes and manually enter them
   */
  private async showAuthenticatorWindow(): Promise<void> {
    try {
      console.log('[TOTP AutoFill] Requesting authenticator window for:', this.site);

      const response = await extensionAPI.runtime.sendMessage({
        action: 'show_authenticator',
        site: this.site,
      });

      if (response?.success) {
        console.log('[TOTP AutoFill] Authenticator window shown successfully');
      } else {
        console.warn('[TOTP AutoFill] Failed to show authenticator:', response?.error);
      }
    } catch (error) {
      console.error('[TOTP AutoFill] Error showing authenticator window:', error);
    }
  }

  /**
   * Trigger push approval request and wait for user response
   */
  private async triggerPushApproval(): Promise<void> {
    if (!this.context.otpField || this.destroyed) return;

    try {
      console.log('[TOTP Push] Triggering push approval for', this.site, this.username);

      // Send push request to background script (which forwards to PassAlways desktop)
      // The response now includes the TOTP code directly
      const response = await extensionAPI.runtime.sendMessage({
        action: 'trigger_push_approval',
        site: this.site,
        username: this.username,
      });

      if (response?.success && response.approved === true && response.code) {
        console.log('[TOTP Push] Approved - auto-filling TOTP code:', response.code);

        // Fill the OTP field(s) with the code from push approval
        this.fillOtpCode(response.code);

        // Focus the field
        this.context.otpField.focus();

        console.log('[TOTP Push] TOTP code auto-filled successfully');
      } else if (response?.approved === false) {
        console.log('[TOTP Push] Denied - showing manual button as fallback');
        // User denied - show manual button as fallback
        this.createFillButton();
      } else {
        throw new Error(response?.error || 'Push approval failed or no TOTP code returned');
      }
    } catch (error) {
      console.error('[TOTP Push] Failed to get push approval:', error);
      // Fallback to manual button on error
      console.log('[TOTP Push] Falling back to manual button');
      this.createFillButton();
    }
  }

  /**
   * Create and inject the "Fill 2FA Code" button
   */
  private createFillButton(): void {
    if (!this.context.otpField || this.destroyed) return;

    // Create button element
    this.fillButton = document.createElement('button');
    this.fillButton.type = 'button';
    this.fillButton.textContent = 'Fill 2FA Code';
    this.fillButton.className = 'passalways-totp-fill-button';

    // Style the button
    Object.assign(this.fillButton.style, {
      position: 'absolute',
      zIndex: '10000',
      padding: '6px 12px',
      backgroundColor: '#4CAF50',
      color: 'white',
      border: 'none',
      borderRadius: '4px',
      fontSize: '13px',
      fontWeight: '500',
      cursor: 'pointer',
      boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
      transition: 'background-color 0.2s',
    });

    // Hover effect
    this.fillButton.addEventListener('mouseenter', () => {
      if (this.fillButton) {
        this.fillButton.style.backgroundColor = '#45a049';
      }
    });

    this.fillButton.addEventListener('mouseleave', () => {
      if (this.fillButton) {
        this.fillButton.style.backgroundColor = '#4CAF50';
      }
    });

    // Click handler
    this.fillButton.addEventListener('click', () => this.handleFill());

    // Position button relative to OTP field
    this.positionButton();

    // Inject button into DOM
    document.body.appendChild(this.fillButton);

    // Reposition on window resize
    window.addEventListener('resize', () => this.positionButton());
  }

  /**
   * Position the fill button relative to the OTP field
   */
  private positionButton(): void {
    if (!this.fillButton || !this.context.otpField || this.destroyed) return;

    const otpField = this.context.otpField;
    const container = otpField.closest('form') || otpField.parentElement;

    const scrollY = window.scrollY || window.pageYOffset;
    const scrollX = window.scrollX || window.pageXOffset;

    if (!container) {
      // Fallback: position to the right of the single field
      const rect = otpField.getBoundingClientRect();
      this.fillButton.style.top = `${rect.top + scrollY}px`;
      this.fillButton.style.left = `${rect.right + scrollX + 10}px`;
      return;
    }

    // Check for split OTP inputs (6 separate boxes for digits)
    const allInputs = Array.from(container.querySelectorAll<HTMLInputElement>('input'));
    const splitInputs = allInputs.filter(input => {
      const maxLen = input.maxLength;
      const isNumeric =
        input.inputMode === 'numeric' ||
        input.type === 'tel' ||
        input.type === 'number' ||
        input.type === 'text';
      return isNumeric && maxLen >= 1 && maxLen <= 2;
    });

    // If split inputs detected (4-8 separate digit boxes), position below them
    if (splitInputs.length >= 4 && splitInputs.length <= 8) {
      // Get bounding rect of the last input
      const lastInput = splitInputs[splitInputs.length - 1];
      const lastRect = lastInput.getBoundingClientRect();
      const firstRect = splitInputs[0].getBoundingClientRect();

      // Position button below the input row, aligned with the first input
      this.fillButton.style.top = `${lastRect.bottom + scrollY + 8}px`;
      this.fillButton.style.left = `${firstRect.left + scrollX}px`;
    } else {
      // Single input - position to the right as before
      const rect = otpField.getBoundingClientRect();
      this.fillButton.style.top = `${rect.top + scrollY}px`;
      this.fillButton.style.left = `${rect.right + scrollX + 10}px`;
    }
  }

  /**
   * Handle fill button click - request and fill TOTP code
   */
  private async handleFill(): Promise<void> {
    if (!this.context.otpField || this.destroyed) return;

    try {
      // Disable button and show loading state
      if (this.fillButton) {
        this.fillButton.disabled = true;
        this.fillButton.textContent = 'Generating...';
      }

      // Request TOTP code from background script
      const response = await extensionAPI.runtime.sendMessage({
        action: 'get_totp_code',
        site: this.site,
        username: this.username,
      });

      if (response?.success && response.code) {
        // Fill the OTP field(s)
        this.fillOtpCode(response.code);

        // Show success feedback
        if (this.fillButton) {
          this.fillButton.textContent = '✓ Filled';
          this.fillButton.style.backgroundColor = '#2196F3';
        }

        // Focus the OTP field
        this.context.otpField.focus();

        // Reset button after 2 seconds
        setTimeout(() => {
          if (this.fillButton && !this.destroyed) {
            this.fillButton.disabled = false;
            this.fillButton.textContent = 'Fill 2FA Code';
            this.fillButton.style.backgroundColor = '#4CAF50';
          }
        }, 2000);
      } else {
        throw new Error(response?.error || 'Failed to generate TOTP code');
      }
    } catch (error) {
      console.error('[TOTP AutoFill] Failed to fill TOTP code:', error);

      // Show error feedback
      if (this.fillButton) {
        this.fillButton.textContent = '✗ Error';
        this.fillButton.style.backgroundColor = '#f44336';
      }

      // Reset button after 2 seconds
      setTimeout(() => {
        if (this.fillButton && !this.destroyed) {
          this.fillButton.disabled = false;
          this.fillButton.textContent = 'Fill 2FA Code';
          this.fillButton.style.backgroundColor = '#4CAF50';
        }
      }, 2000);
    }
  }

  /**
   * Fill OTP code into field(s) - handles both single and split inputs
   */
  private fillOtpCode(code: string): void {
    const otpField = this.context.otpField;

    // Check if this is a split OTP input (6 separate boxes for 6 digits)
    const container = otpField.closest('form') || otpField.parentElement;
    if (!container) {
      // Fallback: just fill the single field
      otpField.value = code;
      otpField.dispatchEvent(new Event('input', { bubbles: true }));
      otpField.dispatchEvent(new Event('change', { bubbles: true }));
      return;
    }

    // Find all small numeric inputs in the container
    const allInputs = Array.from(container.querySelectorAll<HTMLInputElement>('input'));
    const splitInputs = allInputs.filter(input => {
      const maxLen = input.maxLength;
      const isNumeric = input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number' || input.type === 'text';
      return isNumeric && maxLen >= 1 && maxLen <= 2;
    });

    // If we found 4-8 split inputs, fill them individually
    if (splitInputs.length >= 4 && splitInputs.length <= 8) {
      const digits = code.replace(/\s/g, '').split(''); // Remove spaces and split into digits

      splitInputs.forEach((input, index) => {
        if (index < digits.length) {
          input.value = digits[index];
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    } else {
      // Not a split input, fill normally
      otpField.value = code;
      otpField.dispatchEvent(new Event('input', { bubbles: true }));
      otpField.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  /**
   * Destroy the handler and clean up resources
   */
  destroy(): void {
    this.destroyed = true;

    if (this.fillButton && this.fillButton.parentNode) {
      this.fillButton.parentNode.removeChild(this.fillButton);
      this.fillButton = null;
    }
  }
}
