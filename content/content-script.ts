// PassAlways Browser Extension - Main Content Script
// Co-Authored-By: Project Engineer MelAnee Hannah

import { FormDetector } from './form-detector';
import { SignupHandler } from './signup-handler';
import { SigninHandler } from './signin-handler';
import { PasswordChangeHandler } from './password-change-handler';
import { TotpAutofillHandler } from './totp-autofill-handler';
import type { FormContext } from '../shared/types';

// Firefox/Chrome API compatibility
declare const browser: typeof chrome | undefined;
const extensionAPI = typeof browser !== 'undefined' ? browser : chrome;

/**
 * Main orchestrator for content scripts
 * Detects forms and delegates to appropriate handler
 */
class PassAlwaysContentScript {
  private currentHandler: SignupHandler | SigninHandler | PasswordChangeHandler | TotpAutofillHandler | null = null;
  private currentContext: FormContext | null = null;
  private totpObserver: MutationObserver | null = null;
  private authenticatorShown: boolean = false;

  constructor() {
    this.initialize();
  }

  /**
   * Initialize content script
   */
  private initialize(): void {
    console.log('[PassAlways] Content script initialized on:', window.location.href);

    // Check if this is a 2FA page and show authenticator window
    this.check2FAPageAndShowAuthenticator();

    // Start monitoring for forms
    FormDetector.startMonitoring((context) => {
      this.handleFormDetection(context);
    });

    // Also observe for 2FA fields that appear after password entry
    this.totpObserver = FormDetector.observeFor2FA((context) => {
      this.handleFormDetection(context);
    });

    // Watch for DOM changes that might indicate 2FA page transition
    this.observeFor2FAPageContent();
  }

  /**
   * Check if we're on a 2FA page and show the authenticator window
   */
  private async check2FAPageAndShowAuthenticator(): Promise<void> {
    if (this.authenticatorShown) return;

    if (FormDetector.is2FAPage()) {
      console.log('[PassAlways] 2FA page detected, showing authenticator window');
      this.authenticatorShown = true;
      await this.showAuthenticatorWindow();
    }
  }

  /**
   * Observe for page content changes that might indicate 2FA page
   */
  private observeFor2FAPageContent(): void {
    const observer = new MutationObserver(() => {
      this.check2FAPageAndShowAuthenticator();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  /**
   * Show the authenticator window in PassAlways desktop app
   */
  private async showAuthenticatorWindow(): Promise<void> {
    try {
      const site = this.extractSite();
      console.log('[PassAlways] Requesting authenticator window for site:', site);

      const response = await extensionAPI.runtime.sendMessage({
        action: 'show_authenticator',
        site: site,
      });

      if (response?.success) {
        console.log('[PassAlways] Authenticator window shown successfully');
      } else {
        console.warn('[PassAlways] Failed to show authenticator:', response?.error);
      }
    } catch (error) {
      console.error('[PassAlways] Error showing authenticator window:', error);
    }
  }

  /**
   * Extract normalized site from current URL
   */
  private extractSite(): string {
    const hostname = window.location.hostname;
    // Remove common prefixes like www, m, mobile
    const commonPrefixes = ['www', 'm', 'mobile', 'wap'];
    const parts = hostname.split('.');
    if (parts.length >= 3 && commonPrefixes.includes(parts[0].toLowerCase())) {
      parts.shift();
      return parts.join('.');
    }
    return hostname;
  }

  /**
   * Handle form detection - create appropriate handler
   */
  private handleFormDetection(context: FormContext): void {
    console.log('[PassAlways] Form detected:', context.type, context);

    // Check if context changed
    if (this.currentContext && this.currentContext.type === context.type) {
      console.log('[PassAlways] Same form type, skipping handler recreation');
      return; // Same form type, no need to recreate handler
    }

    // Clean up previous handler
    if (this.currentHandler) {
      this.currentHandler.destroy();
      this.currentHandler = null;
    }

    // Create new handler based on form type
    this.currentContext = context;


    switch (context.type) {
      case 'signup':
        this.currentHandler = new SignupHandler(context);
        break;

      case 'signin':
        this.currentHandler = new SigninHandler(context);
        break;

      case 'password-change':
        this.currentHandler = new PasswordChangeHandler(context);
        break;

      case 'two-factor':
        this.currentHandler = new TotpAutofillHandler(context);
        break;

      default:
        console.warn('Unknown form type:', context.type);
        return;
    }

    // Initialize handler
    this.currentHandler.initialize().catch((error) => {
      console.error('Failed to initialize handler:', error);
    });
  }
}

// Initialize content script
new PassAlwaysContentScript();
