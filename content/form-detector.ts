// PassAlways Browser Extension - Form Detection
// Co-Authored-By: Project Engineer MelAnee Hannah

import type { FormContext } from '../shared/types';

/**
 * Detects password forms and determines their type (signup, signin, password-change)
 * with confidence scoring based on multiple heuristics
 */
export class FormDetector {
  private static readonly SIGNUP_KEYWORDS = /sign[\s-]?up|register|create[\s-]?account|join|new[\s-]?account/i;
  private static readonly SIGNIN_KEYWORDS = /sign[\s-]?in|log[\s-]?in|login|log[\s-]?on/i;
  private static readonly PASSWORD_CHANGE_KEYWORDS = /change[\s-]?password|update[\s-]?password|reset[\s-]?password|new[\s-]?password/i;
  private static readonly SETTINGS_KEYWORDS = /settings|account|security|profile|preferences/i;
  private static readonly PASSWORD_RESET_KEYWORDS = /password[\s-]?retrieval|password[\s-]?recovery|forgot[\s-]?password|reset[\s-]?password|security[\s-]?question|recover[\s-]?account/i;

  // 2FA/OTP detection patterns
  private static readonly OTP_PATTERNS = [
    /\b(otp|totp|2fa|two[\s-]?factor|mfa|multi[\s-]?factor)\b/i,
    /\b(verification|authenticator|security)[\s-]?(code|token)\b/i,
    /\b(code|token|pin)\b/i,
    /\bsms[\s-]?code\b/i,
    /\bauth(entication)?[\s-]?code\b/i,
  ];

  /**
   * Main detection method - analyzes the page and returns form context
   */
  static detect(): FormContext | null {
    // Check for OTP/2FA fields first (higher priority - appears after login)
    const otpField = this.detectOtpField();
    if (otpField) {
      return {
        type: 'two-factor',
        confidence: 90,
        passwordFields: [],
        usernameField: null,
        emailField: null,
        otpField,
        form: otpField.closest('form'),
      };
    }

    const passwordInputs = Array.from(
      document.querySelectorAll<HTMLInputElement>('input[type="password"]:not([disabled])')
    ).filter(input => {
      // Only consider visible password fields
      const style = window.getComputedStyle(input);
      return style.display !== 'none' &&
             style.visibility !== 'hidden' &&
             input.offsetParent !== null &&
             input.offsetWidth > 0 &&
             input.offsetHeight > 0;
    });

    if (passwordInputs.length === 0) {
      return null;
    }

    const fieldCount = passwordInputs.length;
    const hasEmailField = document.querySelector('input[type="email"]:not([disabled])') !== null;
    const hasUsernameField = this.findUsernameField() !== null;
    const pageText = document.body.innerText;
    const url = window.location.href;
    const pathname = window.location.pathname.toLowerCase();

    // EXCLUDE password reset/retrieval/security question pages
    // Only check pathname to avoid false positives from "forgot password" links
    if (this.PASSWORD_RESET_KEYWORDS.test(pathname)) {
      return null;
    }

    // Detect PASSWORD CHANGE (3 fields + settings context)
    if (fieldCount === 3) {
      const isSettingsPage = this.SETTINGS_KEYWORDS.test(pathname) || this.SETTINGS_KEYWORDS.test(pageText);
      const hasChangeKeywords = this.PASSWORD_CHANGE_KEYWORDS.test(pageText);

      if (isSettingsPage || hasChangeKeywords) {
        return {
          type: 'password-change',
          confidence: isSettingsPage && hasChangeKeywords ? 95 : 80,
          passwordFields: passwordInputs,
          usernameField: this.findUsernameField(),
          emailField: this.findEmailField(),
        };
      }
    }

    // Detect SIGNUP (2 fields + email/username + signup keywords)
    if (fieldCount === 2) {
      const hasSignupKeywords = this.SIGNUP_KEYWORDS.test(pageText);
      const noSigninKeywords = !this.SIGNIN_KEYWORDS.test(pageText);
      const hasIdentityField = hasEmailField || hasUsernameField;

      if (hasSignupKeywords && hasIdentityField) {
        return {
          type: 'signup',
          confidence: noSigninKeywords ? 90 : 70,
          passwordFields: passwordInputs,
          usernameField: this.findUsernameField(),
          emailField: this.findEmailField(),
        };
      }
    }

    // Detect SIGNIN (1-2 fields + signin keywords)
    if (fieldCount <= 2) {
      const hasSigninKeywords = this.SIGNIN_KEYWORDS.test(pageText);
      const noSignupKeywords = !this.SIGNUP_KEYWORDS.test(pageText);

      if (hasSigninKeywords || (fieldCount === 1 && noSignupKeywords)) {
        return {
          type: 'signin',
          confidence: hasSigninKeywords && noSignupKeywords ? 90 : 60,
          passwordFields: passwordInputs,
          usernameField: this.findUsernameField(),
          emailField: this.findEmailField(),
        };
      }
    }

    // Fallback: single password field = likely signin
    if (fieldCount === 1) {
      return {
        type: 'signin',
        confidence: 50,
        passwordFields: passwordInputs,
        usernameField: this.findUsernameField(),
        emailField: this.findEmailField(),
      };
    }

    return null;
  }

  /**
   * Find email input field
   */
  private static findEmailField(): HTMLInputElement | null {
    return document.querySelector<HTMLInputElement>('input[type="email"]:not([disabled])');
  }

  /**
   * Find username input field using multiple heuristics
   */
  private static findUsernameField(): HTMLInputElement | null {
    // Try explicit username fields first
    const usernameSelectors = [
      'input[name*="user" i]:not([type="password"]):not([disabled])',
      'input[id*="user" i]:not([type="password"]):not([disabled])',
      'input[autocomplete="username"]:not([disabled])',
      'input[type="text"][name*="login" i]:not([disabled])',
      'input[type="text"][id*="login" i]:not([disabled])',
    ];

    for (const selector of usernameSelectors) {
      const field = document.querySelector<HTMLInputElement>(selector);
      if (field) {
        return field;
      }
    }

    // Fallback: first text input before password field
    const passwordField = document.querySelector<HTMLInputElement>('input[type="password"]');
    if (passwordField) {
      const form = passwordField.closest('form');
      if (form) {
        const textInputs = Array.from(
          form.querySelectorAll<HTMLInputElement>('input[type="text"]:not([disabled]), input:not([type]):not([disabled])')
        );

        // Find the last text input before the password field
        for (let i = textInputs.length - 1; i >= 0; i--) {
          const textInput = textInputs[i];
          if (this.compareDocumentPosition(textInput, passwordField)) {
            return textInput;
          }
        }
      }
    }

    return null;
  }

  /**
   * Check if element1 comes before element2 in document order
   */
  private static compareDocumentPosition(element1: HTMLElement, element2: HTMLElement): boolean {
    const position = element1.compareDocumentPosition(element2);
    return (position & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
  }

  /**
   * Detect OTP/2FA input field
   */
  private static detectOtpField(): HTMLInputElement | null {
    // Find all visible input fields
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input:not([disabled])')).filter(input => {
      const style = window.getComputedStyle(input);
      return style.display !== 'none' &&
             style.visibility !== 'hidden' &&
             input.offsetParent !== null;
    });

    console.log('[PassAlways] Checking for OTP field, found', inputs.length, 'visible inputs');

    for (const input of inputs) {
      // Check autocomplete attribute (most reliable indicator)
      if (input.autocomplete === 'one-time-code') {
        return input;
      }

      // Check for numeric input with limited length
      const hasNumericInput = input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number';
      const hasRestrictedPattern = input.pattern && /\[0-9\]/.test(input.pattern);
      const hasMaxLength = input.maxLength >= 4 && input.maxLength <= 8;

      if ((hasNumericInput || hasRestrictedPattern) && hasMaxLength) {
        // Check surrounding text for OTP keywords
        const text = this.getInputContext(input);

        for (const pattern of this.OTP_PATTERNS) {
          if (pattern.test(text)) {
            return input;
          }
        }
      }

      // Check for inputs with OTP-related attributes
      const otpAttributes = [
        input.name,
        input.id,
        input.className,
        input.placeholder,
        input.getAttribute('aria-label') || '',
        input.getAttribute('data-testid') || '',
      ].join(' ').toLowerCase();

      if (/\b(otp|totp|2fa|code|token|verify|auth)\b/i.test(otpAttributes)) {
        // Additional check: must be numeric or have length constraint
        if (hasNumericInput || hasMaxLength || input.maxLength === -1) {
          return input;
        }
      }
    }

    // Check for split OTP inputs (e.g., 6 separate boxes for 6 digits)
    // Common pattern: multiple small numeric inputs grouped together
    const splitOtpField = this.detectSplitOtpInputs(inputs);
    if (splitOtpField) {
      console.log('[PassAlways] ✓ Detected split OTP input pattern');
      return splitOtpField;
    }

    console.log('[PassAlways] No OTP field detected');
    return null;
  }

  /**
   * Detect split OTP inputs (multiple small input fields for each digit)
   * Returns the first input if a split OTP pattern is detected
   */
  private static detectSplitOtpInputs(inputs: HTMLInputElement[]): HTMLInputElement | null {
    // Look for groups of small numeric inputs (typically 4-8 inputs)
    const smallNumericInputs = inputs.filter(input => {
      const maxLen = input.maxLength;
      const isNumeric = input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number' || input.type === 'text';

      // Each input should accept only 1-2 characters
      return isNumeric && maxLen >= 1 && maxLen <= 2;
    });

    console.log('[PassAlways] Found', smallNumericInputs.length, 'small numeric inputs');

    // Need at least 4 inputs for it to be a split OTP (4, 6, or 8 digits are common)
    if (smallNumericInputs.length < 4 || smallNumericInputs.length > 8) {
      console.log('[PassAlways] Not enough small inputs for split OTP pattern');
      return null;
    }

    // Check if they're grouped together (share a common parent container)
    const firstInput = smallNumericInputs[0];
    const container = firstInput.closest('form') || firstInput.parentElement;

    console.log('[PassAlways] Split OTP container:', container?.tagName);

    if (!container) {
      console.log('[PassAlways] No container found for split OTP inputs');
      return null;
    }

    // Verify all inputs are in the same container
    const allInSameContainer = smallNumericInputs.every(input =>
      input.closest('form') === container.querySelector('form') || input.parentElement === container
    );

    console.log('[PassAlways] All inputs in same container?', allInSameContainer);

    if (!allInSameContainer) {
      console.log('[PassAlways] Inputs not in same container, rejecting split OTP');
      return null;
    }

    // Check surrounding text for OTP keywords
    // Look up the DOM tree to find text context
    let textContainer: Element | null = container;
    let foundPattern = false;

    // Check up to 5 levels up the DOM tree for OTP-related text
    for (let i = 0; i < 5 && textContainer; i++) {
      const containerText = textContainer.textContent || '';

      if (i === 0) {
        console.log('[PassAlways] Container text (first 200 chars):', containerText.substring(0, 200));
      }

      for (const pattern of this.OTP_PATTERNS) {
        if (pattern.test(containerText)) {
          console.log('[PassAlways] ✓ Matched OTP pattern at level', i, ':', pattern);
          foundPattern = true;
          break;
        }
      }

      if (foundPattern) break;
      textContainer = textContainer.parentElement;
    }

    if (foundPattern) {
      return firstInput;
    }

    // If we have exactly 6 inputs (standard OTP length), accept it even without text match
    // This is a strong signal for OTP fields
    if (smallNumericInputs.length === 6) {
      console.log('[PassAlways] ✓ Found 6 grouped numeric inputs - accepting as OTP field');
      return firstInput;
    }

    console.log('[PassAlways] No OTP patterns matched in container hierarchy');
    return null;
  }

  /**
   * Get text context around an input field (labels, placeholders, nearby text)
   */
  private static getInputContext(input: HTMLInputElement): string {
    const parts: string[] = [];

    // Input attributes
    parts.push(input.name || '');
    parts.push(input.id || '');
    parts.push(input.placeholder || '');
    parts.push(input.getAttribute('aria-label') || '');

    // Associated labels
    if (input.labels) {
      for (const label of Array.from(input.labels)) {
        parts.push(label.textContent || '');
      }
    }

    // Nearby labels (within same form or parent container)
    const container = input.closest('form') || input.parentElement;
    if (container) {
      const labels = container.querySelectorAll('label');
      for (const label of Array.from(labels)) {
        // Only include labels close to this input
        if (label.contains(input) || input.contains(label) || label.htmlFor === input.id) {
          parts.push(label.textContent || '');
        }
      }
    }

    // Nearby text (previous/next siblings)
    const prev = input.previousElementSibling;
    if (prev && (prev.tagName === 'LABEL' || prev.tagName === 'SPAN' || prev.tagName === 'DIV')) {
      parts.push(prev.textContent?.substring(0, 100) || '');
    }

    return parts.join(' ');
  }

  /**
   * Monitor page for dynamic form additions
   */
  static startMonitoring(callback: (context: FormContext) => void): void {
    let lastDetection: FormContext | null = null;

    const checkForms = () => {
      const context = this.detect();

      // Only trigger callback if detection changed
      if (context && (!lastDetection || context.type !== lastDetection.type)) {
        lastDetection = context;
        callback(context);
      }
    };

    // Initial check
    checkForms();

    // Monitor for DOM changes
    const observer = new MutationObserver(() => {
      checkForms();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    // Also check on page load events
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', checkForms);
    }
  }

  /**
   * Detect 2FA page based on URL patterns and page content
   * This works even when no OTP input field is found (useful for sites like GitLab)
   */
  static is2FAPage(): boolean {
    const url = window.location.href.toLowerCase();
    const pathname = window.location.pathname.toLowerCase();

    // URL patterns that indicate 2FA page
    const URL_2FA_PATTERNS = [
      /\/2fa/i,
      /\/mfa/i,
      /\/totp/i,
      /\/otp/i,
      /\/verify/i,
      /\/challenge/i,
      /\/two[\-_]?factor/i,
      /\/second[\-_]?factor/i,
      /\/authenticator/i,
    ];

    for (const pattern of URL_2FA_PATTERNS) {
      if (pattern.test(url) || pattern.test(pathname)) {
        console.log('[PassAlways] 2FA URL pattern detected:', url);
        return true;
      }
    }

    // Page content patterns that indicate 2FA
    const PAGE_2FA_PATTERNS = [
      /enter.*(code|token)/i,
      /verification\s+code/i,
      /authenticator\s+(app|code)/i,
      /two[\s-]?factor/i,
      /2[\s-]?step/i,
      /security\s+code/i,
      /6[\s-]?digit/i,
    ];

    // Check headings and labels for 2FA indicators
    // Skip if PassAlways TOTP modal is active (password generation TOTP, not website 2FA)
    if (document.getElementById('passalways-totp-modal') || document.getElementById('passalways-totp-overlay')) {
      console.log('[PassAlways] Skipping 2FA detection - PassAlways TOTP modal is active');
      return false;
    }

    const headingsAndLabels = document.querySelectorAll('h1, h2, h3, h4, label, p, span');
    for (const el of headingsAndLabels) {
      // Skip elements inside PassAlways/PassMemo components (modals, notifications, dialogs)
      if (el.closest('#passalways-totp-modal') ||
          el.closest('#passalways-totp-overlay') ||
          el.closest('[id^="passalways-"]') ||
          el.closest('[class*="passmemo-"]') ||
          el.closest('[class*="passalways-"]')) {
        continue;
      }
      const text = el.textContent || '';
      if (text.length > 200) continue; // Skip long text blocks
      for (const pattern of PAGE_2FA_PATTERNS) {
        if (pattern.test(text)) {
          console.log('[PassAlways] 2FA page content detected:', text.substring(0, 50));
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Observe for 2FA fields that appear after password entry (post-login 2FA)
   *
   * Many sites show 2FA prompts after successful password entry.
   * This observer watches for these dynamic 2FA fields.
   *
   * @param callback Function to call when 2FA field is detected
   * @returns MutationObserver instance (can be disconnected if needed)
   */
  static observeFor2FA(callback: (context: FormContext) => void): MutationObserver {
    let checkCount = 0;
    const observer = new MutationObserver(() => {
      checkCount++;
      console.log('[PassAlways] 2FA observer triggered (check #' + checkCount + ')');
      const context = this.detect();

      // Only trigger for 2FA forms
      if (context && context.type === 'two-factor') {
        console.log('[PassAlways] ✓ 2FA form detected!');
        callback(context);

        // Optionally disconnect after first 2FA detection
        // observer.disconnect();
      }
    });

    console.log('[PassAlways] Starting 2FA observer on document.body');
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
    });

    // Also do immediate check
    console.log('[PassAlways] Running immediate 2FA check');
    const context = this.detect();
    if (context && context.type === 'two-factor') {
      console.log('[PassAlways] ✓ Found 2FA field immediately');
      callback(context);
    } else {
      console.log('[PassAlways] No 2FA field found yet, waiting for DOM changes...');
    }

    return observer;
  }
}
