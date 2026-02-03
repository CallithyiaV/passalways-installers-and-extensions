// PassAlways Authenticator - WebAuthn Main World Script
// Co-Authored-By: Project Engineer MelAnee Hannah
//
// This script runs in the MAIN world and overrides navigator.credentials API
// It communicates with the ISOLATED world via window.postMessage

(function() {
  'use strict';

  console.log('[PassAlways WebAuthn] Injecting navigator.credentials override...');

  // Store original WebAuthn API
  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  // Request counter for matching requests/responses
  let requestId = 0;

  /**
   * Send message to content script bridge and wait for response
   */
  function sendToExtension(type: string, data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = ++requestId;

      const handleResponse = (event: MessageEvent) => {
        if (event.source !== window) return;
        if (!event.data || event.data.source !== 'passalways-webauthn-response') return;
        if (event.data.requestId !== id) return;

        window.removeEventListener('message', handleResponse);
        clearTimeout(timeout);

        if (event.data.success) {
          resolve(event.data);
        } else {
          reject(new Error(event.data.error || 'Request failed'));
        }
      };

      // Timeout after 30 seconds
      const timeout = setTimeout(() => {
        window.removeEventListener('message', handleResponse);
        reject(new Error('Request timeout'));
      }, 30000);

      window.addEventListener('message', handleResponse);

      // Security: Use explicit origin instead of '*' to prevent cross-origin message leakage
      window.postMessage({
        source: 'passalways-webauthn',
        type,
        requestId: id,
        data
      }, window.location.origin);
    });
  }

  /**
   * Convert ArrayBuffer to Base64URL string
   */
  function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Convert Base64URL string to Uint8Array
   * Handles both base64 and base64URL encoding (URL-safe variant)
   */
  function base64ToUint8Array(base64url: string): Uint8Array {
    // Convert base64URL to base64 by replacing URL-safe chars and adding padding
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Construct PublicKeyCredential for registration response
   */
  function constructRegistrationCredential(data: any, challenge: Uint8Array): any {
    console.log('[PassAlways WebAuthn] Raw data from native host:', data);
    console.log('[PassAlways WebAuthn] credential_id type:', typeof data.credential_id);
    console.log('[PassAlways WebAuthn] attestation_object type:', typeof data.attestation_object);

    // Native host sends base64-encoded byte arrays, decode them
    const credentialId = base64ToUint8Array(data.credential_id);
    const attestationObject = base64ToUint8Array(data.attestation_object);
    const authenticatorData = data.authenticator_data ? base64ToUint8Array(data.authenticator_data) : null;

    console.log('[PassAlways WebAuthn] Decoded attestationObject length:', attestationObject.length);
    console.log('[PassAlways WebAuthn] Decoded attestationObject hex:', Array.from(attestationObject.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(''));

    const clientData = {
      type: 'webauthn.create',
      challenge: arrayBufferToBase64Url(challenge),
      origin: window.location.origin,
      crossOrigin: false
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

    const response = {
      clientDataJSON,
      attestationObject,
      getTransports: () => ['internal'],
      getAuthenticatorData: () => authenticatorData,
      getPublicKey: () => base64ToUint8Array(data.public_key),
      getPublicKeyAlgorithm: () => -7
    };

    const credential = {
      id: arrayBufferToBase64Url(credentialId),
      rawId: credentialId,
      type: 'public-key',
      response,
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({})
    };

    return credential;
  }

  /**
   * Construct PublicKeyCredential for authentication response
   */
  function constructAuthenticationCredential(data: any, credentialId: Uint8Array, challenge: Uint8Array, clientDataJSON: Uint8Array): any {
    const credId = new Uint8Array(credentialId);
    const authenticatorData = base64ToUint8Array(data.authenticator_data);
    const signature = base64ToUint8Array(data.signature);

    // Convert user_handle from base64 to Uint8Array (WebAuthn expects ArrayBuffer or null)
    const userHandle = data.user_handle && data.user_handle.length > 0
      ? base64ToUint8Array(data.user_handle)
      : null;

    const response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle
    };

    const credential = {
      id: arrayBufferToBase64Url(credId),
      rawId: credId,
      type: 'public-key',
      response,
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({})
    };

    return credential;
  }

  /**
   * Intercept navigator.credentials.create() for passkey registration
   */
  navigator.credentials.create = async function(options?: CredentialCreationOptions): Promise<Credential | null> {
    console.log('[PassAlways WebAuthn] Intercepted credentials.create():', options);

    // Only handle PublicKeyCredential requests
    if (!options?.publicKey) {
      console.log('[PassAlways WebAuthn] Not a publicKey request, using original API');
      return originalCreate(options);
    }

    try {
      const publicKey = options.publicKey;

      const rpId = publicKey.rp.id || window.location.hostname;
      const challenge = new Uint8Array(publicKey.challenge);
      const userId = new Uint8Array(publicKey.user.id);
      const userName = publicKey.user.name;
      const userDisplayName = publicKey.user.displayName || userName;

      const site = rpId.split('.')[0];

      console.log('[PassAlways WebAuthn] Registration request:', {
        rpId,
        site,
        userName,
        userDisplayName
      });

      // Send to extension
      const response = await sendToExtension('create_passkey', {
        site,
        rpId,
        userId: Array.from(userId),
        userName,
        userDisplayName,
        challenge: Array.from(challenge),
        version: 0
      });

      console.log('[PassAlways WebAuthn] Registration successful, constructing credential');

      return constructRegistrationCredential(response.data, challenge);

    } catch (error) {
      console.error('[PassAlways WebAuthn] Error during registration:', error);
      console.log('[PassAlways WebAuthn] Falling back to native WebAuthn');
      return originalCreate(options);
    }
  };

  /**
   * Intercept navigator.credentials.get() for passkey authentication
   */
  navigator.credentials.get = async function(options?: CredentialRequestOptions): Promise<Credential | null> {
    console.log('[PassAlways WebAuthn] Intercepted credentials.get():', options);

    // Only handle PublicKeyCredential requests
    if (!options?.publicKey) {
      console.log('[PassAlways WebAuthn] Not a publicKey request, using original API');
      return originalGet(options);
    }

    // Skip passkey if TOTP fields are visible - user likely wants to use TOTP
    // IMPORTANT: Don't call originalGet() - that would show browser's native passkey UI
    // Instead, return null to signal "no credential" and let site fall back to TOTP
    if (isTotpFieldVisible()) {
      console.log('[PassAlways WebAuthn] TOTP field visible, rejecting passkey to allow TOTP entry');
      // Return null signals no credential selected - site should fall back to TOTP
      return null;
    }

    try {
      const publicKey = options.publicKey;

      const rpId = (publicKey as any).rpId || window.location.hostname;
      const challenge = new Uint8Array(publicKey.challenge);

      console.log('[PassAlways WebAuthn] ========================================');
      console.log('[PassAlways WebAuthn] Authentication request for:', rpId);
      console.log('[PassAlways WebAuthn] allowCredentials:', publicKey.allowCredentials);
      if (publicKey.allowCredentials && publicKey.allowCredentials.length > 0) {
        console.log('[PassAlways WebAuthn] Website is requesting specific credentials:');
        publicKey.allowCredentials.forEach((cred: any, idx: number) => {
          const credId = new Uint8Array(cred.id);
          console.log(`[PassAlways WebAuthn]   [${idx}] credential_id:`, arrayBufferToBase64Url(credId));
        });
      } else {
        console.log('[PassAlways WebAuthn] No allowCredentials - website wants any credential (resident key flow)');
      }
      console.log('[PassAlways WebAuthn] ========================================');

      // Query available passkeys for this RP
      const availablePasskeys = await sendToExtension('get_passkeys_for_rp', { rpId });

      console.log('[PassAlways WebAuthn] get_passkeys_for_rp response:', availablePasskeys);
      console.log('[PassAlways WebAuthn] availablePasskeys.success:', availablePasskeys?.success);
      console.log('[PassAlways WebAuthn] availablePasskeys.data:', availablePasskeys?.data);
      console.log('[PassAlways WebAuthn] is array?', Array.isArray(availablePasskeys?.data));
      console.log('[PassAlways WebAuthn] length:', availablePasskeys?.data?.length);

      if (!availablePasskeys || !availablePasskeys.data || !Array.isArray(availablePasskeys.data) || availablePasskeys.data.length === 0) {
        console.log('[PassAlways WebAuthn] No passkeys found for RP, using native WebAuthn');
        console.log('[PassAlways WebAuthn] Response was:', JSON.stringify(availablePasskeys));
        return originalGet(options);
      }

      // Filter passkeys based on allowCredentials if provided
      let filteredPasskeys = availablePasskeys.data;
      if (publicKey.allowCredentials && Array.isArray(publicKey.allowCredentials) && publicKey.allowCredentials.length > 0) {
        console.log('[PassAlways WebAuthn] Filtering passkeys based on allowCredentials:', publicKey.allowCredentials.length, 'credentials allowed');

        // Convert allowCredentials to a Set of base64-encoded credential IDs for faster lookup
        const allowedCredIds = new Set(
          publicKey.allowCredentials.map((cred: any) => {
            const credId = new Uint8Array(cred.id);
            return arrayBufferToBase64Url(credId);
          })
        );

        // Debug: Log all allowed credential IDs from website
        console.log('[PassAlways WebAuthn] ===== CREDENTIAL ID COMPARISON =====');
        console.log('[PassAlways WebAuthn] Website requests these credential_ids (base64url):');
        Array.from(allowedCredIds).forEach((id, idx) => {
          console.log(`[PassAlways WebAuthn]   [${idx}] ${id}`);
        });

        console.log('[PassAlways WebAuthn] We have these passkeys stored:');
        availablePasskeys.data.forEach((passkey: any, idx: number) => {
          const passkeyCredId = arrayBufferToBase64Url(new Uint8Array(passkey.credential_id));
          console.log(`[PassAlways WebAuthn]   [${idx}] username: ${passkey.username}, credential_id: ${passkeyCredId}`);
          console.log(`[PassAlways WebAuthn]        raw bytes (first 20): [${passkey.credential_id.slice(0, 20).join(', ')}]`);
        });

        filteredPasskeys = availablePasskeys.data.filter((passkey: any) => {
          const passkeyCredId = arrayBufferToBase64Url(new Uint8Array(passkey.credential_id));
          const isAllowed = allowedCredIds.has(passkeyCredId);
          console.log('[PassAlways WebAuthn] Passkey', passkey.username, 'credential_id:', passkeyCredId, 'allowed:', isAllowed);
          return isAllowed;
        });
        console.log('[PassAlways WebAuthn] =====================================');

        console.log('[PassAlways WebAuthn] Filtered to', filteredPasskeys.length, 'passkeys');

        if (filteredPasskeys.length === 0) {
          console.log('[PassAlways WebAuthn] No matching passkeys found after filtering, using native WebAuthn');
          return originalGet(options);
        }
      }

      // Try to get the active (pre-selected) passkey for this RP
      // First check if it was included in the get_passkeys_for_rp response (most reliable)
      let selectedPasskey = null;
      let activeCredId = availablePasskeys.activeCredentialId;

      console.log('[PassAlways WebAuthn] Active credential_id from get_passkeys_for_rp:', activeCredId);

      if (activeCredId && Array.isArray(activeCredId) && activeCredId.length > 0) {
        const activeCredIdStr = arrayBufferToBase64Url(new Uint8Array(activeCredId));
        console.log('[PassAlways WebAuthn] Active credential_id (base64):', activeCredIdStr);

        // Find the passkey matching the active credential_id
        selectedPasskey = filteredPasskeys.find((passkey: any) => {
          const passkeyCredIdStr = arrayBufferToBase64Url(new Uint8Array(passkey.credential_id));
          console.log('[PassAlways WebAuthn] Comparing active:', activeCredIdStr, 'with passkey:', passkeyCredIdStr, 'username:', passkey.username);
          return passkeyCredIdStr === activeCredIdStr;
        });

        if (selectedPasskey) {
          console.log('[PassAlways WebAuthn] ✓ Using active passkey for username:', selectedPasskey.username);
          console.log('[PassAlways WebAuthn] ✓ Active credential_id:', selectedPasskey.credential_id);
        } else {
          console.log('[PassAlways WebAuthn] ✗ Active passkey not found in filtered list');
        }
      }

      // Fall back to separate call if active passkey not in response
      if (!selectedPasskey) {
        try {
          const activePasskeyResponse = await sendToExtension('get_active_passkey_for_rp', { rpId });
          console.log('[PassAlways WebAuthn] Active passkey response (fallback):', activePasskeyResponse);

          if (activePasskeyResponse?.success && activePasskeyResponse?.data?.credential_id) {
            activeCredId = activePasskeyResponse.data.credential_id;
            const activeCredIdStr = arrayBufferToBase64Url(new Uint8Array(activeCredId));
            console.log('[PassAlways WebAuthn] Active credential_id from fallback (base64):', activeCredIdStr);

            // Find the passkey matching the active credential_id
            selectedPasskey = filteredPasskeys.find((passkey: any) => {
              const passkeyCredIdStr = arrayBufferToBase64Url(new Uint8Array(passkey.credential_id));
              return passkeyCredIdStr === activeCredIdStr;
            });

            if (selectedPasskey) {
              console.log('[PassAlways WebAuthn] ✓ Using active passkey from fallback:', selectedPasskey.username);
            }
          }
        } catch (err) {
          console.warn('[PassAlways WebAuthn] Could not retrieve active passkey (fallback):', err);
        }
      }

      // Fall back to first available passkey if no active passkey set
      if (!selectedPasskey) {
        selectedPasskey = filteredPasskeys[0];
        console.log('[PassAlways WebAuthn] No active passkey found, using first available:', selectedPasskey?.username);
        console.log('[PassAlways WebAuthn] First available credential_id:', selectedPasskey?.credential_id);
      }

      if (!selectedPasskey || !selectedPasskey.credential_id) {
        console.error('[PassAlways WebAuthn] Invalid passkey data:', selectedPasskey);
        return originalGet(options);
      }
      console.log('[PassAlways WebAuthn] Using passkey for username:', selectedPasskey.username);
      console.log('[PassAlways WebAuthn] Passkey details:', selectedPasskey);

      // Construct clientDataJSON (needed for signature verification)
      const clientData = {
        type: 'webauthn.get',
        challenge: arrayBufferToBase64Url(challenge),
        origin: window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

      // Hash the clientDataJSON for signature
      const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);

      // Send authentication request with clientDataJSON hash
      const response = await sendToExtension('sign_passkey_challenge', {
        credentialId: selectedPasskey.credential_id,
        rpId,
        clientDataHash: Array.from(new Uint8Array(clientDataHash))
      });

      console.log('[PassAlways WebAuthn] Authentication successful, constructing assertion');

      return constructAuthenticationCredential(response.data, selectedPasskey.credential_id, challenge, clientDataJSON);

    } catch (error) {
      console.error('[PassAlways WebAuthn] Error during authentication:', error);
      console.log('[PassAlways WebAuthn] Falling back to native WebAuthn');
      return originalGet(options);
    }
  };

  /**
   * Detect if TOTP/OTP input fields are visible on the page
   * If so, user likely wants to use TOTP instead of passkey
   */
  function isTotpFieldVisible(): boolean {
    // Check URL for 2FA-related paths
    const url = window.location.href.toLowerCase();
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
      if (pattern.test(url)) {
        console.log('[PassAlways WebAuthn] 2FA URL detected:', url);
        return true;
      }
    }

    const OTP_PATTERNS = [
      /\b(otp|totp|2fa|two[\s-]?factor|mfa|multi[\s-]?factor)\b/i,
      /\b(verification|authenticator|security)[\s-]?(code|token)\b/i,
      /\bauth(entication)?[\s-]?code\b/i,
    ];

    // Find all visible input fields
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input:not([disabled])')).filter(input => {
      const style = window.getComputedStyle(input);
      return style.display !== 'none' &&
             style.visibility !== 'hidden' &&
             input.offsetParent !== null &&
             input.offsetWidth > 0 &&
             input.offsetHeight > 0;
    });

    for (const input of inputs) {
      // Check autocomplete attribute
      if (input.autocomplete === 'one-time-code') {
        console.log('[PassAlways WebAuthn] TOTP field detected (autocomplete=one-time-code)');
        return true;
      }

      // Check for numeric input with limited length (typical OTP field)
      const hasNumericInput = input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number';
      const hasMaxLength = input.maxLength >= 4 && input.maxLength <= 8;

      // Check input attributes for OTP keywords
      const attributes = [
        input.name,
        input.id,
        input.className,
        input.placeholder,
        input.getAttribute('aria-label') || '',
      ].join(' ').toLowerCase();

      if (/\b(otp|totp|2fa|code|token|verify|auth)\b/i.test(attributes)) {
        if (hasNumericInput || hasMaxLength) {
          console.log('[PassAlways WebAuthn] TOTP field detected (attributes match):', input.name || input.id);
          return true;
        }
      }

      // Check surrounding text for OTP keywords
      if ((hasNumericInput || hasMaxLength) && input.maxLength <= 8) {
        const container = input.closest('form') || input.parentElement;
        if (container) {
          const containerText = container.textContent || '';
          for (const pattern of OTP_PATTERNS) {
            if (pattern.test(containerText)) {
              console.log('[PassAlways WebAuthn] TOTP field detected (context text match)');
              return true;
            }
          }
        }
      }
    }

    // Check for split OTP inputs (multiple small input boxes)
    const smallNumericInputs = inputs.filter(input => {
      const isNumeric = input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number' || input.type === 'text';
      return isNumeric && input.maxLength >= 1 && input.maxLength <= 2;
    });

    if (smallNumericInputs.length >= 4 && smallNumericInputs.length <= 8) {
      console.log('[PassAlways WebAuthn] Split TOTP input detected (' + smallNumericInputs.length + ' fields)');
      return true;
    }

    // Check for visible headings or labels mentioning 2FA
    const PAGE_2FA_PATTERNS = [
      /enter.*(code|token)/i,
      /verification\s+code/i,
      /authenticator\s+(app|code)/i,
      /two[\s-]?factor/i,
      /2[\s-]?step/i,
      /security\s+code/i,
      /6[\s-]?digit/i,
    ];

    const headingsAndLabels = document.querySelectorAll('h1, h2, h3, h4, label, p, span');
    for (const el of headingsAndLabels) {
      const text = el.textContent || '';
      if (text.length > 200) continue; // Skip long text blocks
      for (const pattern of PAGE_2FA_PATTERNS) {
        if (pattern.test(text)) {
          console.log('[PassAlways WebAuthn] 2FA page content detected:', text.substring(0, 50));
          return true;
        }
      }
    }

    return false;
  }

  console.log('[PassAlways WebAuthn] navigator.credentials API intercepted successfully');

})();
