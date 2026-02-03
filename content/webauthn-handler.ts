// PassAlways Authenticator - WebAuthn Bridge (ISOLATED World)
// Co-Authored-By: Project Engineer MelAnee Hannah
//
// This script runs in ISOLATED world and has chrome.runtime access
// For Chrome: webauthn-main.js is injected via manifest with world: "MAIN"
// For Firefox: we manually inject webauthn-main.js since Firefox MV3 doesn't support world: "MAIN"
// This script forwards messages between MAIN world and background script

// Firefox compatibility
const chromeAPI = typeof (globalThis as any).browser !== 'undefined' ? (globalThis as any).browser : (globalThis as any).chrome;
const chrome = chromeAPI;

// Detect if we're in Firefox (browser API exists natively)
const isFirefox = typeof (globalThis as any).browser !== 'undefined';

console.log('[PassAlways WebAuthn Bridge] Message bridge initializing, isFirefox:', isFirefox);

// For Firefox, we need to manually inject webauthn-main.js into the page context
// since Firefox MV3 doesn't support content_scripts with world: "MAIN"
if (isFirefox) {
  console.log('[PassAlways WebAuthn Bridge] Firefox detected, injecting webauthn-main.js into page context');

  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('content/webauthn-main.js');
  script.onload = () => {
    console.log('[PassAlways WebAuthn Bridge] webauthn-main.js injected successfully');
    script.remove(); // Clean up the script tag after execution
  };
  script.onerror = (error) => {
    console.error('[PassAlways WebAuthn Bridge] Failed to inject webauthn-main.js:', error);
  };

  // Inject as early as possible
  (document.head || document.documentElement).appendChild(script);
}

// Listen for messages from the MAIN world script
window.addEventListener('message', async (event) => {
  // Only accept messages from same origin
  if (event.source !== window) return;

  const message = event.data;

  // Only handle PassAlways WebAuthn messages
  if (!message || message.source !== 'passalways-webauthn') return;

  console.log('[PassAlways WebAuthn Bridge] Received message from page:', message.type);

  try {
    let response;

    switch (message.type) {
      case 'create_passkey':
        response = await chrome.runtime.sendMessage({
          action: 'create_passkey',
          data: message.data
        });
        break;

      case 'get_passkeys_for_rp':
        response = await chrome.runtime.sendMessage({
          action: 'get_passkeys_for_rp',
          data: message.data
        });
        break;

      case 'sign_passkey_challenge':
        response = await chrome.runtime.sendMessage({
          action: 'sign_passkey_challenge',
          data: message.data
        });
        break;

      case 'get_active_passkey_for_rp':
        response = await chrome.runtime.sendMessage({
          action: 'get_active_passkey_for_rp',
          data: message.data
        });
        break;

      case 'set_active_passkey_for_rp':
        response = await chrome.runtime.sendMessage({
          action: 'set_active_passkey_for_rp',
          data: message.data
        });
        break;

      default:
        console.error('[PassAlways WebAuthn Bridge] Unknown message type:', message.type);
        return;
    }

    // Send response back to MAIN world
    // Security: Use explicit origin instead of '*' to prevent cross-origin message leakage
    window.postMessage({
      source: 'passalways-webauthn-response',
      requestId: message.requestId,
      success: response?.success ?? false,
      data: response?.data,
      error: response?.error
    }, window.location.origin);

  } catch (error) {
    console.error('[PassAlways WebAuthn Bridge] Error handling message:', error);

    // Send error response back to MAIN world
    // Security: Use explicit origin instead of '*' to prevent cross-origin message leakage
    window.postMessage({
      source: 'passalways-webauthn-response',
      requestId: message.requestId,
      success: false,
      error: error instanceof Error ? error.message : String(error)
    }, window.location.origin);
  }
});

console.log('[PassAlways WebAuthn Bridge] Message bridge active');
