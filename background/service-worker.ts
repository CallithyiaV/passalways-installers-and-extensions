// PassAlways Browser Extension - Background Service Worker
// Co-Authored-By: Project Engineer MelAnee Hannah

import init, { PassmemoGenerator, verify_isbn } from '../shared/passmemo_wasm.js';
import type {
  MessageRequest,
  MessageResponse,
  PassmemoConfig,
  SitePasswordAttributes,
  PasswordCategories,
} from '../shared/types';

let wasmInitialized = false;
let generator: PassmemoGenerator | null = null;

// Local cache for active passkeys (rpId -> credential_id as number array)
// This avoids calling the native host for every authentication
const ACTIVE_PASSKEYS_STORAGE_KEY = 'passalways_active_passkeys';

async function getActivePasskeyFromStorage(rpId: string): Promise<number[] | null> {
  try {
    const result = await chrome.storage.local.get(ACTIVE_PASSKEYS_STORAGE_KEY);
    const activePasskeys = result[ACTIVE_PASSKEYS_STORAGE_KEY] || {};
    return activePasskeys[rpId] || null;
  } catch (error) {
    console.error('[Background] Error reading active passkey from storage:', error);
    return null;
  }
}

async function setActivePasskeyInStorage(rpId: string, credentialId: number[] | null): Promise<void> {
  try {
    const result = await chrome.storage.local.get(ACTIVE_PASSKEYS_STORAGE_KEY);
    const activePasskeys = result[ACTIVE_PASSKEYS_STORAGE_KEY] || {};
    if (credentialId) {
      activePasskeys[rpId] = credentialId;
    } else {
      delete activePasskeys[rpId];
    }
    await chrome.storage.local.set({ [ACTIVE_PASSKEYS_STORAGE_KEY]: activePasskeys });
    console.log('[Background] Active passkey stored for', rpId);
  } catch (error) {
    console.error('[Background] Error storing active passkey:', error);
  }
}

// Helper: Convert byte array to base64 string
function arrayToBase64(arr: number[]): string {
  const bytes = new Uint8Array(arr);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Initialize WASM module
async function initWasm(): Promise<void> {
  if (!wasmInitialized) {
    try {
      // In Manifest V3, we need to provide the WASM URL explicitly
      const wasmUrl = chrome.runtime.getURL('shared/passmemo_wasm_bg.wasm');
      const wasmResponse = await fetch(wasmUrl);
      const wasmBuffer = await wasmResponse.arrayBuffer();
      await init(wasmBuffer);
      wasmInitialized = true;
    } catch (error) {
      console.error('❌ Failed to initialize WASM:', error);
      throw error;
    }
  }
}

// Load configuration from storage
async function loadConfig(): Promise<PassmemoConfig | null> {
  try {
    const result = await chrome.storage.local.get('passmemo_config');
    if (result.passmemo_config) {
      return result.passmemo_config as PassmemoConfig;
    }
    return null;
  } catch (error) {
    console.error('Failed to load config:', error);
    return null;
  }
}

// Save configuration to storage
async function saveConfig(config: PassmemoConfig): Promise<void> {
  await chrome.storage.local.set({ passmemo_config: config });
}

// Get client IP address (best effort)
async function getClientIP(): Promise<string> {
  try {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    return data.ip || '127.0.0.1';
  } catch (error) {
    return '127.0.0.1'; // Fallback
  }
}

// Wait for push approval from user (poll for status)
// Returns { approved: boolean, totpCode?: string }
async function waitForPushApproval(requestId: string): Promise<{ approved: boolean; totpCode?: string }> {
  const maxWait = 60000; // 60 seconds
  const pollInterval = 1000; // 1 second
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    try {
      // Check approval status via IPC
      const response = await sendNativeMessage({
        type: 'get_push_approval_status',
        request_id: requestId,
      });

      if (response.status === 'approved') {
        // Fetch TOTP code for approved request
        try {
          const totpResponse = await sendNativeMessage({
            type: 'get_push_totp_code',
            request_id: requestId,
          });
          return { approved: true, totpCode: totpResponse.code };
        } catch (error) {
          console.error('[Background] Error fetching TOTP code:', error);
          return { approved: true }; // Approved but no TOTP code
        }
      } else if (response.status === 'denied' || response.status === 'expired') {
        return { approved: false };
      }

      // Still pending, wait and poll again
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    } catch (error) {
      console.error('[Background] Error checking push approval status:', error);
      return { approved: false };
    }
  }

  // Timeout
  return { approved: false };
}

// Phase 2: Session Management (using sessionStorage for ephemeral TOTP sessions)

async function saveSession(
  session_id: string,
  session_token: string,
  expires_in: number
): Promise<void> {
  const session_expires = Date.now() + expires_in * 1000;
  await chrome.storage.session.set({
    passalways_session_id: session_id,
    passalways_session_token: session_token,
    passalways_session_expires: session_expires,
  });
}

async function getSession(): Promise<{ session_id: string; session_token: string } | null> {
  try {
    const result = await chrome.storage.session.get([
      'passalways_session_id',
      'passalways_session_token',
      'passalways_session_expires',
    ]);

    const session_id = result.passalways_session_id;
    const session_token = result.passalways_session_token;
    const session_expires = result.passalways_session_expires;

    // Check expiry
    if (session_id && session_token && session_expires) {
      if (Date.now() < session_expires) {
        return { session_id, session_token };
      } else {
        // Session expired - clear it
        await chrome.storage.session.remove([
          'passalways_session_id',
          'passalways_session_token',
          'passalways_session_expires',
        ]);
      }
    }

    return null;
  } catch (error) {
    console.error('Failed to get session:', error);
    return null;
  }
}

async function clearSession(): Promise<void> {
  await chrome.storage.session.remove([
    'passalways_session_id',
    'passalways_session_token',
    'passalways_session_expires',
  ]);
}

// Send message to native host
async function sendNativeMessage(message: any): Promise<any> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage('com.passalways.host', message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response && !response.success) {
        reject(new Error(response.error || 'Native host error'));
      } else {
        resolve(response);
      }
    });
  });
}

// Initialize generator from config
async function initGenerator(): Promise<PassmemoGenerator> {
  if (generator) {
    return generator;
  }

  await initWasm();
  const config = await loadConfig();

  if (!config) {
    throw new Error('PassAlways not configured. Please complete setup first.');
  }

  generator = new PassmemoGenerator(
    config.isbn,
    config.page1,
    config.page2,
    config.passphrase1_template,
    config.passphrase2_template
  );

  return generator;
}

// Message handler
chrome.runtime.onMessage.addListener((request: MessageRequest, sender, sendResponse) => {
  // Handle async operations properly for Firefox compatibility
  const handleMessage = async () => {
    try {
      switch (request.action) {
        case 'get_config': {
          const config = await loadConfig();
          sendResponse({
            success: true,
            config: config || undefined,
          } as MessageResponse);
          break;
        }

        case 'save_config': {
          await saveConfig(request.config);
          // Reset generator to use new config
          generator = null;
          sendResponse({
            success: true,
          } as MessageResponse);
          break;
        }

        // Phase 2: TOTP Session Management
        case 'establish_session': {
          try {
            const response = await sendNativeMessage({
              action: 'establish_session',
              isbn: request.isbn,
              page1: request.page1,
              page2: request.page2,
            });

            sendResponse({
              success: true,
              session_id: response.data.session_id,
              totp_code: response.data.totp_code,
            } as MessageResponse);
          } catch (error) {
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'validate_session': {
          try {
            const response = await sendNativeMessage({
              action: 'validate_session',
              session_id: request.session_id,
              totp_code: request.totp_code,
            });

            // Save session to chrome.storage.session
            await saveSession(
              request.session_id,
              response.data.session_token,
              response.data.expires_in
            );

            sendResponse({
              success: true,
              session_token: response.data.session_token,
              expires_in: response.data.expires_in,
            } as MessageResponse);
          } catch (error) {
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'get_session': {
          try {
            const session = await getSession();

            if (!session) {
              sendResponse({
                success: false,
                error: 'No active session',
              } as MessageResponse);
              break;
            }

            // Validate with native host
            const response = await sendNativeMessage({
              action: 'get_session',
              session_id: session.session_id,
              session_token: session.session_token,
            });

            sendResponse({
              success: true,
              valid: response.data.valid,
              created_at: response.data.created_at,
              expires_at: response.data.expires_at,
            } as MessageResponse);
          } catch (error) {
            // Clear invalid session
            await clearSession();
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'remove_session': {
          try {
            const session = await getSession();

            if (session) {
              await sendNativeMessage({
                action: 'remove_session',
                session_id: session.session_id,
              });
            }

            await clearSession();

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        // Phase 6: New IPC Protocol Actions
        case 'generate_password_ipc': {
          try {
            const response = await sendNativeMessage({
              action: 'generate_password_ipc',
              site: request.site,
              username: request.username,
              length: request.length,
            });

            // Response contains status field with response type
            sendResponse({
              success: true,
              password: response.data?.password,
              username: response.data?.username,
              status: response.data?.status,
              message: response.data?.message,
              time_since_last: response.data?.time_since_last,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] generate_password_ipc error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'submit_totp': {
          try {
            const response = await sendNativeMessage({
              action: 'submit_totp',
              totp_code: request.totp_code,
              site: request.site,
              username: request.username,
            });

            sendResponse({
              success: true,
              password: response.data?.password,
              username: response.data?.username,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] submit_totp error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'ping_authenticator': {
          try {
            // Simple ping to check if native host is responsive
            const response = await sendNativeMessage({
              action: 'is_session_unlocked',
            });

            sendResponse({
              success: true,
              connected: true,
            } as MessageResponse);
          } catch (error) {
            sendResponse({
              success: false,
              connected: false,
            } as MessageResponse);
          }
          break;
        }

        case 'get_site_usernames_ipc': {
          try {
            const response = await sendNativeMessage({
              action: 'get_site_usernames_ipc',
              site: request.site,
            });

            // Also get default username from config
            const config = await loadConfig();

            sendResponse({
              success: true,
              usernames: response.data?.usernames || [],
              default_username: config?.default_username,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] get_site_usernames_ipc error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              usernames: [],
            } as MessageResponse);
          }
          break;
        }

        case 'get_site_metadata_ipc': {
          try {
            const response = await sendNativeMessage({
              action: 'get_site_metadata_ipc',
              site: request.site,
              username: request.username,
            });

            sendResponse({
              success: true,
              version: response.data?.version || 0,
              no_special_chars: response.data?.no_special_chars || false,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] get_site_metadata_ipc error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              version: 0,
              no_special_chars: false,
            } as MessageResponse);
          }
          break;
        }

        case 'unlock_session': {
          try {
            const response = await sendNativeMessage({
              action: 'unlock_session',
              pin: request.pin,
            });

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] unlock_session error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        // TOTP Authenticator Actions
        case 'has_totp_config': {
          try {
            const response = await sendNativeMessage({
              action: 'has_totp_config',
              site: request.site,
              username: request.username,
            });

            console.log('[Background] has_totp_config response:', response);

            sendResponse({
              success: true,
              has_config: response.data?.has_config || false,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] has_totp_config error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              has_config: false,
            } as MessageResponse);
          }
          break;
        }

        case 'get_totp_code': {
          try {
            const response = await sendNativeMessage({
              action: 'get_totp_code',
              site: request.site,
              username: request.username,
            });

            sendResponse({
              success: true,
              code: response.data?.code,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] get_totp_code error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'trigger_push_approval': {
          try {
            console.log('[Background] Triggering push approval for', request.site, request.username);

            // Send push request to PassAlways desktop via IPC
            const response = await sendNativeMessage({
              action: 'trigger_local_push_request',
              site: request.site,
              username: request.username,
              ip_address: await getClientIP(),
              user_agent: navigator.userAgent,
              location: null, // Could add geolocation later
            });

            console.log('[Background] Push request sent, request_id:', response.request_id);

            // Wait for user approval (poll for status and get TOTP code)
            const result = await waitForPushApproval(response.request_id);

            console.log('[Background] Push approval result:', result);

            sendResponse({
              success: true,
              approved: result.approved,
              code: result.totpCode, // Include TOTP code in response
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] trigger_push_approval error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'add_totp_config': {
          try {
            const response = await sendNativeMessage({
              action: 'add_totp_config',
              site: request.site,
              username: request.username,
              secret: request.secret,
              issuer: request.issuer,
              account: request.account,
              algorithm: request.algorithm,
              digits: request.digits,
              period: request.period,
            });

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] add_totp_config error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'list_totp_accounts': {
          try {
            const response = await sendNativeMessage({
              action: 'list_totp_accounts',
            });

            sendResponse({
              success: true,
              accounts: response.data?.accounts || [],
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] list_totp_accounts error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              accounts: [],
            } as MessageResponse);
          }
          break;
        }

        case 'remove_totp_config': {
          try {
            const response = await sendNativeMessage({
              action: 'remove_totp_config',
              site: request.site,
              username: request.username,
            });

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] remove_totp_config error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'parse_otpauth_uri': {
          try {
            const response = await sendNativeMessage({
              action: 'parse_otpauth_uri',
              uri: request.uri,
            });

            sendResponse({
              success: true,
              config: response.data?.config,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] parse_otpauth_uri error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'validate_totp_setup': {
          try {
            const response = await sendNativeMessage({
              action: 'validate_totp_setup',
              site: request.site,
              username: request.username,
              test_code: request.test_code,
            });

            sendResponse({
              success: true,
              valid: response.data?.valid || false,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] validate_totp_setup error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              valid: false,
            } as MessageResponse);
          }
          break;
        }

        case 'get_default_username': {
          try {
            const config = await loadConfig();
            sendResponse({
              success: true,
              username: config?.default_username,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] get_default_username error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'show_authenticator': {
          try {
            console.log('[Background] Showing authenticator window for site:', request.site);

            const response = await sendNativeMessage({
              action: 'show_authenticator',
              site: request.site,
            });

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] show_authenticator error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        // ===== Passkey/WebAuthn Handlers =====

        case 'create_passkey': {
          try {
            console.log('[Background] Creating passkey for', request.data.rpId, request.data.userName);

            // Convert arrays to base64 strings for native host
            const userIdBase64 = arrayToBase64(request.data.userId);
            const challengeBase64 = arrayToBase64(request.data.challenge);

            const response = await sendNativeMessage({
              action: 'create_passkey',
              site: request.data.site,
              rp_id: request.data.rpId,
              user_id: userIdBase64,
              user_name: request.data.userName,
              user_display_name: request.data.userDisplayName,
              challenge: challengeBase64,
              version: request.data.version || 0,
            });

            if (response.success) {
              sendResponse({
                success: true,
                data: response.data,
              } as MessageResponse);
            } else {
              sendResponse({
                success: false,
                error: response.error || 'Failed to create passkey',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] create_passkey error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'sign_passkey_challenge': {
          try {
            console.log('[Background] === SIGN_PASSKEY_CHALLENGE START ===');
            console.log('[Background] request.data:', request.data);
            console.log('[Background] credentialId:', request.data.credentialId);
            console.log('[Background] challenge:', request.data.challenge);
            console.log('[Background] rpId:', request.data.rpId);

            // Convert arrays to base64 strings for native host
            const clientDataHashBase64 = arrayToBase64(request.data.clientDataHash);
            const credentialIdBase64 = arrayToBase64(request.data.credentialId);

            console.log('[Background] clientDataHashBase64:', clientDataHashBase64);
            console.log('[Background] credentialIdBase64:', credentialIdBase64);

            // Extract site from rpId (e.g., "webauthn.io" -> "webauthn")
            const site = request.data.rpId.split('.')[0];

            const messageToSend = {
              action: 'sign_passkey_challenge',
              site: site,
              rp_id: request.data.rpId,
              client_data_hash: clientDataHashBase64,
              credential_id: credentialIdBase64,
            };

            console.log('[Background] Sending to native host:', JSON.stringify(messageToSend));

            const response = await sendNativeMessage(messageToSend);

            if (response.success) {
              sendResponse({
                success: true,
                data: response.data,
              } as MessageResponse);
            } else {
              sendResponse({
                success: false,
                error: response.error || 'Failed to sign challenge',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] sign_passkey_challenge error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'get_passkeys_for_rp': {
          try {
            console.log('[Background] Getting passkeys for RP:', request.data.rpId);

            const response = await sendNativeMessage({
              action: 'get_passkeys_for_rp',
              rp_id: request.data.rpId,
            });

            console.log('[Background] get_passkeys_for_rp response:', response);
            console.log('[Background] response.data:', response.data);
            console.log('[Background] response.data?.passkeys:', response.data?.passkeys);
            console.log('[Background] response.data?.active_credential_id:', response.data?.active_credential_id);

            if (response.success) {
              const passkeys = response.data?.passkeys || [];
              const activeCredentialId = response.data?.active_credential_id || null;

              // Cache the active passkey in local storage if provided
              if (activeCredentialId && request.data.rpId) {
                await setActivePasskeyInStorage(request.data.rpId, activeCredentialId);
                console.log('[Background] Cached active passkey from get_passkeys_for_rp');
              }

              console.log('[Background] Returning passkeys array, length:', passkeys.length, 'activeCredentialId:', activeCredentialId ? 'set' : 'none');
              sendResponse({
                success: true,
                data: passkeys,
                activeCredentialId: activeCredentialId,
              } as MessageResponse);
            } else {
              sendResponse({
                success: false,
                error: response.error || 'Failed to get passkeys',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] get_passkeys_for_rp error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'get_active_passkey_for_rp': {
          try {
            console.log('[Background] Getting active passkey for RP:', request.data.rpId);

            // First check local storage (fast, reliable)
            const localCredentialId = await getActivePasskeyFromStorage(request.data.rpId);
            if (localCredentialId) {
              console.log('[Background] Found active passkey in local storage');
              sendResponse({
                success: true,
                data: {
                  credential_id: localCredentialId,
                },
              } as MessageResponse);
              break;
            }

            // Fall back to native host (might fail if native host exits)
            try {
              const response = await sendNativeMessage({
                action: 'get_active_passkey_for_rp',
                rp_id: request.data.rpId,
              });

              if (response.success && response.data?.credential_id) {
                // Cache in local storage for future use
                await setActivePasskeyInStorage(request.data.rpId, response.data.credential_id);
                sendResponse({
                  success: true,
                  data: {
                    credential_id: response.data.credential_id,
                  },
                } as MessageResponse);
              } else {
                sendResponse({
                  success: false,
                  error: response.error || 'No active passkey set',
                } as MessageResponse);
              }
            } catch (nativeError) {
              console.warn('[Background] Native host call failed, no active passkey:', nativeError);
              sendResponse({
                success: false,
                error: 'No active passkey set',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] get_active_passkey_for_rp error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'set_active_passkey_for_rp': {
          try {
            console.log('[Background] Setting active passkey for RP:', request.data.rpId);

            // Store in local storage first (fast, reliable)
            await setActivePasskeyInStorage(request.data.rpId, request.data.credentialId);

            // Also sync to native host (best effort)
            try {
              const response = await sendNativeMessage({
                action: 'set_active_passkey_for_rp',
                rp_id: request.data.rpId,
                credential_id: arrayToBase64(request.data.credentialId),
              });

              if (!response.success) {
                console.warn('[Background] Native host set_active_passkey failed:', response.error);
              }
            } catch (nativeError) {
              console.warn('[Background] Native host sync failed:', nativeError);
              // Don't fail - we already stored locally
            }

            sendResponse({
              success: true,
            } as MessageResponse);
          } catch (error) {
            console.error('[Background] set_active_passkey_for_rp error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'list_passkeys': {
          try {
            console.log('[Background] Listing all passkeys');

            const response = await sendNativeMessage({
              action: 'list_passkeys',
            });

            if (response.success) {
              sendResponse({
                success: true,
                data: response.data?.passkeys || [],
              } as MessageResponse);
            } else {
              sendResponse({
                success: false,
                error: response.error || 'Failed to list passkeys',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] list_passkeys error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        case 'remove_passkey': {
          try {
            console.log('[Background] Removing passkey:', request.data.credentialId);

            const response = await sendNativeMessage({
              action: 'remove_passkey',
              credential_id: request.data.credentialId,
            });

            if (response.success) {
              sendResponse({
                success: true,
              } as MessageResponse);
            } else {
              sendResponse({
                success: false,
                error: response.error || 'Failed to remove passkey',
              } as MessageResponse);
            }
          } catch (error) {
            console.error('[Background] remove_passkey error:', error);
            sendResponse({
              success: false,
              error: error instanceof Error ? error.message : String(error),
            } as MessageResponse);
          }
          break;
        }

        default:
          sendResponse({
            success: false,
            error: 'Unknown action',
          } as MessageResponse);
      }
    } catch (error) {
      console.error('Background script error:', error);
      sendResponse({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      } as MessageResponse);
    }
  };

  // Execute async handler and catch any errors
  handleMessage().catch((error) => {
    console.error('Unhandled error in message handler:', error);
    sendResponse({
      success: false,
      error: error instanceof Error ? error.message : String(error),
    } as MessageResponse);
  });

  return true; // Keep message channel open for async response
});

