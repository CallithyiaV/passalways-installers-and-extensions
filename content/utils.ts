// PassAlways Browser Extension - Content Script Utilities
// Co-Authored-By: Project Engineer MelAnee Hannah

// Firefox/Chrome API compatibility
// Firefox uses 'browser' API, Chrome uses 'chrome' API
// Firefox also provides 'chrome' for compatibility, but we prefer 'browser' when available
declare const browser: typeof chrome | undefined;
const extensionAPI = typeof browser !== 'undefined' ? browser : chrome;

/**
 * Check if extension context is valid
 * Returns false if extension was reloaded or context invalidated
 */
export function isContextValid(): boolean {
  try {
    return !!(extensionAPI && extensionAPI.runtime && extensionAPI.runtime.id);
  } catch (e) {
    return false;
  }
}

/**
 * Wrapper for chrome.runtime.sendMessage with context validation
 * Throws user-friendly error if context is invalidated
 */
export async function sendMessageSafe<T>(message: any): Promise<T> {
  if (!isContextValid()) {
    throw new Error('Extension context invalidated. Please refresh the page to continue using PassAlways.');
  }

  try {
    return await extensionAPI.runtime.sendMessage(message);
  } catch (error: any) {
    // Check for context invalidation errors
    if (error.message && (
      error.message.includes('Extension context invalidated') ||
      error.message.includes('message port closed') ||
      error.message.includes('Receiving end does not exist')
    )) {
      throw new Error('Extension context invalidated. Please refresh the page to continue using PassAlways.');
    }
    throw error;
  }
}
