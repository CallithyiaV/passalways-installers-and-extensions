# PassAlways Browser Extension

Browser extension for PassAlways password manager.

## Supported Browsers

- Google Chrome / Chromium
- Microsoft Edge
- Mozilla Firefox

## Requirements

**Important:** This extension requires the [PassAlways Authenticator](https://portal.passalways.com) desktop app to function.

## Installation

### Chrome / Edge
1. Download `passalways-chrome.zip` from [portal.passalways.com](https://portal.passalways.com)
2. Go to `chrome://extensions` (or `edge://extensions`)
3. Enable "Developer mode"
4. Click "Load unpacked" or drag & drop the zip file

### Firefox
1. Download `passalways-firefox.xpi` from [portal.passalways.com](https://portal.passalways.com)
2. Go to `about:addons`
3. Click gear icon → "Install Add-on From File..."
4. Select the .xpi file

## Features

- Deterministic password generation
- TOTP/2FA code autofill
- FIDO2/WebAuthn passkey support
- Secure communication with desktop app

## Building

```bash
# Install dependencies
npm install

# Build Chrome extension
npm run build:chrome

# Build Firefox extension
npm run build:firefox
```

## License

MIT License - See LICENSE file

---
Co-Authored-By: Project Engineer MelAnee Hannah
