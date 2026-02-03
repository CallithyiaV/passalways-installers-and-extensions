# PassAlways WASM Module - Code Analysis

> **Co-Authored-By: Project Engineer MelAnee Hannah**
>
> Comprehensive analysis of the WebAssembly (WASM) module - a Rust-compiled password
> generator using quantum-resistant cryptography (BLAKE3 + Argon2id) for deterministic
> password generation in the browser.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Analysis](#module-analysis)
   - [lib.rs - WASM Bridge](#librs---wasm-bridge)
   - [crypto.rs - Cryptographic Core](#cryptors---cryptographic-core)
3. [Cryptographic Algorithm](#cryptographic-algorithm)
4. [Password Generation Flow](#password-generation-flow)
5. [Character Sets](#character-sets)
6. [Security Properties](#security-properties)
7. [Test Coverage](#test-coverage)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PassAlways WASM Module                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        lib.rs (WASM Bridge)                          │   │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────┐  │   │
│  │  │ PassmemoGenerator  │  │ PasswordCategories │  │ verify_isbn() │  │   │
│  │  │ (wasm_bindgen)     │  │ (serde)            │  │ (utility)     │  │   │
│  │  └─────────┬──────────┘  └────────────────────┘  └───────────────┘  │   │
│  │            │                                                         │   │
│  └────────────┼─────────────────────────────────────────────────────────┘   │
│               │                                                             │
│  ┌────────────┼─────────────────────────────────────────────────────────┐   │
│  │            ▼         crypto.rs (Cryptographic Core)                  │   │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────┐  │   │
│  │  │ MasterSeed         │  │ PassphraseTemplate │  │ SecureBytes   │  │   │
│  │  │ (ISBN + Pages)     │  │ ({USERNAME}/{SITE})│  │ (Zeroize)     │  │   │
│  │  └────────────────────┘  └────────────────────┘  └───────────────┘  │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────┐ │   │
│  │  │            QuantumPasswordGenerator                            │ │   │
│  │  │  ┌──────────┐     ┌──────────┐     ┌──────────┐               │ │   │
│  │  │  │ BLAKE3   │────►│ Argon2id │────►│ Encode   │               │ │   │
│  │  │  │ (256-bit)│     │ (KDF)    │     │ (Z85)    │               │ │   │
│  │  │  └──────────┘     └──────────┘     └──────────┘               │ │   │
│  │  └────────────────────────────────────────────────────────────────┘ │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────┐ │   │
│  │  │            Encryption Functions (AES-256-GCM)                  │ │   │
│  │  │  • generate_encryption_key()                                   │ │   │
│  │  │  • encrypt_passphrase()                                        │ │   │
│  │  │  • decrypt_passphrase()                                        │ │   │
│  │  └────────────────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Analysis

### lib.rs - WASM Bridge

**Purpose:** WebAssembly binding layer exposing Rust crypto functions to JavaScript.

**Line Count:** 187 lines

#### External Bindings (Lines 12-16)

```rust
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);  // Access to console.log from Rust
}
```

#### PasswordCategories (Lines 18-25)

```rust
pub struct PasswordCategories {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub allowed_symbols: Option<String>,
}
```

#### PassmemoGenerator Class (Lines 27-154)

| Method | Line | Parameters | Description |
|--------|------|------------|-------------|
| `new()` | 38-69 | isbn, page1, page2, passphrase1, passphrase2 | Constructor - validates templates, creates seed |
| `generate_password()` | 73-110 | site, username, length, categories_js, enforce_categories, version | Standard password generation |
| `generate_password_advanced()` | 114-153 | + enforce_first_16 | Advanced with first-16 char enforcement |

**Constructor Validation:**
- Passphrase 1 must contain `{USERNAME}` placeholder
- Passphrase 2 must contain `{SITE}` placeholder

#### Utility Functions (Lines 156-186)

| Function | Line | Description |
|----------|------|-------------|
| `verify_isbn()` | 158-178 | Validate ISBN-13 checksum |
| `main()` | 180-186 | WASM module initialization |

**ISBN-13 Checksum Algorithm:**
```rust
// Sum: digits[0]*1 + digits[1]*3 + digits[2]*1 + ...
let sum: u32 = digits.iter()
    .enumerate()
    .map(|(i, &d)| if i % 2 == 0 { d } else { d * 3 })
    .sum();
// Valid if sum % 10 == 0
```

---

### crypto.rs - Cryptographic Core

**Purpose:** Quantum-resistant password generation using BLAKE3 and Argon2id.

**Line Count:** 757 lines

#### PasswordCategories (Lines 13-59)

| Method | Line | Description |
|--------|------|-------------|
| `build_charset()` | 24-45 | Build character set from enabled flags |
| `validate_password()` | 48-58 | Check if password meets requirements |

**Character Set Construction:**
```rust
// Ambiguous characters removed (0, O, I, l, 1)
lowercase: "abcdefghijkmnpqrstuvwxyz"  // 24 chars (no 'l' or 'o')
uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ"  // 24 chars (no 'I' or 'O')
numbers:   "23456789"                   // 8 chars (no '0' or '1')
symbols:   "!@#$%^&*()"                 // 10 chars (default)
```

#### CryptoError (Lines 61-75)

```rust
pub enum CryptoError {
    HashError(String),
    KeyDerivationError(String),
    InvalidInput(String),
    TemplateError(String),
    EncryptionError(String),
    DecryptionError(String),
}
```

#### SecureBytes (Lines 77-89)

Zeroize-on-drop wrapper for sensitive data:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);
```

#### MasterSeed (Lines 91-139)

| Method | Line | Description |
|--------|------|-------------|
| `new()` | 102-123 | Create seed from ISBN + pages |
| `new_encryption()` | 128-130 | Alias for encryption key derivation |
| `as_str()` | 132-134 | Get seed string |
| `from_string()` | 136-138 | Create from existing string |

**Seed Format:**
```
ISBN-13: 9780770118686 → 0770118686 (remove 978 prefix)
Page 1:  112 → 112 (3 digits, zero-padded)
Page 2:  57  → 057 (3 digits, zero-padded)
Result:  "0770118686112057" (16 characters)
```

#### PassphraseTemplate (Lines 141-162)

| Method | Line | Description |
|--------|------|-------------|
| `new()` | 148-150 | Create template from string |
| `fill()` | 155-157 | Replace placeholder with value |
| `as_str()` | 159-161 | Get template string |

#### Hash Functions (Lines 164-188)

| Function | Line | Description |
|----------|------|-------------|
| `blake3_hash()` | 165-169 | Compute BLAKE3 256-bit hash |
| `argon2id_hash()` | 172-188 | Argon2id key derivation |

#### QuantumPasswordGenerator (Lines 190-572)

##### Constructor (Lines 195-198)

```rust
pub fn new(master_seed: MasterSeed) -> Self
```

##### Generation Methods

| Method | Line | Description |
|--------|------|-------------|
| `generate_password()` | 201-238 | Basic password generation |
| `generate_password_with_attributes()` | 246-268 | Generation with version/categories |
| `generate_password_with_attributes_internal()` | 271-312 | Internal with first-16 enforcement |
| `generate_password_internal()` | 315-360 | Core generation with augmented seed |

##### Encoding Methods

| Method | Line | Description |
|--------|------|-------------|
| `encode_to_password()` | 363-434 | Modified Z85 encoding (legacy) |
| `encode_with_categories()` | 443-507 | Category-based encoding |
| `ensure_categories_in_prefix()` | 511-571 | Enforce categories in first 16 chars |

#### Encryption Functions (Lines 574-670)

| Function | Line | Description |
|----------|------|-------------|
| `generate_encryption_key()` | 576-618 | Derive AES-256 key from credentials |
| `encrypt_passphrase()` | 622-645 | AES-256-GCM encryption |
| `decrypt_passphrase()` | 649-670 | AES-256-GCM decryption |

---

## Cryptographic Algorithm

### Password Generation Pipeline

```
                                ┌─────────────────────────────────────────┐
                                │           INPUT PARAMETERS              │
                                │  • ISBN + Page1 + Page2 → MasterSeed   │
                                │  • Passphrase1 template + username      │
                                │  • Passphrase2 template + site          │
                                │  • Version + Attempt counters          │
                                └─────────────────────┬───────────────────┘
                                                      │
                    ┌─────────────────────────────────┼──────────────────────────────────┐
                    │                                 │                                  │
                    ▼                                 ▼                                  │
┌───────────────────────────────┐   ┌───────────────────────────────┐                   │
│         FIRST HALF            │   │         SECOND HALF           │                   │
│                               │   │                               │                   │
│ filled_phrase1 =              │   │ filled_phrase2 =              │                   │
│   template1.fill("{USERNAME}",│   │   template2.fill("{SITE}",    │                   │
│     username.lowercase())     │   │     site.lowercase())         │                   │
│                               │   │                               │                   │
│ augmented_seed =              │   │ augmented_seed =              │                   │
│   master_seed + "v{version}   │   │   master_seed + "v{version}   │                   │
│   a{attempt}"                 │   │   a{attempt}"                 │                   │
│                               │   │                               │                   │
│ combined1 =                   │   │ combined2 =                   │                   │
│   filled_phrase1 +            │   │   filled_phrase2 +            │                   │
│   augmented_seed              │   │   augmented_seed              │                   │
│                               │   │                               │                   │
│         ↓                     │   │         ↓                     │                   │
│    BLAKE3(combined1)          │   │    BLAKE3(combined2)          │                   │
│    (256-bit hash)             │   │    (256-bit hash)             │                   │
│         ↓                     │   │         ↓                     │                   │
│    Argon2id(hash,             │   │    Argon2id(hash,             │                   │
│      "passmemo_first_salt")   │   │      "passmemo_second_salt")  │                   │
│         ↓                     │   │         ↓                     │                   │
│    first_half (32 bytes)      │   │    second_half (32 bytes)     │                   │
└───────────────────┬───────────┘   └───────────────────┬───────────┘                   │
                    │                                   │                                │
                    └─────────────────┬─────────────────┘                                │
                                      │                                                  │
                                      ▼                                                  │
                    ┌─────────────────────────────────────┐                              │
                    │         512-BIT MASTER KEY          │                              │
                    │    first_half || second_half        │                              │
                    └─────────────────┬───────────────────┘                              │
                                      │                                                  │
                                      ▼                                                  │
                    ┌─────────────────────────────────────┐                              │
                    │         BLAKE3 EXPANSION            │                              │
                    │    Expand entropy as needed         │                              │
                    │    (re-hash every 32 bytes)         │                              │
                    └─────────────────┬───────────────────┘                              │
                                      │                                                  │
                                      ▼                                                  │
                    ┌─────────────────────────────────────┐                              │
                    │       CHARACTER ENCODING            │                              │
                    │  • Map bytes to charset             │                              │
                    │  • Prevent >2 consecutive repeats   │                              │
                    │  • Enforce category requirements    │                              │
                    └─────────────────┬───────────────────┘                              │
                                      │                                                  │
                                      ▼                                                  │
                    ┌─────────────────────────────────────┐                              │
                    │            PASSWORD                 │◄─────────────────────────────┘
                    │   (deterministic, site-specific)    │   Retry if categories
                    └─────────────────────────────────────┘   not met (max 100)
```

### Version/Attempt Counters

```
augmented_seed = base_seed + "v" + version + "a" + attempt

Example:
  base_seed: "0770118686112057"
  version: 2
  attempt: 5
  augmented_seed: "0770118686112057v2a5"
```

- **Version**: User-controlled counter for password rotation
- **Attempt**: Internal counter for category enforcement retries (max 100)

---

## Password Generation Flow

### Standard Generation

```typescript
// JavaScript call
const password = generator.generate_password(
    "facebook.com",      // site
    "user@email.com",    // username
    16,                  // length
    {                    // categories
        lowercase: true,
        uppercase: true,
        numbers: true,
        symbols: true,
        allowed_symbols: null
    },
    true,               // enforce_categories
    0                   // version
);
```

### Category Enforcement

1. Generate password with version + attempt=0
2. Check if password meets category requirements
3. If not, increment attempt and regenerate
4. Repeat up to 100 times
5. If still not met, return error

### First-16 Enforcement (Advanced)

For sites that truncate passwords:

```
Position:  0123456789012345678901234567890123456789
Password:  abc123DEF!@#xyz...
           ^^^^^^^^^^^^^^^^
           Critical window (first 16 chars)

If enforce_first_16 = true:
  Inject missing categories at positions 12-15
```

---

## Character Sets

### Default Sets (Ambiguous Characters Removed)

| Category | Characters | Count |
|----------|------------|-------|
| Lowercase | `abcdefghijkmnpqrstuvwxyz` | 24 |
| Uppercase | `ABCDEFGHJKLMNPQRSTUVWXYZ` | 24 |
| Numbers | `23456789` | 8 |
| Symbols | `!@#$%^&*()` | 10 |

**Removed Ambiguous Characters:**
- `0` (zero) vs `O` (letter O)
- `1` (one) vs `l` (lowercase L) vs `I` (uppercase i)

### Modified Z85 Character Set (Legacy)

```rust
const SYMBOLIZED: &str =
    "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ_.-!@#$%^&*23456789.-!@#$%^&*";
```

---

## Security Properties

### Cryptographic Primitives

| Primitive | Use Case | Security Level |
|-----------|----------|----------------|
| BLAKE3 | Fast hashing, entropy expansion | 256-bit |
| Argon2id | Memory-hard KDF | Resistant to GPU/ASIC attacks |
| AES-256-GCM | Passphrase encryption | 256-bit authenticated |

### Quantum Resistance

- BLAKE3 and Argon2id are hash-based, not vulnerable to Shor's algorithm
- No public-key cryptography used in password generation
- Key space: 2^512 (512-bit master key)

### Determinism Guarantees

| Input | Effect |
|-------|--------|
| Same ISBN+pages+username+site+version | Same password |
| Different ISBN | Different password |
| Different pages | Different password |
| Different username | Different password |
| Different site | Different password |
| Different version | Different password |
| Case differences in username/site | Same password (normalized) |

### Zeroization

All sensitive data uses `Zeroize` trait:
- `SecureBytes` - cleared on drop
- `MasterSeed` - cleared on drop
- Argon2id output - cleared after use

---

## Test Coverage

### crypto.rs Tests (Lines 672-756)

| Test | Description |
|------|-------------|
| `test_master_seed_creation` | ISBN-13 to seed conversion |
| `test_master_seed_isbn10` | ISBN-10 to seed conversion |
| `test_blake3_hash` | BLAKE3 produces 32-byte output |
| `test_template_filling` | Template placeholder replacement |
| `test_password_generation_with_templates` | Full generation test |

### Generation Test Assertions

```rust
// Length correctness
assert_eq!(password.len(), 32);

// Determinism
assert_eq!(password, password2);

// Case insensitivity
assert_eq!(password, password3);  // same for MelAnee vs melanee

// Site uniqueness
assert_ne!(password, password4);  // different for Facebook vs Twitter
```

---

## Integration with Browser Extension

### WASM Loading

```typescript
// service-worker.ts
async function initWasm(): Promise<void> {
    const wasmUrl = chrome.runtime.getURL('shared/passmemo_wasm_bg.wasm');
    const wasmResponse = await fetch(wasmUrl);
    const wasmBuffer = await wasmResponse.arrayBuffer();
    await init(wasmBuffer);  // wasm_bindgen init
}
```

### Generator Usage

```typescript
// Create generator once with config
generator = new PassmemoGenerator(
    config.isbn,
    config.page1,
    config.page2,
    config.passphrase1_template,
    config.passphrase2_template
);

// Generate passwords on demand
const password = generator.generate_password(
    site,
    username,
    length,
    categories,
    enforce_categories,
    version
);
```

---

*Generated by Claude Code Analysis*
*Co-Authored-By: Project Engineer MelAnee Hannah*
