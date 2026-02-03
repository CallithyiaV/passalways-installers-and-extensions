// Quantum-resistant cryptography implementation for Passmemo
// Co-Authored-By: Project Engineer MelAnee Hannah

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Password character category requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCategories {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub allowed_symbols: Option<String>,
}

impl PasswordCategories {
    /// Build character set from enabled categories
    pub fn build_charset(&self) -> String {
        let mut charset = String::new();

        if self.lowercase {
            charset.push_str("abcdefghijkmnpqrstuvwxyz");
        }
        if self.uppercase {
            charset.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ");
        }
        if self.numbers {
            charset.push_str("23456789");
        }
        if self.symbols {
            if let Some(ref allowed) = self.allowed_symbols {
                charset.push_str(allowed);
            } else {
                charset.push_str("!@#$%^&*()");
            }
        }

        charset
    }

    /// Validate that password meets category requirements
    pub fn validate_password(&self, password: &str) -> bool {
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_number = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        (!self.lowercase || has_lowercase) &&
        (!self.uppercase || has_uppercase) &&
        (!self.numbers || has_number) &&
        (!self.symbols || has_symbol)
    }
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Hash generation failed: {0}")]
    HashError(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Template error: {0}")]
    TemplateError(String),
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
}

/// Secure container for sensitive data that zeroes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        SecureBytes(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Master seed derived from ISBN, family name, and page numbers
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed {
    #[serde(skip)]
    seed: String,
}

impl MasterSeed {
    /// Create master seed for password generation (ISBN + pages only)
    /// Format: ISBN(10) + Page1(3) + Page2(3)
    /// Example: 0770118686112057
    pub fn new(isbn: &str, page1: u16, page2: u16) -> Result<Self, CryptoError> {
        // Validate ISBN (should be 10 or 13 digits)
        let isbn_clean: String = isbn.chars().filter(|c| c.is_numeric()).collect();
        let isbn_final = if isbn_clean.len() == 13 {
            // Remove predictable 978 prefix
            isbn_clean[3..].to_string()
        } else if isbn_clean.len() == 10 {
            isbn_clean
        } else {
            return Err(CryptoError::InvalidInput(
                "ISBN must be 10 or 13 digits".to_string()
            ));
        };

        // Format seed: ISBN(10) + PAGE1(3) + PAGE2(3)
        let seed = format!(
            "{}{:03}{:03}",
            isbn_final, page1, page2
        );

        Ok(MasterSeed { seed })
    }

    /// Create master seed for encryption (same as new() - ISBN + pages only)
    /// Format: ISBN(10) + Page1(3) + Page2(3)
    /// Example: 0770118686112057
    pub fn new_encryption(isbn: &str, page1: u16, page2: u16) -> Result<Self, CryptoError> {
        Self::new(isbn, page1, page2)
    }

    pub fn as_str(&self) -> &str {
        &self.seed
    }

    pub fn from_string(seed: String) -> Self {
        MasterSeed { seed }
    }
}

/// Passphrase template with placeholder support
#[derive(Clone, Serialize, Deserialize)]
pub struct PassphraseTemplate {
    template: String,
}

impl PassphraseTemplate {
    pub fn new(template: String) -> Self {
        PassphraseTemplate { template }
    }

    /// Fill template with actual value
    /// {USERNAME} -> actual username
    /// {SITE} -> actual site name
    pub fn fill(&self, placeholder: &str, value: &str) -> String {
        self.template.replace(placeholder, value)
    }

    pub fn as_str(&self) -> &str {
        &self.template
    }
}

/// Compute BLAKE3 hash
pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Compute Argon2id hash for key derivation
pub fn argon2id_hash(data: &[u8], salt: &[u8]) -> Result<SecureBytes, CryptoError> {
    let argon2 = Argon2::default();

    // Create fixed salt from provided bytes
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    let hash = argon2
        .hash_password(data, &salt_string)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    // Extract the hash bytes (32 bytes)
    let hash_bytes = hash.hash
        .ok_or_else(|| CryptoError::KeyDerivationError("No hash generated".to_string()))?;

    Ok(SecureBytes::new(hash_bytes.as_bytes().to_vec()))
}

/// Password generator using quantum-resistant cryptography with template support
pub struct QuantumPasswordGenerator {
    master_seed: MasterSeed,
}

impl QuantumPasswordGenerator {
    pub fn new(master_seed: MasterSeed) -> Self {
        QuantumPasswordGenerator { master_seed }
    }

    /// Generate password from passphrase templates (backwards compatible)
    pub fn generate_password(
        &self,
        first_template: &PassphraseTemplate,
        second_template: &PassphraseTemplate,
        username: &str,
        site: &str,
        length: usize,
    ) -> Result<String, CryptoError> {
        // Normalize inputs for deterministic generation
        let username_normalized = username.to_lowercase();
        let site_normalized = site.to_lowercase();

        // Fill templates with normalized values
        let first_phrase = first_template.fill("{USERNAME}", &username_normalized);
        let second_phrase = second_template.fill("{SITE}", &site_normalized);

        // Generate first half: BLAKE3(firstPhrase + seed) -> Argon2id
        let first_combined = format!("{}{}", first_phrase, self.master_seed.as_str());
        let first_blake = blake3_hash(first_combined.as_bytes());
        let first_salt = blake3_hash(b"passmemo_first_salt");
        let first_half = argon2id_hash(&first_blake, &first_salt[..16])?;

        // Generate second half: BLAKE3(secondPhrase + seed) -> Argon2id
        let second_combined = format!("{}{}", second_phrase, self.master_seed.as_str());
        let second_blake = blake3_hash(second_combined.as_bytes());
        let second_salt = blake3_hash(b"passmemo_second_salt");
        let second_half = argon2id_hash(&second_blake, &second_salt[..16])?;

        // Combine halves to create 512-bit master key
        let mut master_key = Vec::new();
        master_key.extend_from_slice(first_half.as_bytes());
        master_key.extend_from_slice(second_half.as_bytes());

        // Generate password using modified Z85 encoding
        let password = self.encode_to_password(&master_key, length)?;

        Ok(password)
    }

    /// Generate password with per-site attributes
    /// Includes: custom character categories, version counter, and category enforcement
    ///
    /// # Parameters
    /// - enforce_first_16: If true, ensures categories appear in first 16 chars (for retry attempts)
    ///                     If false, validates across full password length (for first attempt)
    pub fn generate_password_with_attributes(
        &self,
        first_template: &PassphraseTemplate,
        second_template: &PassphraseTemplate,
        username: &str,
        site: &str,
        length: usize,
        categories: &PasswordCategories,
        enforce_categories: bool,
        version: u32,
    ) -> Result<String, CryptoError> {
        self.generate_password_with_attributes_internal(
            first_template,
            second_template,
            username,
            site,
            length,
            categories,
            enforce_categories,
            version,
            false, // Don't enforce first 16 chars for normal use
        )
    }

    /// Internal version with first-16 enforcement control
    pub fn generate_password_with_attributes_internal(
        &self,
        first_template: &PassphraseTemplate,
        second_template: &PassphraseTemplate,
        username: &str,
        site: &str,
        length: usize,
        categories: &PasswordCategories,
        enforce_categories: bool,
        version: u32,
        enforce_first_16: bool,
    ) -> Result<String, CryptoError> {
        const MAX_ATTEMPTS: u32 = 100;

        // Try up to MAX_ATTEMPTS to find a password meeting requirements
        for attempt in 0..MAX_ATTEMPTS {
            // Generate password with version and attempt counter
            let password = self.generate_password_internal(
                first_template,
                second_template,
                username,
                site,
                length,
                categories,
                version,
                attempt,
                enforce_first_16,
            )?;

            // Check if category enforcement is required
            if !enforce_categories || categories.validate_password(&password) {
                return Ok(password);  // Success!
            }

            // Category requirements not met, try next attempt
        }

        // Max attempts exceeded
        Err(CryptoError::KeyDerivationError(
            "Could not generate password meeting category requirements after 100 attempts".to_string()
        ))
    }

    /// Internal password generation with version and attempt counter
    fn generate_password_internal(
        &self,
        first_template: &PassphraseTemplate,
        second_template: &PassphraseTemplate,
        username: &str,
        site: &str,
        length: usize,
        categories: &PasswordCategories,
        version: u32,
        attempt: u32,
        enforce_first_16: bool,
    ) -> Result<String, CryptoError> {
        // Normalize inputs for deterministic generation
        let username_normalized = username.to_lowercase();
        let site_normalized = site.to_lowercase();

        // Fill templates with normalized values
        let first_phrase = first_template.fill("{USERNAME}", &username_normalized);
        let second_phrase = second_template.fill("{SITE}", &site_normalized);

        // Create augmented seed with version and attempt
        // Format: base_seed + version + attempt
        let augmented_seed = format!("{}v{}a{}", self.master_seed.as_str(), version, attempt);

        // Generate first half: BLAKE3(firstPhrase + augmented_seed) -> Argon2id
        let first_combined = format!("{}{}", first_phrase, augmented_seed);
        let first_blake = blake3_hash(first_combined.as_bytes());
        let first_salt = blake3_hash(b"passmemo_first_salt");
        let first_half = argon2id_hash(&first_blake, &first_salt[..16])?;

        // Generate second half: BLAKE3(secondPhrase + augmented_seed) -> Argon2id
        let second_combined = format!("{}{}", second_phrase, augmented_seed);
        let second_blake = blake3_hash(second_combined.as_bytes());
        let second_salt = blake3_hash(b"passmemo_second_salt");
        let second_half = argon2id_hash(&second_blake, &second_salt[..16])?;

        // Combine halves to create 512-bit master key
        let mut master_key = Vec::new();
        master_key.extend_from_slice(first_half.as_bytes());
        master_key.extend_from_slice(second_half.as_bytes());

        // Generate password using category-based encoding
        let password = self.encode_with_categories(&master_key, length, categories, enforce_first_16)?;

        Ok(password)
    }

    /// Encode bytes to password using modified Z85 encoding
    fn encode_to_password(&self, data: &[u8], length: usize) -> Result<String, CryptoError> {
        // Modified Z85 character sets from specification
        const SYMBOLIZED: &str =
            "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ_.-!@#$%^&*23456789.-!@#$%^&*";

        let charset = SYMBOLIZED.as_bytes();
        let mut password = String::new();

        // Use BLAKE3 to expand data for deterministic password generation
        let mut hasher = Hasher::new();
        hasher.update(data);
        let mut hash = hasher.finalize().as_bytes().to_vec();

        // Generate password ensuring character category requirements
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_symbol = false;
        let mut last_char = '\0';
        let mut last_count = 0;

        for i in 0..length {
            // Re-hash if we need more entropy
            if i > 0 && i % 32 == 0 {
                hasher = Hasher::new();
                hasher.update(&hash);
                hash = hasher.finalize().as_bytes().to_vec();
            }

            let byte_index = i % hash.len();
            let char_index = (hash[byte_index] as usize) % charset.len();
            let ch = charset[char_index] as char;

            // Check for consecutive repetition (max 2)
            if ch == last_char {
                last_count += 1;
                if last_count >= 2 {
                    // Skip this character and rehash
                    hasher = Hasher::new();
                    hasher.update(&hash);
                    hasher.update(&[i as u8]);
                    hash = hasher.finalize().as_bytes().to_vec();
                    continue;
                }
            } else {
                last_char = ch;
                last_count = 1;
            }

            // Track character categories
            if ch.is_lowercase() { has_lower = true; }
            if ch.is_uppercase() { has_upper = true; }
            if ch.is_numeric() { has_digit = true; }
            if !ch.is_alphanumeric() { has_symbol = true; }

            password.push(ch);
        }

        // Ensure at least one from each category
        if !has_lower || !has_upper || !has_digit || !has_symbol {
            // Force inclusion by replacing specific positions
            let mut result = password.chars().collect::<Vec<char>>();
            let len = result.len();
            if !has_lower && len > 3 { result[len - 4] = 'a'; }
            if !has_upper && len > 2 { result[len - 3] = 'Z'; }
            if !has_digit && len > 1 { result[len - 2] = '7'; }
            if !has_symbol && len > 0 { result[len - 1] = '@'; }
            password = result.into_iter().collect();
        }

        Ok(password)
    }

    /// Encode bytes to password with custom character categories
    /// Strategy: Ensure required categories appear within first 16 characters (for retry attempts)
    /// Sites will truncate to their length requirements naturally
    ///
    /// # Parameters
    /// - enforce_first_16: If true, ensures categories in first 16 chars (retry attempts)
    ///                     If false, validates across full password (first attempt)
    fn encode_with_categories(
        &self,
        data: &[u8],
        length: usize,
        categories: &PasswordCategories,
        enforce_first_16: bool,
    ) -> Result<String, CryptoError> {
        // Build charset from enabled categories
        let charset = categories.build_charset();
        if charset.is_empty() {
            return Err(CryptoError::InvalidInput(
                "At least one character category must be enabled".to_string()
            ));
        }

        let charset_bytes = charset.as_bytes();
        let mut password = String::new();

        // Use BLAKE3 to expand data for deterministic password generation
        let mut hasher = Hasher::new();
        hasher.update(data);
        let mut hash = hasher.finalize().as_bytes().to_vec();

        let mut last_char = '\0';
        let mut last_count = 0;
        let mut key_index = 0;

        while password.len() < length {
            // Re-hash if we need more entropy
            if key_index > 0 && key_index % hash.len() == 0 {
                hasher = Hasher::new();
                hasher.update(&hash);
                hasher.update(&[key_index as u8]);
                hash = hasher.finalize().as_bytes().to_vec();
            }

            let byte_index = key_index % hash.len();
            let char_index = (hash[byte_index] as usize) % charset_bytes.len();
            let ch = charset_bytes[char_index] as char;

            // Check for consecutive repetition (max 2)
            if ch == last_char {
                last_count += 1;
                if last_count >= 2 {
                    // Skip this character
                    key_index += 1;
                    continue;
                }
            } else {
                last_char = ch;
                last_count = 1;
            }

            password.push(ch);
            key_index += 1;
        }

        // Post-processing: Conditionally enforce categories in first 16 chars
        // Only for retry attempts - first attempt validates across full password
        if enforce_first_16 {
            self.ensure_categories_in_prefix(&mut password, categories);
        }

        Ok(password)
    }

    /// Ensure each required category appears within first 16 characters
    /// This handles sites that truncate passwords to 8-16 character limits
    fn ensure_categories_in_prefix(
        &self,
        password: &mut String,
        categories: &PasswordCategories,
    ) {
        const CRITICAL_WINDOW: usize = 16; // First 16 chars must have all categories

        let mut chars: Vec<char> = password.chars().collect();
        if chars.len() < CRITICAL_WINDOW {
            return; // Password too short, skip enforcement
        }

        // Check what categories exist in first 16 chars
        let prefix = &chars[..CRITICAL_WINDOW];
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_number = false;
        let mut has_symbol = false; // Only counts !@#$%^&*() (not .-_)

        for &ch in prefix {
            if ch.is_ascii_lowercase() {
                has_lowercase = true;
            } else if ch.is_ascii_uppercase() {
                has_uppercase = true;
            } else if ch.is_ascii_digit() {
                has_number = true;
            } else if "!@#$%^&*()".contains(ch) {
                has_symbol = true;
            }
        }

        // Inject missing required categories into first 16 positions
        // Use positions 12-15 (toward end of critical window) to minimize pattern detection
        let mut inject_pos = 12;

        if categories.lowercase && !has_lowercase && chars.len() > inject_pos {
            chars[inject_pos] = 'a';
            inject_pos += 1;
        }
        if categories.uppercase && !has_uppercase && chars.len() > inject_pos {
            chars[inject_pos] = 'Z';
            inject_pos += 1;
        }
        if categories.numbers && !has_number && chars.len() > inject_pos {
            chars[inject_pos] = '7';
            inject_pos += 1;
        }
        if categories.symbols && !has_symbol && chars.len() > inject_pos {
            // Use first allowed symbol
            let symbol = if let Some(ref allowed) = categories.allowed_symbols {
                allowed.chars().next().unwrap_or('!')
            } else {
                '!'
            };
            if chars.len() > inject_pos {
                chars[inject_pos] = symbol;
            }
        }

        *password = chars.into_iter().collect();
    }
}

/// Generate encryption master key from default username and author's full name
/// For encrypting/decrypting passphrase templates in storage
pub fn generate_encryption_key(
    default_username: &str,
    author_fullname: &str,
    master_seed: &MasterSeed,
) -> Result<SecureBytes, CryptoError> {
    // Normalize author fullname: remove spaces, lowercase
    let author_normalized: String = author_fullname
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();

    // Create templates with placeholders
    let first_template = PassphraseTemplate::new(
        format!("encryption_key_{{USERNAME}}")
    );
    let second_template = PassphraseTemplate::new(
        format!("encryption_key_{{SITE}}")
    );

    // Fill templates
    let first_phrase = first_template.fill("{USERNAME}", default_username);
    let second_phrase = second_template.fill("{SITE}", &author_normalized);

    // Generate encryption key: BLAKE3(phrase + seed) -> Argon2id
    let first_combined = format!("{}{}", first_phrase, master_seed.as_str());
    let first_blake = blake3_hash(first_combined.as_bytes());
    let first_salt = blake3_hash(b"passmemo_encryption_salt");
    let first_half = argon2id_hash(&first_blake, &first_salt[..16])?;

    let second_combined = format!("{}{}", second_phrase, master_seed.as_str());
    let second_blake = blake3_hash(second_combined.as_bytes());
    let second_salt = blake3_hash(b"passmemo_encryption_salt2");
    let second_half = argon2id_hash(&second_blake, &second_salt[..16])?;

    // Combine to create 512-bit key, then take first 256 bits for AES-256
    let mut key_material = Vec::new();
    key_material.extend_from_slice(first_half.as_bytes());
    key_material.extend_from_slice(second_half.as_bytes());

    // Use first 32 bytes (256 bits) for AES-256-GCM
    Ok(SecureBytes::new(key_material[..32].to_vec()))
}

/// Encrypt passphrase template using AES-256-GCM
/// Returns: nonce (12 bytes) + ciphertext
pub fn encrypt_passphrase(
    passphrase: &str,
    encryption_key: &SecureBytes,
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::rand_core::RngCore;

    let key = Key::<Aes256Gcm>::from_slice(encryption_key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    // Generate random nonce for this encryption
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, passphrase.as_bytes())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Prepend nonce to ciphertext for storage
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt passphrase template using AES-256-GCM
/// Input: nonce (12 bytes) + ciphertext
pub fn decrypt_passphrase(
    data: &[u8],
    encryption_key: &SecureBytes,
) -> Result<String, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::DecryptionError("Data too short".to_string()));
    }

    let key = Key::<Aes256Gcm>::from_slice(encryption_key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_seed_creation() {
        let seed = MasterSeed::new("9780770118686", 112, 57).unwrap();
        assert_eq!(seed.as_str(), "0770118686112057");
    }

    #[test]
    fn test_master_seed_isbn10() {
        let seed = MasterSeed::new("0770118686", 112, 57).unwrap();
        assert_eq!(seed.as_str(), "0770118686112057");
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash = blake3_hash(data);
        assert_eq!(hash.len(), 32); // BLAKE3 produces 32-byte hash
    }

    #[test]
    fn test_template_filling() {
        let template = PassphraseTemplate::new(
            "Nothing can be real until you can imagine like a {USERNAME}".to_string()
        );
        let filled = template.fill("{USERNAME}", "melanee@mail.com");
        assert_eq!(filled, "Nothing can be real until you can imagine like a melanee@mail.com");
    }

    #[test]
    fn test_password_generation_with_templates() {
        let seed = MasterSeed::new("9780770118686", 112, 57).unwrap();
        let generator = QuantumPasswordGenerator::new(seed);

        let first_template = PassphraseTemplate::new(
            "Nothing can be real until you can imagine like a {USERNAME}".to_string()
        );
        let second_template = PassphraseTemplate::new(
            "Only under a blue sky the {SITE} cry".to_string()
        );

        let password = generator.generate_password(
            &first_template,
            &second_template,
            "MelAnee@mail.com",
            "Facebook",
            32,
        ).unwrap();

        assert_eq!(password.len(), 32);

        // Verify deterministic generation
        let password2 = generator.generate_password(
            &first_template,
            &second_template,
            "MelAnee@mail.com",
            "Facebook",
            32,
        ).unwrap();
        assert_eq!(password, password2);

        // Verify case-insensitive determinism
        let password3 = generator.generate_password(
            &first_template,
            &second_template,
            "melanee@mail.com",  // lowercase
            "facebook",          // lowercase
            32,
        ).unwrap();
        assert_eq!(password, password3, "Passwords should be the same regardless of case");

        // Verify different site produces different password
        let password4 = generator.generate_password(
            &first_template,
            &second_template,
            "MelAnee@mail.com",
            "Twitter",
            32,
        ).unwrap();
        assert_ne!(password, password4);
    }
}
