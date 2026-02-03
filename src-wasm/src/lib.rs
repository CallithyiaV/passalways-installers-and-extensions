// PassMemo Browser Extension - WASM Bridge
// Co-Authored-By: Project Engineer MelAnee Hannah

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

// Re-export core crypto modules from parent project
// We'll link to the main crypto.rs implementation
mod crypto;
use crypto::{MasterSeed, PassphraseTemplate, QuantumPasswordGenerator};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Serialize, Deserialize)]
pub struct PasswordCategories {
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub allowed_symbols: Option<String>,
}

#[wasm_bindgen]
pub struct PassmemoGenerator {
    generator: QuantumPasswordGenerator,
    phrase1_template: PassphraseTemplate,
    phrase2_template: PassphraseTemplate,
}

#[wasm_bindgen]
impl PassmemoGenerator {
    /// Create a new generator instance
    #[wasm_bindgen(constructor)]
    pub fn new(
        isbn: &str,
        page1: u16,
        page2: u16,
        passphrase1: &str,
        passphrase2: &str,
    ) -> Result<PassmemoGenerator, JsValue> {
        // Validate inputs
        if !passphrase1.contains("{USERNAME}") {
            return Err(JsValue::from_str("Passphrase 1 must contain {USERNAME} placeholder"));
        }
        if !passphrase2.contains("{SITE}") {
            return Err(JsValue::from_str("Passphrase 2 must contain {SITE} placeholder"));
        }

        // Create master seed
        let master_seed = MasterSeed::new(isbn, page1, page2)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Create templates
        let phrase1_template = PassphraseTemplate::new(passphrase1.to_string());
        let phrase2_template = PassphraseTemplate::new(passphrase2.to_string());

        // Create generator
        let generator = QuantumPasswordGenerator::new(master_seed);

        Ok(PassmemoGenerator {
            generator,
            phrase1_template,
            phrase2_template,
        })
    }

    /// Generate a password for a site
    #[wasm_bindgen]
    pub fn generate_password(
        &self,
        site: &str,
        username: &str,
        length: usize,
        categories_js: JsValue,
        enforce_categories: bool,
        version: u32,
    ) -> Result<String, JsValue> {
        // Deserialize categories from JavaScript
        let categories: PasswordCategories = serde_wasm_bindgen::from_value(categories_js)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse categories: {:?}", e)))?;

        // Convert to internal format
        let pwd_categories = crypto::PasswordCategories {
            lowercase: categories.lowercase,
            uppercase: categories.uppercase,
            numbers: categories.numbers,
            symbols: categories.symbols,
            allowed_symbols: categories.allowed_symbols,
        };

        // Generate password with attributes
        let password = self.generator
            .generate_password_with_attributes(
                &self.phrase1_template,
                &self.phrase2_template,
                username,
                site,
                length,
                &pwd_categories,
                enforce_categories,
                version,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(password)
    }

    /// Generate password with first-16 enforcement control
    #[wasm_bindgen]
    pub fn generate_password_advanced(
        &self,
        site: &str,
        username: &str,
        length: usize,
        categories_js: JsValue,
        enforce_categories: bool,
        version: u32,
        enforce_first_16: bool,
    ) -> Result<String, JsValue> {
        // Deserialize categories
        let categories: PasswordCategories = serde_wasm_bindgen::from_value(categories_js)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse categories: {:?}", e)))?;

        // Convert to internal format
        let pwd_categories = crypto::PasswordCategories {
            lowercase: categories.lowercase,
            uppercase: categories.uppercase,
            numbers: categories.numbers,
            symbols: categories.symbols,
            allowed_symbols: categories.allowed_symbols,
        };

        // Generate password with internal method
        let password = self.generator
            .generate_password_with_attributes_internal(
                &self.phrase1_template,
                &self.phrase2_template,
                username,
                site,
                length,
                &pwd_categories,
                enforce_categories,
                version,
                enforce_first_16,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(password)
    }
}

/// Verify ISBN checksum (utility function)
#[wasm_bindgen]
pub fn verify_isbn(isbn: &str) -> bool {
    // ISBN-13 checksum validation
    if isbn.len() != 13 {
        return false;
    }

    let digits: Vec<u32> = isbn.chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 13 {
        return false;
    }

    let sum: u32 = digits.iter()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 0 { d } else { d * 3 })
        .sum();

    sum % 10 == 0
}

#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    log("PassMemo WASM module initialized");
}
