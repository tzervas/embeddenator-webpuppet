//! Data encryption utilities for secure credential and cookie storage.
//!
//! Provides AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;

/// Helper for encrypting sensitive data like cookies.
pub struct DataEncryption {
    key: Secret<[u8; 32]>,
}

impl DataEncryption {
    /// Create a new encryption helper using a passphrase and salt.
    pub fn new(passphrase: &str, salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, 100_000, &mut key);
        Self {
            key: Secret::new(key),
        }
    }

    /// Encrypt data using AES-256-GCM.
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret())
            .map_err(|e| anyhow::anyhow!("Crypto error: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data using AES-256-GCM.
    pub fn decrypt(&self, encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }

        let cipher = Aes256Gcm::new_from_slice(self.key.expose_secret())
            .map_err(|e| anyhow::anyhow!("Crypto error: {}", e))?;

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
}
