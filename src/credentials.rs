//! Secure credential storage using OS keyring.

use std::sync::RwLock;

#[allow(unused_imports)]
use crate::error::{Error, Result};
use crate::providers::Provider;
use crate::security::DataEncryption;
use std::sync::OnceLock;

/// Service name for keyring entries.
#[allow(dead_code)]
const SERVICE_NAME: &str = "embeddenator-webpuppet";

static MEM_KEY: OnceLock<String> = OnceLock::new();

fn get_mem_key() -> &'static str {
    MEM_KEY.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Secure credential storage.
pub struct CredentialStore {
    // In-memory cache (encrypted at rest)
    cache: RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl CredentialStore {
    /// Create a new credential store.
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(std::collections::HashMap::new()),
        })
    }

    fn get_encryption(&self) -> DataEncryption {
        DataEncryption::new(get_mem_key(), b"mem_cache_salt")
    }

    /// Store a credential for a provider.
    pub fn store(&self, provider: Provider, key: &str, value: &str) -> Result<()> {
        let entry_name = format!("{}:{}", provider.name(), key);

        // Try to store in OS keyring
        #[cfg(feature = "keyring")]
        {
            let entry = keyring::Entry::new(SERVICE_NAME, &entry_name)
                .map_err(|e| Error::Credential(e.to_string()))?;
            entry
                .set_password(value)
                .map_err(|e| Error::Credential(e.to_string()))?;
        }

        // Also cache in memory (encrypted)
        let encryption = self.get_encryption();
        let encrypted = encryption
            .encrypt(value.as_bytes())
            .map_err(|e| Error::Internal(format!("Memory encryption failed: {}", e)))?;

        let mut cache = self.cache.write().unwrap();
        cache.insert(entry_name, encrypted);

        Ok(())
    }

    /// Retrieve a credential for a provider.
    pub fn get(&self, provider: Provider, key: &str) -> Result<Option<String>> {
        let entry_name = format!("{}:{}", provider.name(), key);

        // Check in-memory cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(encrypted) = cache.get(&entry_name) {
                let encryption = self.get_encryption();
                let decrypted = encryption
                    .decrypt(encrypted)
                    .map_err(|e| Error::Internal(format!("Memory decryption failed: {}", e)))?;
                return Ok(Some(String::from_utf8(decrypted).unwrap()));
            }
        }

        // Try OS keyring
        #[cfg(feature = "keyring")]
        {
            let entry = keyring::Entry::new(SERVICE_NAME, &entry_name)
                .map_err(|e| Error::Credential(e.to_string()))?;

            match entry.get_password() {
                Ok(value) => {
                    // Cache for future use (encrypted)
                    let encryption = self.get_encryption();
                    let encrypted = encryption
                        .encrypt(value.as_bytes())
                        .map_err(|e| Error::Internal(format!("Memory encryption failed: {}", e)))?;

                    let mut cache = self.cache.write().unwrap();
                    cache.insert(entry_name, encrypted);
                    return Ok(Some(value));
                }
                Err(keyring::Error::NoEntry) => return Ok(None),
                Err(e) => return Err(Error::Credential(e.to_string())),
            }
        }

        #[allow(unreachable_code)]
        Ok(None)
    }

    /// Delete a credential.
    pub fn delete(&self, provider: Provider, key: &str) -> Result<()> {
        let entry_name = format!("{}:{}", provider.name(), key);

        // Remove from cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.remove(&entry_name);
        }

        // Remove from keyring
        #[cfg(feature = "keyring")]
        {
            let entry = keyring::Entry::new(SERVICE_NAME, &entry_name)
                .map_err(|e| Error::Credential(e.to_string()))?;

            // Ignore NoEntry error (already deleted)
            match entry.delete_credential() {
                Ok(_) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(Error::Credential(e.to_string())),
            }
        }

        Ok(())
    }

    /// Check if credentials exist for a provider.
    pub fn has_credentials(&self, provider: Provider) -> bool {
        // Check for common credential keys
        let keys = ["session_token", "auth_cookie", "refresh_token"];

        for key in keys {
            if self.get(provider, key).ok().flatten().is_some() {
                return true;
            }
        }

        false
    }

    /// Clear all credentials for a provider.
    pub fn clear_provider(&self, provider: Provider) -> Result<()> {
        // Common credential keys
        let keys = [
            "session_token",
            "auth_cookie",
            "refresh_token",
            "access_token",
            "username",
        ];

        for key in keys {
            self.delete(provider, key).ok();
        }

        Ok(())
    }

    /// Store sensitive data with automatic zeroization.
    #[cfg(feature = "secrecy")]
    pub fn store_secret(
        &self,
        provider: Provider,
        key: &str,
        secret: secrecy::SecretString,
    ) -> Result<()> {
        use secrecy::ExposeSecret;
        self.store(provider, key, secret.expose_secret())
    }

    /// Retrieve sensitive data as a zeroizing secret.
    #[cfg(feature = "secrecy")]
    pub fn get_secret(
        &self,
        provider: Provider,
        key: &str,
    ) -> Result<Option<secrecy::SecretString>> {
        self.get(provider, key)
            .map(|opt| opt.map(|s| secrecy::SecretString::new(s.into())))
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new().expect("Failed to create credential store")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_store_cache() {
        let store = CredentialStore::new().unwrap();

        // Store should work with in-memory cache
        store
            .store(Provider::Claude, "test_key", "test_value")
            .unwrap();

        // Retrieval should work
        let value = store.get(Provider::Claude, "test_key").unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        // Delete should work
        store.delete(Provider::Claude, "test_key").unwrap();
        let value = store.get(Provider::Claude, "test_key").unwrap();
        assert_eq!(value, None);
    }
}
