//! Error types for webpuppet operations.

use std::fmt;
use thiserror::Error;

/// Result type alias for webpuppet operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during browser automation.
#[derive(Error, Debug)]
pub enum Error {
    /// Browser failed to launch or crashed.
    #[error("browser error: {0}")]
    Browser(String),

    /// Navigation failed (timeout, invalid URL, etc.).
    #[error("navigation error: {0}")]
    Navigation(String),

    /// Element not found on page.
    #[error("element not found: {selector}")]
    ElementNotFound {
        /// CSS selector that failed.
        selector: String,
    },

    /// Authentication failed.
    #[error("authentication failed for provider {provider}: {reason}")]
    AuthenticationFailed {
        /// Provider name.
        provider: String,
        /// Failure reason.
        reason: String,
    },

    /// Session expired or invalid.
    #[error("session expired for provider {0}")]
    SessionExpired(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded, retry after {retry_after_secs}s")]
    RateLimitExceeded {
        /// Seconds to wait before retry.
        retry_after_secs: u64,
    },

    /// Provider returned an error response.
    #[error("provider error from {provider}: {message}")]
    ProviderError {
        /// Provider name.
        provider: String,
        /// Error message from provider.
        message: String,
    },

    /// Response extraction failed.
    #[error("failed to extract response: {0}")]
    ExtractionFailed(String),

    /// Credential storage error.
    #[error("credential error: {0}")]
    Credential(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Timeout waiting for operation.
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// Provider not supported or not enabled.
    #[error("provider {0} not supported")]
    UnsupportedProvider(String),

    /// Browser not found at path.
    #[error("browser not found at path: {0}")]
    BrowserNotFound(String),

    /// Permission denied for operation.
    #[error("permission denied for {operation}: {reason}")]
    PermissionDenied {
        /// Operation that was denied.
        operation: String,
        /// Reason for denial.
        reason: String,
    },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Chromium-specific error.
    #[cfg(feature = "chromium")]
    #[error("chromium error: {0}")]
    Chromium(String),

    /// WebDriver error.
    #[cfg(feature = "firefox")]
    #[error("webdriver error: {0}")]
    WebDriver(String),

    /// Human intervention was cancelled.
    #[error("intervention cancelled by user")]
    InterventionCancelled,

    /// Human intervention timed out.
    #[error("intervention timed out after {0}s")]
    InterventionTimeout(u64),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Navigation(_)
                | Error::RateLimitExceeded { .. }
                | Error::Timeout(_)
                | Error::Browser(_)
        )
    }

    /// Returns the retry delay in seconds, if applicable.
    pub fn retry_delay_secs(&self) -> Option<u64> {
        match self {
            Error::RateLimitExceeded { retry_after_secs } => Some(*retry_after_secs),
            Error::Timeout(_) => Some(5),
            Error::Navigation(_) | Error::Browser(_) => Some(10),
            _ => None,
        }
    }
}

/// Detailed error context for debugging.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// The operation that failed.
    pub operation: String,
    /// Provider involved, if any.
    pub provider: Option<String>,
    /// URL being accessed, if any.
    pub url: Option<String>,
    /// Additional context.
    pub details: Option<String>,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation: {}", self.operation)?;
        if let Some(ref p) = self.provider {
            write!(f, ", provider: {}", p)?;
        }
        if let Some(ref u) = self.url {
            write!(f, ", url: {}", u)?;
        }
        if let Some(ref d) = self.details {
            write!(f, ", details: {}", d)?;
        }
        Ok(())
    }
}
