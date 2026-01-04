//! # embeddenator-webpuppet
//!
//! Self-hosted browser automation for AI provider web UIs.
//!
//! This crate provides puppeteer-like functionality for automating interactions
//! with AI chat interfaces (Grok, Claude, Gemini) through their web UIs,
//! bypassing API requirements.
//!
//! ## Features
//!
//! - **Multi-provider support**: Grok (X.ai), Claude (Anthropic), Gemini (Google)
//! - **Headless browser automation**: Chrome/Chromium/Brave via chromiumoxide
//! - **System browser integration**: Use existing Brave/Chrome profiles with auth
//! - **Session management**: Persistent auth, cookie handling
//! - **Rate limiting**: Respect provider limits, avoid detection
//! - **Security guardrails**: Permission system blocks destructive operations
//! - **Secure credential storage**: OS keyring integration
//!
//! ## Security Considerations
//!
//! ⚠️ **IMPORTANT**: This tool automates web UIs which may violate terms of service.
//! Use responsibly and only for legitimate research purposes.
//!
//! - Credentials are stored in the OS keyring, never in plaintext
//! - Browser profiles are sandboxed per-provider
//! - Rate limiting prevents abuse detection
//! - All automation is local - no external API calls
//! - Permission guardrails block destructive operations by default
//!
//! ## Example
//!
//! ```rust,ignore
//! use embeddenator_webpuppet::{WebPuppet, Provider, PromptRequest};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let puppet = WebPuppet::new()
//!         .with_provider(Provider::Claude)
//!         .headless(true)
//!         .build()
//!         .await?;
//!
//!     let response = puppet.prompt(PromptRequest {
//!         message: "Explain io_uring async I/O in Rust".into(),
//!         context: Some("Focus on memory safety".into()),
//!         ..Default::default()
//!     }).await?;
//!
//!     println!("Response: {}", response.text);
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod browser;
pub mod config;
pub mod credentials;
pub mod error;
pub mod intervention;
pub mod permissions;
pub mod providers;
pub mod puppet;
pub mod ratelimit;
pub mod security;
pub mod session;

pub use browser::{BrowserDetector, BrowserInstallation, BrowserLaunchConfig, BrowserType};
pub use config::Config;
pub use credentials::CredentialStore;
pub use error::{Error, Result};
pub use intervention::{
    InterventionConfig, InterventionDetector, InterventionHandler, InterventionReason,
    InterventionState,
};
pub use permissions::{Operation, PermissionGuard, PermissionPolicy, PermissionDecision};
pub use providers::{Provider, ProviderTrait};
pub use puppet::{PromptRequest, PromptResponse, WebPuppet};
pub use ratelimit::RateLimiter;
pub use security::{ContentScreener, ScreeningConfig, ScreeningResult, SecurityIssue};
pub use session::Session;
