//! # embeddenator-webpuppet
//!
//! Browser automation library for AI provider web interfaces.
//!
//! This crate provides programmatic control of Chrome/Chromium browsers to interact 
//! with AI chat providers through their web UIs. It handles authentication, session 
//! management, and response extraction for research and development workflows.
//!
//! ## Features
//!
//! - **Multi-provider support**: Claude, Grok, Gemini, ChatGPT, Perplexity, NotebookLM
//! - **Browser automation**: Chrome/Chromium control via chromiumoxide
//! - **Session persistence**: Secure credential and cookie storage
//! - **Rate limiting**: Configurable request throttling
//! - **Content security**: Response screening for security threats
//!
//! ## Security Considerations
//!
//! ⚠️ **IMPORTANT**: This library automates third-party web interfaces. Users must
//! comply with provider terms of service and applicable laws.
//!
//! - Credentials stored in OS keyring (never plaintext)
//! - Browser profiles sandboxed per provider
//! - Rate limiting prevents abuse detection
//! - All automation is local (no external API calls)
//! - Permission controls block unauthorized operations
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
