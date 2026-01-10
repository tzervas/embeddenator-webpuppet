//! # webpuppet
//!
//! Browser automation library for AI provider web interfaces.
//!
//! This crate provides programmatic control of Chromium-based browsers to interact
//! with AI chat providers through their web UIs. It handles authentication, session
//! management, and response extraction for research and development workflows.
//!
//! ## Supported Browsers
//!
//! **Chromium-based (Full CDP automation)**:
//! Brave, Chrome, Chromium, Edge, Opera, Vivaldi
//!
//! **Detection only**: Firefox (Gecko), Safari (WebKit, macOS only)
//!
//! **Cross-platform**: Linux, macOS, Windows (including Flatpak/Snap on Linux)
//!
//! ## Features
//!
//! - **Multi-provider support**: Claude, Grok, Gemini, ChatGPT, Perplexity, NotebookLM, Kaggle
//! - **Browser automation**: CDP (Chrome DevTools Protocol) via chromiumoxide
//! - **Browser detection**: Automatic detection with platform-specific paths
//! - **Session persistence**: Secure credential and cookie storage with AES-256-GCM
//! - **Rate limiting**: Configurable request throttling with humanized delays
//! - **Content security**: Response screening for security threats
//! - **Permission controls**: Domain allowlisting and operation restrictions
//!
//! ## Security Considerations
//!
//! ⚠️ **IMPORTANT**: This library automates third-party web interfaces. Users must
//! comply with provider terms of service and applicable laws.
//!
//! - Credentials stored in OS keyring with AES-256-GCM encryption (never plaintext)
//! - Browser profiles sandboxed per provider
//! - Rate limiting prevents abuse detection
//! - All automation is local (no external API calls)
//! - Permission controls block unauthorized operations
//!
//! ## Example
//!
//! ```rust,ignore
//! use webpuppet::{WebPuppet, Provider, PromptRequest};
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
pub use permissions::{Operation, PermissionDecision, PermissionGuard, PermissionPolicy};
pub use providers::{Provider, ProviderTrait};
pub use puppet::{PromptRequest, PromptResponse, WebPuppet};
pub use ratelimit::RateLimiter;
pub use security::{ContentScreener, ScreeningConfig, ScreeningResult, SecurityIssue};
pub use session::Session;
