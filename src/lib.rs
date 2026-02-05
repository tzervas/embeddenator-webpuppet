//! # webpuppet
//!
//! Browser automation library for AI provider web interfaces with integrated
//! security pipeline.
//!
//! This crate provides programmatic control of Chromium-based browsers to interact
//! with AI chat providers through their web UIs. It handles authentication, session
//! management, response extraction, and **mandatory security screening** for
//! research and development workflows.
//!
//! ## Security Architecture
//!
//! All content flows through a unified security pipeline by default:
//! - **Input screening**: SQL injection, command injection, XSS, path traversal,
//!   LDAP, XXE, SSTI, prompt injection, and control character detection
//! - **Output screening**: PII detection (email, phone, SSN, credit card, IP),
//!   secrets detection (AWS keys, GitHub tokens, JWT, private keys, database URLs),
//!   and content manipulation detection (zero-width chars, hidden HTML, homoglyphs)
//! - **MCP proxy**: Stateful connections to downstream MCP servers with enforced
//!   security screening on all tool calls and responses
//! - **Redaction**: Automatic masking of sensitive data in content
//!
//! ## Display Modes
//!
//! - **Headless**: No visible browser UI (default, for automation)
//! - **HeadsUp**: Interactive popup browser window for observation and intervention
//! - **Dashboard**: Full monitoring with dual-head browsers for security review
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
//! ## Example
//!
//! ```rust,ignore
//! use webpuppet::{WebPuppet, Provider, PromptRequest, DisplayMode};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let puppet = WebPuppet::builder()
//!         .with_provider(Provider::Claude)
//!         .display_mode(DisplayMode::HeadsUp) // Interactive browser
//!         .build()
//!         .await?;
//!
//!     // Input is screened for injection; output is screened for PII/secrets
//!     let response = puppet.prompt(
//!         Provider::Claude,
//!         PromptRequest::new("Explain io_uring async I/O in Rust"),
//!     ).await?;
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
pub mod display;
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
pub use display::DisplayMode;
pub use error::{Error, Result};
pub use intervention::{
    InterventionConfig, InterventionDetector, InterventionHandler, InterventionReason,
    InterventionState,
};
pub use permissions::{Operation, PermissionDecision, PermissionGuard, PermissionPolicy};
pub use providers::{Provider, ProviderTrait};
pub use puppet::{PromptRequest, PromptResponse, WebPuppet};
pub use ratelimit::RateLimiter;
pub use security::screening::{ContentScreener, ScreeningConfig, ScreeningResult, SecurityIssue};
pub use security::{
    Direction, Finding, McpSecurityProxy, PipelineConfig, PipelineResult, SecurityPipeline,
    Severity, Verdict,
};
pub use session::Session;
