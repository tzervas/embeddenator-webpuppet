//! Unified security module for webpuppet.
//!
//! This module integrates all security capabilities from the original webpuppet-rs
//! ContentScreener and the security-mcp project into a single, mandatory security
//! pipeline. All content -- prompts, responses, and MCP tool calls -- flows through
//! this pipeline by default.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   SecurityPipeline                       │
//! │                                                         │
//! │  Input ──► InjectionDetector ──► Verdict                │
//! │            (SQL, XSS, cmd, path traversal, LDAP,        │
//! │             XXE, SSTI, prompt injection, control chars)  │
//! │                                                         │
//! │  Output ──► PiiDetector ──► SecretDetector ──►          │
//! │            ContentScreener ──► Redaction ──► Verdict     │
//! │            (email, phone, SSN, credit card, IP,          │
//! │             AWS keys, GitHub tokens, JWT, private keys,  │
//! │             zero-width, hidden HTML, homoglyphs)         │
//! │                                                         │
//! │  MCP ──► InjectionDetector ──► PiiDetector ──►          │
//! │          SecretDetector ──► Redaction ──► Verdict        │
//! │                                                         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`detectors`] - Core trait and types for all detectors
//! - [`patterns`] - Compiled regex patterns (lazy-initialized)
//! - [`injection`] - Input injection detection (9 categories)
//! - [`pii`] - PII detection (8 categories)
//! - [`secrets`] - Secrets/credential detection (9 categories + entropy)
//! - [`screening`] - Original ContentScreener (hidden text, homoglyphs, etc.)
//! - [`redaction`] - Content redaction engine
//! - [`pipeline`] - SecurityPipeline orchestrator
//! - [`proxy`] - MCP security proxy for tool call routing enforcement
//! - [`encryption`] - AES-256-GCM encryption utilities

pub mod detectors;
pub mod encryption;
pub mod injection;
pub mod patterns;
pub mod pii;
pub mod pipeline;
pub mod proxy;
pub mod redaction;
pub mod screening;
pub mod secrets;

// Re-export primary types for convenience
pub use detectors::{Detector, Direction, Finding, Severity, Verdict};
pub use encryption::DataEncryption;
pub use injection::InjectionDetector;
pub use pii::PiiDetector;
pub use pipeline::{PipelineConfig, PipelineResult, SecurityPipeline};
pub use proxy::{
    ConnectionStatus, McpResponseScreeningResult, McpScreeningResult, McpSecurityProxy,
    McpServerConfig, McpServerState, McpToolInfo, McpTransport, ScreeningStats,
};
pub use redaction::redact;
pub use screening::{ContentScreener, ScreeningConfig, ScreeningResult, SecurityIssue};
pub use secrets::SecretDetector;
