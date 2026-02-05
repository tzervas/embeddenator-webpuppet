//! Trait-based detector system for security screening.
//!
//! Defines the core [`Detector`] trait and common types shared across all
//! detection modules (PII, secrets, injection, content screening).

use std::fmt;

/// Severity levels for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational finding, no action needed.
    Info,
    /// Low severity, minor concern.
    Low,
    /// Medium severity, should be reviewed.
    Medium,
    /// High severity, likely requires action.
    High,
    /// Critical severity, must be addressed immediately.
    Critical,
}

impl Severity {
    /// Numeric weight for risk score calculation.
    pub fn weight(&self) -> f32 {
        match self {
            Severity::Info => 0.1,
            Severity::Low => 0.2,
            Severity::Medium => 0.5,
            Severity::High => 0.8,
            Severity::Critical => 1.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Direction of content being screened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Content going to the AI provider (user input).
    Input,
    /// Content coming from the AI provider (response).
    Output,
    /// Content being proxied through MCP.
    McpToolCall,
    /// Content from MCP tool response.
    McpToolResult,
}

/// A single security finding from a detector.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Which detector produced this finding.
    pub detector: String,
    /// Category of the finding.
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// The matched content (may be truncated).
    pub matched_content: String,
    /// Severity level.
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Byte offset in the original content where the match starts.
    pub offset: Option<usize>,
    /// Length of the match in bytes.
    pub length: Option<usize>,
    /// Suggested redaction replacement text, if applicable.
    pub redaction: Option<String>,
}

/// Verdict from the security pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Content is safe to pass through.
    Safe,
    /// Content has warnings but can proceed.
    Warning,
    /// Content was redacted and can proceed.
    Redacted,
    /// Content is blocked due to policy.
    Blocked,
    /// Screening timed out.
    Timeout,
    /// An error occurred during screening.
    Error,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Safe => write!(f, "safe"),
            Verdict::Warning => write!(f, "warning"),
            Verdict::Redacted => write!(f, "redacted"),
            Verdict::Blocked => write!(f, "blocked"),
            Verdict::Timeout => write!(f, "timeout"),
            Verdict::Error => write!(f, "error"),
        }
    }
}

/// Trait for all security detectors.
pub trait Detector: Send + Sync {
    /// Name of this detector.
    fn name(&self) -> &str;

    /// Detect issues in the given content.
    fn detect(&self, content: &str, direction: Direction) -> Vec<Finding>;

    /// Whether this detector is relevant for the given direction.
    fn supports_direction(&self, direction: Direction) -> bool;
}
