//! Security pipeline orchestrator.
//!
//! The [`SecurityPipeline`] runs all registered detectors against content,
//! aggregates findings, computes risk scores, and determines a verdict.
//! This is the core enforcement layer -- all content must flow through it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::detectors::{Detector, Direction, Finding, Severity, Verdict};
use super::injection::InjectionDetector;
use super::pii::PiiDetector;
use super::redaction;
use super::screening::ContentScreener;
use super::secrets::SecretDetector;

/// Configuration for the security pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Enable input screening (injection detection).
    pub screen_input: bool,
    /// Enable output screening (PII, secrets, content manipulation).
    pub screen_output: bool,
    /// Enable PII detection.
    pub enable_pii: bool,
    /// Enable secrets detection.
    pub enable_secrets: bool,
    /// Enable injection detection.
    pub enable_injection: bool,
    /// Enable content screening (zero-width, hidden elements, etc.).
    pub enable_content_screening: bool,
    /// Automatically redact sensitive findings.
    pub auto_redact: bool,
    /// Block content with high/critical severity findings.
    pub block_on_high: bool,
    /// Allow content that has warning-level findings to pass.
    pub allow_warnings: bool,
    /// Risk score threshold for blocking (0.0 - 1.0).
    pub risk_threshold: f32,
    /// Maximum content size in bytes (reject larger).
    pub max_content_size: usize,
    /// Log all screening decisions.
    pub audit_all: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            screen_input: true,
            screen_output: true,
            enable_pii: true,
            enable_secrets: true,
            enable_injection: true,
            enable_content_screening: true,
            auto_redact: true,
            block_on_high: true,
            allow_warnings: true,
            risk_threshold: 0.7,
            max_content_size: 10 * 1024 * 1024, // 10MB
            audit_all: false,
        }
    }
}

/// Result from the security pipeline.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// The verdict (Safe, Warning, Redacted, Blocked).
    pub verdict: Verdict,
    /// All findings from all detectors.
    pub findings: Vec<Finding>,
    /// Aggregate risk score (0.0 - 1.0).
    pub risk_score: f32,
    /// The content after redaction (if redaction was applied).
    pub redacted_content: Option<String>,
    /// The original content.
    pub original_content: String,
    /// Which direction was screened.
    pub direction: Direction,
}

impl PipelineResult {
    /// Whether the content is allowed to proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self.verdict,
            Verdict::Safe | Verdict::Warning | Verdict::Redacted
        )
    }

    /// Get the content to use (redacted if available, otherwise original).
    pub fn content(&self) -> &str {
        self.redacted_content
            .as_deref()
            .unwrap_or(&self.original_content)
    }
}

/// The unified security pipeline.
///
/// All content -- prompts, responses, and MCP tool calls -- must flow
/// through this pipeline. It runs registered detectors, aggregates
/// findings, applies redactions, and produces a verdict.
pub struct SecurityPipeline {
    config: PipelineConfig,
    detectors: Vec<Arc<dyn Detector>>,
}

impl SecurityPipeline {
    /// Create a new pipeline with default configuration and all detectors.
    pub fn new() -> Self {
        Self::with_config(PipelineConfig::default())
    }

    /// Create a pipeline with custom configuration.
    pub fn with_config(config: PipelineConfig) -> Self {
        let mut detectors: Vec<Arc<dyn Detector>> = Vec::new();

        if config.enable_injection {
            detectors.push(Arc::new(InjectionDetector::default()));
        }
        if config.enable_pii {
            detectors.push(Arc::new(PiiDetector::default()));
        }
        if config.enable_secrets {
            detectors.push(Arc::new(SecretDetector::default()));
        }
        if config.enable_content_screening {
            detectors.push(Arc::new(ContentScreener::new()));
        }

        Self { config, detectors }
    }

    /// Register an additional custom detector.
    pub fn add_detector(&mut self, detector: Arc<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Screen content through the full pipeline.
    pub fn screen(&self, content: &str, direction: Direction) -> PipelineResult {
        // Size check
        if content.len() > self.config.max_content_size {
            return PipelineResult {
                verdict: Verdict::Blocked,
                findings: vec![Finding {
                    detector: "pipeline".into(),
                    category: "size_limit".into(),
                    description: format!(
                        "Content exceeds maximum size ({} > {} bytes)",
                        content.len(),
                        self.config.max_content_size
                    ),
                    matched_content: String::new(),
                    severity: Severity::High,
                    confidence: 1.0,
                    offset: None,
                    length: Some(content.len()),
                    redaction: None,
                }],
                risk_score: 1.0,
                redacted_content: None,
                original_content: content.to_string(),
                direction,
            };
        }

        // Check if screening is enabled for this direction
        let should_screen = match direction {
            Direction::Input | Direction::McpToolCall => self.config.screen_input,
            Direction::Output | Direction::McpToolResult => self.config.screen_output,
        };

        if !should_screen {
            return PipelineResult {
                verdict: Verdict::Safe,
                findings: Vec::new(),
                risk_score: 0.0,
                redacted_content: None,
                original_content: content.to_string(),
                direction,
            };
        }

        // Run all applicable detectors
        let mut all_findings = Vec::new();
        for detector in &self.detectors {
            if detector.supports_direction(direction) {
                let findings = detector.detect(content, direction);
                all_findings.extend(findings);
            }
        }

        // Calculate risk score
        let risk_score = calculate_risk_score(&all_findings);

        // Apply redaction if configured
        let redacted_content = if self.config.auto_redact
            && all_findings.iter().any(|f| f.redaction.is_some())
        {
            Some(redaction::redact(content, &all_findings))
        } else {
            None
        };

        // Determine verdict
        let verdict = self.determine_verdict(&all_findings, risk_score);

        if self.config.audit_all || !matches!(verdict, Verdict::Safe) {
            tracing::info!(
                direction = %format!("{:?}", direction),
                verdict = %verdict,
                risk_score = risk_score,
                findings = all_findings.len(),
                "Security pipeline screening result"
            );
        }

        PipelineResult {
            verdict,
            findings: all_findings,
            risk_score,
            redacted_content,
            original_content: content.to_string(),
            direction,
        }
    }

    /// Screen input content (convenience method).
    pub fn screen_input(&self, content: &str) -> PipelineResult {
        self.screen(content, Direction::Input)
    }

    /// Screen output content (convenience method).
    pub fn screen_output(&self, content: &str) -> PipelineResult {
        self.screen(content, Direction::Output)
    }

    /// Screen MCP tool call arguments (convenience method).
    pub fn screen_mcp_call(&self, content: &str) -> PipelineResult {
        self.screen(content, Direction::McpToolCall)
    }

    /// Screen MCP tool call results (convenience method).
    pub fn screen_mcp_result(&self, content: &str) -> PipelineResult {
        self.screen(content, Direction::McpToolResult)
    }

    /// Quick boolean safety check.
    pub fn is_safe(&self, content: &str, direction: Direction) -> bool {
        let result = self.screen(content, direction);
        result.is_allowed()
    }

    fn determine_verdict(&self, findings: &[Finding], risk_score: f32) -> Verdict {
        if findings.is_empty() {
            return Verdict::Safe;
        }

        let max_severity = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        // Block on high/critical if configured
        if self.config.block_on_high
            && matches!(max_severity, Severity::Critical | Severity::High)
            && risk_score >= self.config.risk_threshold
        {
            return Verdict::Blocked;
        }

        // Check if redaction was applied
        let has_redactions = findings.iter().any(|f| f.redaction.is_some());
        if has_redactions && self.config.auto_redact {
            return Verdict::Redacted;
        }

        // Warning level
        if risk_score > 0.0 {
            if self.config.allow_warnings {
                return Verdict::Warning;
            }
            return Verdict::Blocked;
        }

        Verdict::Safe
    }
}

impl Default for SecurityPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate aggregate risk score from findings using severity-weighted confidence.
fn calculate_risk_score(findings: &[Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let weighted_sum: f32 = findings
        .iter()
        .map(|f| f.severity.weight() * f.confidence)
        .sum();

    let total_weight: f32 = findings.iter().map(|f| f.severity.weight()).sum();

    if total_weight == 0.0 {
        return 0.0;
    }

    // Weighted average, clamped to [0, 1]
    (weighted_sum / total_weight).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_input() {
        let pipeline = SecurityPipeline::new();
        let result = pipeline.screen_input("What is the weather today?");
        assert_eq!(result.verdict, Verdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_injection_blocked() {
        let pipeline = SecurityPipeline::new();
        let result =
            pipeline.screen_input("'; DROP TABLE users; --");
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_pii_in_output() {
        let pipeline = SecurityPipeline::new();
        let result = pipeline.screen_output("Contact user@example.com for details");
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.category == "email"));
    }

    #[test]
    fn test_redaction_applied() {
        let config = PipelineConfig {
            auto_redact: true,
            block_on_high: false,
            ..Default::default()
        };
        let pipeline = SecurityPipeline::with_config(config);
        let result = pipeline.screen_output("Contact user@example.com for details");
        assert!(result.redacted_content.is_some());
        let redacted = result.redacted_content.unwrap();
        assert!(redacted.contains("u***@***"));
    }

    #[test]
    fn test_max_content_size() {
        let config = PipelineConfig {
            max_content_size: 100,
            ..Default::default()
        };
        let pipeline = SecurityPipeline::with_config(config);
        let large_content = "x".repeat(200);
        let result = pipeline.screen_input(&large_content);
        assert_eq!(result.verdict, Verdict::Blocked);
    }
}
