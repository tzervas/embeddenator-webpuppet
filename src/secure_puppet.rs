//! Secure WebPuppet wrapper with comprehensive input/output sanitization.
//!
//! This module provides a security-hardened WebPuppet implementation that:
//! - Sanitizes all input before sending to providers
//! - Filters and redacts sensitive data from outputs  
//! - Executes websearch operations in secure containers
//! - Provides comprehensive security monitoring and logging

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn, error};

use crate::config::Config;
use crate::containerized::{ContainerizedConfig, ContainerizedExecutor};
use crate::credentials::CredentialStore;
use crate::error::{Error, Result};
use crate::providers::Provider;
use crate::puppet::{PromptRequest, PromptResponse, WebPuppet, WebPuppetBuilder};
use crate::sanitization::{SanitizationConfig, Sanitizer, SanitizationResult};
use crate::security::{ContentScreener, ScreeningConfig};

/// Security-enhanced WebPuppet with comprehensive sanitization.
pub struct SecureWebPuppet {
    /// Core WebPuppet instance.
    puppet: WebPuppet,
    /// Input/output sanitizer.
    sanitizer: Sanitizer,
    /// Containerized executor for high-risk operations.
    container_executor: Option<ContainerizedExecutor>,
    /// Security configuration.
    security_config: SecurityConfig,
    /// Security event log.
    security_log: Arc<parking_lot::Mutex<Vec<SecurityEvent>>>,
}

/// Comprehensive security configuration.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Sanitization configuration.
    pub sanitization: SanitizationConfig,
    /// Content screening configuration.
    pub screening: ScreeningConfig,
    /// Container execution configuration.
    pub containerized: Option<ContainerizedConfig>,
    /// Enable containerized execution for websearch.
    pub use_containers_for_websearch: bool,
    /// Block high-risk requests entirely.
    pub block_high_risk: bool,
    /// Risk threshold for containerization (0.0-1.0).
    pub containerization_threshold: f32,
    /// Maximum requests per minute.
    pub rate_limit: u32,
    /// Enable comprehensive security logging.
    pub enable_security_logging: bool,
    /// Quarantine suspicious requests.
    pub quarantine_suspicious: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitization: SanitizationConfig::default(),
            screening: ScreeningConfig::default(),
            containerized: Some(ContainerizedConfig::default()),
            use_containers_for_websearch: true,
            block_high_risk: true,
            containerization_threshold: 0.6,
            rate_limit: 30,
            enable_security_logging: true,
            quarantine_suspicious: true,
        }
    }
}

/// Security event for logging and monitoring.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Timestamp of the event.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type.
    pub event_type: SecurityEventType,
    /// Provider involved.
    pub provider: Option<Provider>,
    /// Risk score (0.0-1.0).
    pub risk_score: f32,
    /// Event details.
    pub details: String,
    /// Action taken.
    pub action: SecurityAction,
}

/// Types of security events.
#[derive(Debug, Clone)]
pub enum SecurityEventType {
    /// Input sanitization triggered.
    InputSanitized,
    /// Output sanitization triggered.
    OutputSanitized,
    /// Request blocked due to high risk.
    RequestBlocked,
    /// Request executed in container.
    ContainerExecution,
    /// Sensitive data detected and redacted.
    DataRedacted,
    /// Prompt injection attempt detected.
    PromptInjectionDetected,
    /// Code injection attempt detected.
    CodeInjectionDetected,
    /// Malicious URL detected.
    MaliciousUrlDetected,
    /// System disclosure prevented.
    SystemDisclosurePrevented,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Container security violation.
    ContainerSecurityViolation,
}

/// Actions taken in response to security events.
#[derive(Debug, Clone)]
pub enum SecurityAction {
    /// Request allowed with sanitization.
    Allowed,
    /// Request blocked.
    Blocked,
    /// Request redirected to container.
    Containerized,
    /// Data redacted.
    Redacted,
    /// Request quarantined for review.
    Quarantined,
    /// Rate limited.
    RateLimited,
}

impl SecureWebPuppet {
    /// Create a new secure WebPuppet instance.
    pub async fn new(security_config: SecurityConfig) -> Result<Self> {
        let puppet = WebPuppetBuilder::default()
            .with_screening_config(security_config.screening.clone())
            .build()
            .await?;

        let sanitizer = Sanitizer::with_config(security_config.sanitization.clone())
            .map_err(|e| Error::Security(format!("Failed to create sanitizer: {}", e)))?;

        let container_executor = if let Some(ref container_config) = security_config.containerized {
            let executor = ContainerizedExecutor::new(container_config.clone(), sanitizer.clone())
                .map_err(|e| Error::Config(format!("Failed to create container executor: {}", e)))?;
            Some(executor)
        } else {
            None
        };

        Ok(Self {
            puppet,
            sanitizer,
            container_executor,
            security_config,
            security_log: Arc::new(parking_lot::Mutex::new(Vec::new())),
        })
    }

    /// Send a secure prompt with comprehensive sanitization.
    pub async fn secure_prompt(
        &self,
        provider: Provider,
        request: PromptRequest,
    ) -> Result<SecurePromptResponse> {
        let start_time = chrono::Utc::now();

        // Step 1: Sanitize input
        let input_sanitization = self.sanitize_input(&request).await?;
        
        if input_sanitization.blocked {
            self.log_security_event(SecurityEvent {
                timestamp: start_time,
                event_type: SecurityEventType::RequestBlocked,
                provider: Some(provider),
                risk_score: input_sanitization.risk_score,
                details: format!("Input blocked: {:?}", input_sanitization.issues),
                action: SecurityAction::Blocked,
            });

            return Err(Error::Security(format!(
                "Request blocked due to security issues (risk: {:.2}): {:?}",
                input_sanitization.risk_score, input_sanitization.issues
            )));
        }

        // Step 2: Determine execution method based on risk
        let use_container = self.should_use_container(&input_sanitization, provider);
        
        let response = if use_container {
            self.execute_containerized(provider, &input_sanitization.sanitized_request).await?
        } else {
            self.execute_standard(provider, &input_sanitization.sanitized_request).await?
        };

        // Step 3: Sanitize output
        let output_sanitization = self.sanitize_output(&response).await?;

        if output_sanitization.blocked && self.security_config.block_high_risk {
            self.log_security_event(SecurityEvent {
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::OutputSanitized,
                provider: Some(provider),
                risk_score: output_sanitization.risk_score,
                details: format!("Output blocked: {:?}", output_sanitization.issues),
                action: SecurityAction::Blocked,
            });

            return Err(Error::Security(format!(
                "Response blocked due to security issues: {:?}",
                output_sanitization.issues
            )));
        }

        // Step 4: Create secure response
        let secure_response = SecurePromptResponse {
            response: PromptResponse {
                text: output_sanitization.sanitized.clone(),
                provider: response.provider,
                conversation_id: response.conversation_id,
                timestamp: response.timestamp,
                tokens_used: response.tokens_used,
                metadata: response.metadata,
            },
            input_sanitization,
            output_sanitization,
            execution_method: if use_container { 
                ExecutionMethod::Containerized 
            } else { 
                ExecutionMethod::Standard 
            },
            security_events: self.get_recent_security_events(start_time),
            execution_time: chrono::Utc::now().signed_duration_since(start_time).to_std().unwrap_or(Duration::ZERO),
        };

        Ok(secure_response)
    }

    /// Execute websearch with maximum security (containerized).
    pub async fn secure_websearch(
        &self,
        provider: Provider,
        query: &str,
    ) -> Result<SecurePromptResponse> {
        // Verify provider supports websearch
        if !Provider::search_providers().contains(&provider) {
            return Err(Error::UnsupportedProvider(format!(
                "{} does not support web search",
                provider
            )));
        }

        let request = PromptRequest::new(query);
        
        // Always use containerization for websearch
        let input_sanitization = self.sanitize_input(&request).await?;
        
        if input_sanitization.blocked {
            return Err(Error::Security(format!(
                "Websearch query blocked: {:?}",
                input_sanitization.issues
            )));
        }

        let response = self.execute_containerized(provider, &input_sanitization.sanitized_request).await?;
        let output_sanitization = self.sanitize_output(&response).await?;

        Ok(SecurePromptResponse {
            response: PromptResponse {
                text: output_sanitization.sanitized.clone(),
                provider: response.provider,
                conversation_id: response.conversation_id,
                timestamp: response.timestamp,
                tokens_used: response.tokens_used,
                metadata: response.metadata,
            },
            input_sanitization,
            output_sanitization,
            execution_method: ExecutionMethod::Containerized,
            security_events: self.get_recent_security_events(chrono::Utc::now() - chrono::Duration::minutes(5)),
            execution_time: Duration::from_secs(0), // Will be set by caller
        })
    }

    /// Get security statistics.
    pub fn get_security_stats(&self) -> SecurityStats {
        let events = self.security_log.lock();
        
        let total_events = events.len();
        let blocked_requests = events.iter().filter(|e| matches!(e.action, SecurityAction::Blocked)).count();
        let containerized_requests = events.iter().filter(|e| matches!(e.action, SecurityAction::Containerized)).count();
        let redacted_data = events.iter().filter(|e| matches!(e.action, SecurityAction::Redacted)).count();
        
        let avg_risk_score = if !events.is_empty() {
            events.iter().map(|e| e.risk_score).sum::<f32>() / events.len() as f32
        } else {
            0.0
        };

        SecurityStats {
            total_events,
            blocked_requests,
            containerized_requests,
            redacted_data,
            average_risk_score: avg_risk_score,
            high_risk_events: events.iter().filter(|e| e.risk_score > 0.8).count(),
        }
    }

    /// Clear security event log.
    pub fn clear_security_log(&self) {
        self.security_log.lock().clear();
    }

    // Private helper methods

    async fn sanitize_input(&self, request: &PromptRequest) -> Result<InputSanitizationResult> {
        let sanitization = self.sanitizer.sanitize_input(&request.message)
            .map_err(|e| Error::Security(format!("Input sanitization failed: {}", e)))?;

        // Log security events
        if !sanitization.issues.is_empty() {
            self.log_security_event(SecurityEvent {
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::InputSanitized,
                provider: None,
                risk_score: sanitization.risk_score,
                details: format!("Issues: {:?}", sanitization.issues),
                action: if sanitization.blocked { 
                    SecurityAction::Blocked 
                } else { 
                    SecurityAction::Allowed 
                },
            });
        }

        // Create sanitized request
        let sanitized_request = PromptRequest {
            message: sanitization.sanitized.clone(),
            context: request.context.clone(),
            conversation_id: request.conversation_id.clone(),
            attachments: request.attachments.clone(), // TODO: Sanitize attachments
            metadata: request.metadata.clone(),
        };

        Ok(InputSanitizationResult {
            original_request: request.clone(),
            sanitized_request,
            issues: sanitization.issues,
            risk_score: sanitization.risk_score,
            blocked: sanitization.blocked,
            redacted_patterns: sanitization.redacted_patterns,
        })
    }

    async fn sanitize_output(&self, response: &PromptResponse) -> Result<OutputSanitizationResult> {
        let sanitization = self.sanitizer.sanitize_output(&response.text)
            .map_err(|e| Error::Security(format!("Output sanitization failed: {}", e)))?;

        // Log security events
        if !sanitization.issues.is_empty() {
            self.log_security_event(SecurityEvent {
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::OutputSanitized,
                provider: Some(response.provider),
                risk_score: sanitization.risk_score,
                details: format!("Issues: {:?}", sanitization.issues),
                action: if sanitization.blocked { 
                    SecurityAction::Blocked 
                } else if !sanitization.redacted_patterns.is_empty() {
                    SecurityAction::Redacted 
                } else { 
                    SecurityAction::Allowed 
                },
            });
        }

        Ok(OutputSanitizationResult {
            original_text: response.text.clone(),
            sanitized: sanitization.sanitized,
            issues: sanitization.issues,
            risk_score: sanitization.risk_score,
            blocked: sanitization.blocked,
            redacted_patterns: sanitization.redacted_patterns,
        })
    }

    fn should_use_container(&self, sanitization: &InputSanitizationResult, provider: Provider) -> bool {
        // Always use containers for websearch if configured
        if self.security_config.use_containers_for_websearch && Provider::search_providers().contains(&provider) {
            return true;
        }

        // Use containers for high-risk requests
        if sanitization.risk_score >= self.security_config.containerization_threshold {
            return true;
        }

        // Use containers if specific threats detected
        for issue in &sanitization.issues {
            match issue {
                crate::sanitization::SanitizationIssue::PromptInjection { confidence, .. } => {
                    if *confidence > 0.7 {
                        return true;
                    }
                }
                crate::sanitization::SanitizationIssue::CodeInjection { .. } => return true,
                _ => {}
            }
        }

        false
    }

    async fn execute_standard(&self, provider: Provider, request: &PromptRequest) -> Result<PromptResponse> {
        info!("Executing standard request for provider: {}", provider);
        self.puppet.prompt(provider, request.clone()).await
    }

    async fn execute_containerized(&self, provider: Provider, request: &PromptRequest) -> Result<PromptResponse> {
        info!("Executing containerized request for provider: {}", provider);
        
        let executor = self.container_executor.as_ref()
            .ok_or_else(|| Error::Config("Container executor not configured".into()))?;

        self.log_security_event(SecurityEvent {
            timestamp: chrono::Utc::now(),
            event_type: SecurityEventType::ContainerExecution,
            provider: Some(provider),
            risk_score: 0.0,
            details: format!("Executing {} in container", provider),
            action: SecurityAction::Containerized,
        });

        executor.execute_websearch(provider, request).await
    }

    fn log_security_event(&self, event: SecurityEvent) {
        if self.security_config.enable_security_logging {
            warn!(
                "Security event: {:?} for {:?} (risk: {:.2}, action: {:?})",
                event.event_type, event.provider, event.risk_score, event.action
            );

            self.security_log.lock().push(event);
        }
    }

    fn get_recent_security_events(&self, since: chrono::DateTime<chrono::Utc>) -> Vec<SecurityEvent> {
        self.security_log.lock()
            .iter()
            .filter(|event| event.timestamp >= since)
            .cloned()
            .collect()
    }
}

/// Response from secure prompt execution.
#[derive(Debug, Clone)]
pub struct SecurePromptResponse {
    /// The actual response.
    pub response: PromptResponse,
    /// Input sanitization details.
    pub input_sanitization: InputSanitizationResult,
    /// Output sanitization details.
    pub output_sanitization: OutputSanitizationResult,
    /// How the request was executed.
    pub execution_method: ExecutionMethod,
    /// Security events during this request.
    pub security_events: Vec<SecurityEvent>,
    /// Total execution time.
    pub execution_time: Duration,
}

/// Method used to execute the request.
#[derive(Debug, Clone)]
pub enum ExecutionMethod {
    /// Standard WebPuppet execution.
    Standard,
    /// Containerized execution for security.
    Containerized,
}

/// Result of input sanitization.
#[derive(Debug, Clone)]
pub struct InputSanitizationResult {
    /// Original request.
    pub original_request: PromptRequest,
    /// Sanitized request.
    pub sanitized_request: PromptRequest,
    /// Security issues found.
    pub issues: Vec<crate::sanitization::SanitizationIssue>,
    /// Risk score (0.0-1.0).
    pub risk_score: f32,
    /// Whether request was blocked.
    pub blocked: bool,
    /// Patterns that were redacted.
    pub redacted_patterns: Vec<String>,
}

/// Result of output sanitization.
#[derive(Debug, Clone)]
pub struct OutputSanitizationResult {
    /// Original response text.
    pub original_text: String,
    /// Sanitized text.
    pub sanitized: String,
    /// Security issues found.
    pub issues: Vec<crate::sanitization::SanitizationIssue>,
    /// Risk score (0.0-1.0).
    pub risk_score: f32,
    /// Whether response was blocked.
    pub blocked: bool,
    /// Patterns that were redacted.
    pub redacted_patterns: Vec<String>,
}

/// Security statistics.
#[derive(Debug, Clone)]
pub struct SecurityStats {
    /// Total security events.
    pub total_events: usize,
    /// Number of blocked requests.
    pub blocked_requests: usize,
    /// Number of containerized requests.
    pub containerized_requests: usize,
    /// Number of data redactions.
    pub redacted_data: usize,
    /// Average risk score.
    pub average_risk_score: f32,
    /// High-risk events (>0.8).
    pub high_risk_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.use_containers_for_websearch);
        assert!(config.block_high_risk);
        assert_eq!(config.containerization_threshold, 0.6);
    }

    #[tokio::test]
    async fn test_execution_method_decision() {
        // This would require a full setup, so just test the enum
        let method = ExecutionMethod::Containerized;
        matches!(method, ExecutionMethod::Containerized);
    }

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            event_type: SecurityEventType::InputSanitized,
            provider: Some(Provider::Perplexity),
            risk_score: 0.8,
            details: "Test event".into(),
            action: SecurityAction::Allowed,
        };

        assert_eq!(event.risk_score, 0.8);
        assert!(matches!(event.event_type, SecurityEventType::InputSanitized));
    }
}