//! Permission and guardrails system for webpuppet operations.
//!
//! This module provides fine-grained control over what operations the webpuppet
//! can perform, with secure defaults that block destructive actions.
//!
//! ## Security Model
//!
//! - **Default Deny**: All operations not explicitly allowed are blocked
//! - **Destructive Protection**: Account deletion, password changes, etc. are blocked
//! - **URL Allowlist**: Only navigate to allowed domains
//! - **Action Audit**: All operations are logged for audit
//!
//! ## Example
//!
//! ```rust,ignore
//! use embeddenator_webpuppet::permissions::{PermissionPolicy, Operation};
//!
//! let policy = PermissionPolicy::builder()
//!     .allow_domain("claude.ai")
//!     .allow_domain("x.com")
//!     .allow_operation(Operation::Navigate)
//!     .allow_operation(Operation::SendPrompt)
//!     .deny_operation(Operation::DeleteAccount)
//!     .build();
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Categories of operations that can be controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    // === Navigation ===
    /// Navigate to a URL.
    Navigate,
    /// Open a new tab.
    OpenTab,
    /// Close a tab.
    CloseTab,

    // === Reading ===
    /// Read page content.
    ReadContent,
    /// Take screenshots.
    Screenshot,
    /// Read cookies.
    ReadCookies,
    /// Read local storage.
    ReadStorage,

    // === AI Interaction ===
    /// Send prompts to AI providers.
    SendPrompt,
    /// Read AI responses.
    ReadResponse,
    /// Start new conversations.
    NewConversation,
    /// Continue existing conversations.
    ContinueConversation,
    /// Delete conversations.
    DeleteConversation,

    // === Form Interaction ===
    /// Click elements.
    Click,
    /// Type text.
    TypeText,
    /// Submit forms.
    SubmitForm,
    /// Upload files.
    UploadFile,

    // === Destructive Operations (BLOCKED by default) ===
    /// Delete account.
    DeleteAccount,
    /// Change password.
    ChangePassword,
    /// Modify account settings.
    ModifyAccountSettings,
    /// Revoke API keys or tokens.
    RevokeTokens,
    /// Export/download all data.
    ExportData,
    /// Clear browsing data.
    ClearBrowsingData,
    /// Modify payment methods.
    ModifyPayment,
    /// Cancel subscriptions.
    CancelSubscription,

    // === System Operations ===
    /// Execute JavaScript.
    ExecuteScript,
    /// Access browser extensions.
    AccessExtensions,
    /// Modify browser settings.
    ModifyBrowserSettings,
    /// Access filesystem via browser.
    FileSystemAccess,
    /// Access clipboard.
    ClipboardAccess,
    /// Access camera/microphone.
    MediaAccess,
}

impl Operation {
    /// Check if this operation is destructive.
    pub fn is_destructive(&self) -> bool {
        matches!(
            self,
            Operation::DeleteAccount
                | Operation::ChangePassword
                | Operation::ModifyAccountSettings
                | Operation::RevokeTokens
                | Operation::ExportData
                | Operation::ClearBrowsingData
                | Operation::ModifyPayment
                | Operation::CancelSubscription
                | Operation::ModifyBrowserSettings
                | Operation::FileSystemAccess
        )
    }

    /// Check if this is a read-only operation.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Operation::Navigate
                | Operation::ReadContent
                | Operation::Screenshot
                | Operation::ReadCookies
                | Operation::ReadStorage
                | Operation::ReadResponse
        )
    }

    /// Get the risk level (0-10).
    pub fn risk_level(&self) -> u8 {
        match self {
            // Low risk (0-2)
            Operation::Navigate => 1,
            Operation::ReadContent => 0,
            Operation::Screenshot => 1,
            Operation::ReadResponse => 0,

            // Medium risk (3-5)
            Operation::OpenTab => 2,
            Operation::CloseTab => 2,
            Operation::ReadCookies => 3,
            Operation::ReadStorage => 3,
            Operation::SendPrompt => 3,
            Operation::NewConversation => 2,
            Operation::ContinueConversation => 2,
            Operation::Click => 3,
            Operation::TypeText => 4,
            Operation::SubmitForm => 5,

            // High risk (6-8)
            Operation::UploadFile => 6,
            Operation::DeleteConversation => 6,
            Operation::ExecuteScript => 7,
            Operation::ClipboardAccess => 6,
            Operation::MediaAccess => 6,
            Operation::AccessExtensions => 7,
            Operation::ExportData => 7,

            // Critical risk (9-10)
            Operation::DeleteAccount => 10,
            Operation::ChangePassword => 10,
            Operation::ModifyAccountSettings => 9,
            Operation::RevokeTokens => 10,
            Operation::ClearBrowsingData => 9,
            Operation::ModifyPayment => 10,
            Operation::CancelSubscription => 9,
            Operation::ModifyBrowserSettings => 8,
            Operation::FileSystemAccess => 9,
        }
    }

    /// Get all operations.
    pub fn all() -> Vec<Operation> {
        vec![
            Operation::Navigate,
            Operation::OpenTab,
            Operation::CloseTab,
            Operation::ReadContent,
            Operation::Screenshot,
            Operation::ReadCookies,
            Operation::ReadStorage,
            Operation::SendPrompt,
            Operation::ReadResponse,
            Operation::NewConversation,
            Operation::ContinueConversation,
            Operation::DeleteConversation,
            Operation::Click,
            Operation::TypeText,
            Operation::SubmitForm,
            Operation::UploadFile,
            Operation::DeleteAccount,
            Operation::ChangePassword,
            Operation::ModifyAccountSettings,
            Operation::RevokeTokens,
            Operation::ExportData,
            Operation::ClearBrowsingData,
            Operation::ModifyPayment,
            Operation::CancelSubscription,
            Operation::ExecuteScript,
            Operation::AccessExtensions,
            Operation::ModifyBrowserSettings,
            Operation::FileSystemAccess,
            Operation::ClipboardAccess,
            Operation::MediaAccess,
        ]
    }

    /// Get safe operations (read + basic AI interaction).
    pub fn safe_operations() -> Vec<Operation> {
        vec![
            Operation::Navigate,
            Operation::ReadContent,
            Operation::ReadResponse,
            Operation::SendPrompt,
            Operation::NewConversation,
            Operation::ContinueConversation,
            Operation::Screenshot,
        ]
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Permission decision result.
#[derive(Debug, Clone)]
pub struct PermissionDecision {
    /// Whether the operation is allowed.
    pub allowed: bool,
    /// Reason for the decision.
    pub reason: String,
    /// Operation that was checked.
    pub operation: Operation,
    /// URL context (if applicable).
    pub url: Option<String>,
    /// Risk level of the operation.
    pub risk_level: u8,
}

impl PermissionDecision {
    /// Create an allow decision.
    pub fn allow(operation: Operation, reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            operation,
            url: None,
            risk_level: operation.risk_level(),
        }
    }

    /// Create a deny decision.
    pub fn deny(operation: Operation, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            operation,
            url: None,
            risk_level: operation.risk_level(),
        }
    }

    /// Add URL context.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

/// Permission policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPolicy {
    /// Allowed operations.
    pub allowed_operations: HashSet<Operation>,
    /// Explicitly denied operations (takes precedence).
    pub denied_operations: HashSet<Operation>,
    /// Allowed URL domains.
    pub allowed_domains: HashSet<String>,
    /// Blocked URL patterns (regex).
    pub blocked_url_patterns: Vec<String>,
    /// Maximum risk level allowed (0-10).
    pub max_risk_level: u8,
    /// Require explicit allow for all operations.
    pub default_deny: bool,
    /// Enable audit logging.
    pub audit_enabled: bool,
    /// Blocked URL substrings (fast check).
    pub blocked_url_substrings: Vec<String>,
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        Self::secure()
    }
}

impl PermissionPolicy {
    /// Create a secure default policy.
    ///
    /// This policy:
    /// - Allows only safe AI interaction operations
    /// - Blocks all destructive operations
    /// - Only allows known AI provider domains
    /// - Blocks dangerous URL patterns
    pub fn secure() -> Self {
        let mut allowed_operations = HashSet::new();
        for op in Operation::safe_operations() {
            allowed_operations.insert(op);
        }

        let mut denied_operations = HashSet::new();
        for op in Operation::all() {
            if op.is_destructive() {
                denied_operations.insert(op);
            }
        }

        let mut allowed_domains = HashSet::new();
        // AI providers
        allowed_domains.insert("claude.ai".into());
        allowed_domains.insert("anthropic.com".into());
        allowed_domains.insert("x.com".into());
        allowed_domains.insert("grok.x.ai".into());
        allowed_domains.insert("gemini.google.com".into());
        allowed_domains.insert("bard.google.com".into());
        allowed_domains.insert("chat.openai.com".into());
        allowed_domains.insert("openai.com".into());
        // Dataset sources
        allowed_domains.insert("kaggle.com".into());
        // Auth providers
        allowed_domains.insert("accounts.google.com".into());

        Self {
            allowed_operations,
            denied_operations,
            allowed_domains,
            blocked_url_patterns: vec![
                r".*delete.*account.*".into(),
                r".*close.*account.*".into(),
                r".*deactivate.*".into(),
                r".*/settings/security.*".into(),
                r".*/settings/password.*".into(),
                r".*/billing.*".into(),
                r".*/payment.*".into(),
            ],
            max_risk_level: 5,
            default_deny: true,
            audit_enabled: true,
            blocked_url_substrings: vec![
                "/delete".into(),
                "/deactivate".into(),
                "/close-account".into(),
                "/billing".into(),
                "/payment".into(),
                "/password".into(),
                "/security-settings".into(),
            ],
        }
    }

    /// Create a permissive policy (use with caution).
    pub fn permissive() -> Self {
        let mut allowed_operations = HashSet::new();
        for op in Operation::all() {
            if !op.is_destructive() {
                allowed_operations.insert(op);
            }
        }

        let mut denied_operations = HashSet::new();
        for op in Operation::all() {
            if op.is_destructive() {
                denied_operations.insert(op);
            }
        }

        Self {
            allowed_operations,
            denied_operations,
            allowed_domains: HashSet::new(), // Allow all domains
            blocked_url_patterns: vec![
                r".*delete.*account.*".into(),
                r".*close.*account.*".into(),
            ],
            max_risk_level: 7,
            default_deny: false,
            audit_enabled: true,
            blocked_url_substrings: vec!["/delete".into(), "/deactivate".into()],
        }
    }

    /// Create a read-only policy.
    pub fn read_only() -> Self {
        let mut allowed_operations = HashSet::new();
        for op in Operation::all() {
            if op.is_read_only() {
                allowed_operations.insert(op);
            }
        }

        Self {
            allowed_operations,
            denied_operations: HashSet::new(),
            allowed_domains: HashSet::new(),
            blocked_url_patterns: Vec::new(),
            max_risk_level: 3,
            default_deny: true,
            audit_enabled: true,
            blocked_url_substrings: Vec::new(),
        }
    }

    /// Create a builder for custom policies.
    pub fn builder() -> PermissionPolicyBuilder {
        PermissionPolicyBuilder::new()
    }
}

/// Builder for permission policies.
#[derive(Debug, Default)]
pub struct PermissionPolicyBuilder {
    policy: PermissionPolicy,
}

impl PermissionPolicyBuilder {
    /// Create a new builder with secure defaults.
    pub fn new() -> Self {
        Self {
            policy: PermissionPolicy::secure(),
        }
    }

    /// Start from a permissive base.
    pub fn permissive() -> Self {
        Self {
            policy: PermissionPolicy::permissive(),
        }
    }

    /// Allow an operation.
    pub fn allow_operation(mut self, op: Operation) -> Self {
        self.policy.allowed_operations.insert(op);
        self.policy.denied_operations.remove(&op);
        self
    }

    /// Deny an operation (takes precedence over allow).
    pub fn deny_operation(mut self, op: Operation) -> Self {
        self.policy.denied_operations.insert(op);
        self
    }

    /// Allow a domain.
    pub fn allow_domain(mut self, domain: impl Into<String>) -> Self {
        self.policy.allowed_domains.insert(domain.into());
        self
    }

    /// Block a URL pattern (regex).
    pub fn block_url_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.policy.blocked_url_patterns.push(pattern.into());
        self
    }

    /// Set maximum risk level (0-10).
    pub fn max_risk_level(mut self, level: u8) -> Self {
        self.policy.max_risk_level = level.min(10);
        self
    }

    /// Enable/disable default deny.
    pub fn default_deny(mut self, deny: bool) -> Self {
        self.policy.default_deny = deny;
        self
    }

    /// Enable/disable audit logging.
    pub fn audit_enabled(mut self, enabled: bool) -> Self {
        self.policy.audit_enabled = enabled;
        self
    }

    /// Build the policy.
    pub fn build(self) -> PermissionPolicy {
        self.policy
    }
}

/// Permission guard that enforces policies.
pub struct PermissionGuard {
    policy: PermissionPolicy,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    url_patterns: Vec<regex::Regex>,
}

impl PermissionGuard {
    /// Create a new permission guard with the given policy.
    pub fn new(policy: PermissionPolicy) -> Self {
        let url_patterns = policy
            .blocked_url_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        Self {
            policy,
            audit_log: Arc::new(RwLock::new(Vec::new())),
            url_patterns,
        }
    }

    /// Create a guard with secure defaults.
    pub fn secure() -> Self {
        Self::new(PermissionPolicy::secure())
    }

    /// Check if an operation is allowed.
    pub fn check(&self, operation: Operation) -> PermissionDecision {
        let decision = self.check_operation(operation, None);
        self.audit(&decision);
        decision
    }

    /// Check if an operation is allowed for a specific URL.
    pub fn check_with_url(&self, operation: Operation, url: &str) -> PermissionDecision {
        let decision = self.check_operation(operation, Some(url));
        self.audit(&decision);
        decision
    }

    /// Check and return Result for convenient error handling.
    pub fn require(&self, operation: Operation) -> Result<()> {
        let decision = self.check(operation);
        if decision.allowed {
            Ok(())
        } else {
            Err(Error::PermissionDenied {
                operation: operation.to_string(),
                reason: decision.reason,
            })
        }
    }

    /// Check with URL and return Result.
    pub fn require_with_url(&self, operation: Operation, url: &str) -> Result<()> {
        let decision = self.check_with_url(operation, url);
        if decision.allowed {
            Ok(())
        } else {
            Err(Error::PermissionDenied {
                operation: operation.to_string(),
                reason: decision.reason,
            })
        }
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().clone()
    }

    /// Clear the audit log.
    pub fn clear_audit_log(&self) {
        self.audit_log.write().clear();
    }

    /// Get the current policy.
    pub fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    fn check_operation(&self, operation: Operation, url: Option<&str>) -> PermissionDecision {
        // 1. Check explicit deny (highest priority)
        if self.policy.denied_operations.contains(&operation) {
            return PermissionDecision::deny(
                operation,
                "Operation explicitly denied by policy",
            );
        }

        // 2. Check risk level
        if operation.risk_level() > self.policy.max_risk_level {
            return PermissionDecision::deny(
                operation,
                format!(
                    "Operation risk level {} exceeds maximum allowed {}",
                    operation.risk_level(),
                    self.policy.max_risk_level
                ),
            );
        }

        // 3. Check URL if provided
        if let Some(url) = url {
            // Enforce HTTPS-only navigation/requests in secure mode.
            if url.trim_start().to_lowercase().starts_with("http://") {
                return PermissionDecision::deny(operation, "Insecure URL scheme http:// is not allowed")
                    .with_url(url);
            }

            // Check blocked URL substrings (fast)
            for blocked in &self.policy.blocked_url_substrings {
                if url.to_lowercase().contains(&blocked.to_lowercase()) {
                    return PermissionDecision::deny(operation, format!("URL contains blocked pattern: {}", blocked))
                        .with_url(url);
                }
            }

            // Check blocked URL patterns (regex)
            for pattern in &self.url_patterns {
                if pattern.is_match(url) {
                    return PermissionDecision::deny(operation, "URL matches blocked pattern")
                        .with_url(url);
                }
            }

            // Check allowed domains (if not empty)
            if !self.policy.allowed_domains.is_empty() {
                let domain = extract_domain(url);
                let is_allowed = self.policy.allowed_domains.iter().any(|d| {
                    domain == *d || domain.ends_with(&format!(".{}", d))
                });

                if !is_allowed {
                    return PermissionDecision::deny(
                        operation,
                        format!("Domain '{}' not in allowlist", domain),
                    )
                    .with_url(url);
                }
            }
        }

        // 4. Check explicit allow
        if self.policy.allowed_operations.contains(&operation) {
            let mut decision = PermissionDecision::allow(operation, "Operation allowed by policy");
            if let Some(url) = url {
                decision = decision.with_url(url);
            }
            return decision;
        }

        // 5. Default deny check
        if self.policy.default_deny {
            return PermissionDecision::deny(
                operation,
                "Operation not in allowlist (default deny)",
            );
        }

        // 6. Allow by default (permissive mode)
        let mut decision = PermissionDecision::allow(operation, "Operation allowed (permissive mode)");
        if let Some(url) = url {
            decision = decision.with_url(url);
        }
        decision
    }

    fn audit(&self, decision: &PermissionDecision) {
        if !self.policy.audit_enabled {
            return;
        }

        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            operation: decision.operation,
            allowed: decision.allowed,
            reason: decision.reason.clone(),
            url: decision.url.clone(),
            risk_level: decision.risk_level,
        };

        self.audit_log.write().push(entry);

        // Log to tracing
        if decision.allowed {
            tracing::debug!(
                operation = %decision.operation,
                url = ?decision.url,
                "Permission granted"
            );
        } else {
            tracing::warn!(
                operation = %decision.operation,
                url = ?decision.url,
                reason = %decision.reason,
                "Permission denied"
            );
        }
    }
}

impl Default for PermissionGuard {
    fn default() -> Self {
        Self::secure()
    }
}

/// Audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the check occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Operation that was checked.
    pub operation: Operation,
    /// Whether it was allowed.
    pub allowed: bool,
    /// Reason for decision.
    pub reason: String,
    /// URL context.
    pub url: Option<String>,
    /// Risk level.
    pub risk_level: u8,
}

/// Extract domain from URL.
fn extract_domain(url_str: &str) -> String {
    use url::Url;
    if let Ok(url) = Url::parse(url_str) {
        if let Some(host) = url.host_str() {
            return host.to_string();
        }
    }
    
    // Fallback for relative or malformed URLs
    url_str.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_policy_blocks_destructive() {
        let guard = PermissionGuard::secure();

        // Should be blocked
        assert!(!guard.check(Operation::DeleteAccount).allowed);
        assert!(!guard.check(Operation::ChangePassword).allowed);
        assert!(!guard.check(Operation::ModifyPayment).allowed);

        // Should be allowed
        assert!(guard.check(Operation::SendPrompt).allowed);
        assert!(guard.check(Operation::ReadResponse).allowed);
        assert!(guard.check(Operation::Navigate).allowed);
    }

    #[test]
    fn test_url_domain_filtering() {
        let guard = PermissionGuard::secure();

        // Allowed domain
        assert!(guard
            .check_with_url(Operation::Navigate, "https://claude.ai/chat")
            .allowed);

        // Blocked domain
        assert!(!guard
            .check_with_url(Operation::Navigate, "https://evil.com/phishing")
            .allowed);
    }

    #[test]
    fn test_https_only_policy() {
        let guard = PermissionGuard::secure();

        assert!(!guard
            .check_with_url(Operation::Navigate, "http://claude.ai/chat")
            .allowed);
        assert!(guard
            .check_with_url(Operation::Navigate, "https://claude.ai/chat")
            .allowed);
    }

    #[test]
    fn test_blocked_url_patterns() {
        let guard = PermissionGuard::secure();

        // Should be blocked
        assert!(!guard
            .check_with_url(Operation::Navigate, "https://claude.ai/settings/delete")
            .allowed);
        assert!(!guard
            .check_with_url(Operation::Navigate, "https://x.com/billing")
            .allowed);
    }

    #[test]
    fn test_risk_levels() {
        assert_eq!(Operation::ReadContent.risk_level(), 0);
        assert_eq!(Operation::DeleteAccount.risk_level(), 10);
        assert!(Operation::DeleteAccount.is_destructive());
        assert!(!Operation::ReadContent.is_destructive());
    }

    #[test]
    fn test_builder() {
        let policy = PermissionPolicy::builder()
            .allow_operation(Operation::ExecuteScript)
            .allow_domain("custom.example.com")
            .max_risk_level(7)
            .build();

        assert!(policy.allowed_operations.contains(&Operation::ExecuteScript));
        assert!(policy.allowed_domains.contains("custom.example.com"));
        assert_eq!(policy.max_risk_level, 7);
    }
}
