//! Compiled regex patterns for all security detectors.
//!
//! Uses `std::sync::OnceLock` for lazy one-time initialization. All patterns
//! from both the original webpuppet-rs ContentScreener and security-mcp
//! are consolidated here.

use regex::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Injection patterns (input screening)
// ---------------------------------------------------------------------------

/// SQL injection patterns.
pub fn sql_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?i)(?:union\s+(?:all\s+)?select)",
            r"(?i)(?:'\s*or\s+'[^']*'\s*=\s*')",
            r"(?i)(?:;\s*drop\s+table)",
            r"(?i)(?:'\s*;\s*--)",
            r"(?i)(?:exec(?:ute)?\s*\()",
            r"(?i)(?:insert\s+into\s+.*values)",
            r"(?i)(?:select\s+.*from\s+.*where)",
            r"(?i)(?:update\s+.*set\s+.*=)",
            r"(?i)(?:delete\s+from)",
            r"(?i)(?:1\s*=\s*1|1\s*=\s*'1')",
        ])
    })
}

/// Command injection patterns.
pub fn command_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?:;\s*(?:cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat)\b)",
            r"(?:\|\s*(?:cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat)\b)",
            r"(?:`[^`]*`)",
            r"(?:\$\([^)]+\))",
            r"(?:\$\{[^}]+\})",
            r"(?:&&\s*(?:cat|ls|rm|wget|curl|bash|sh)\b)",
            r"(?:\|\|\s*(?:cat|ls|rm|wget|curl|bash|sh)\b)",
            r"(?:>\s*/(?:etc|tmp|var)/)",
        ])
    })
}

/// Path traversal patterns.
pub fn path_traversal() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?:\.\./){2,}",
            r"(?:%2e%2e[/\\%]){2,}",
            r"(?:%252e%252e[/\\%]){2,}",
            r"(?:\.\.\\){2,}",
            r"(?:/etc/(?:passwd|shadow|hosts))",
            r"(?:c:\\windows\\)",
        ])
    })
}

/// XSS patterns.
pub fn xss() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?i)(?:<script[^>]*>)",
            r"(?i)(?:javascript\s*:)",
            r"(?i)(?:on(?:load|error|click|mouseover|focus|blur|submit|change|input)\s*=)",
            r"(?i)(?:<iframe[^>]*>)",
            r"(?i)(?:<embed[^>]*>)",
            r"(?i)(?:<object[^>]*>)",
            r"(?i)(?:expression\s*\()",
            r#"(?i)(?:url\s*\(\s*['"]?\s*javascript)"#,
        ])
    })
}

/// LDAP injection patterns.
pub fn ldap_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?:\*\)\(&|\)\(\||\)\(!))",
            r"(?:\x00)",
            r"(?:\*\)\([\w]+=\*\))",
        ])
    })
}

/// XXE injection patterns.
pub fn xxe_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?i)(?:<!DOCTYPE[^>]*\[)",
            r#"(?i)(?:<!ENTITY[^>]*SYSTEM\s*")"#,
            r"(?i)(?:<!ENTITY[^>]*%)",
            r#"(?i)(?:SYSTEM\s*"file://)"#,
        ])
    })
}

/// Template injection (SSTI) patterns.
pub fn template_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?:\{\{.*\}\})",
            r"(?:\{%.*%\})",
            r"(?:\$\{[^}]+\})",
            r"(?:<%[^%]*%>)",
            r"(?:#\{[^}]+\})",
        ])
    })
}

/// Prompt injection patterns (shared between input and output screening).
pub fn prompt_injection() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        compile_all(&[
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
            r"(?i)disregard\s+(all\s+)?(previous|prior|above)",
            r"(?i)new\s+(system\s+)?instructions?:",
            r"(?i)you\s+are\s+now\s+(a|an|the)",
            r"(?i)act\s+as\s+(if\s+)?(a|an|the)",
            r"(?i)\[system\]|\[assistant\]|\[user\]",
            r"(?i)<<\s*sys(tem)?\s*>>",
            r"(?i)```\s*(system|prompt|instruction)",
            r#"(?i)(end|close|exit)\s*(of\s*)?(prompt|context|message|conversation)"#,
            r"(?i)(print|output|reveal|show|display)\s+(the\s+)?(system\s+)?(prompt|instructions?|context)",
            r"(?i)do\s+anything\s+now|dan\s+mode|developer\s+mode|unlocked\s+mode",
            r"(?i)hidden\s+instruction|secret\s+command|covert\s+directive",
            r"(?i)ignore\s+all\s+previous|disregard\s+all",
            r"(?i)pretend\s+you\s+are",
            r"(?i)jailbreak",
            r"(?i)system:\s*you\s+are",
        ])
    })
}

/// Control character patterns (non-printable bytes).
pub fn control_characters() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]").unwrap())
}

// ---------------------------------------------------------------------------
// PII patterns (output screening)
// ---------------------------------------------------------------------------

/// Email address pattern.
pub fn pii_email() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
    })
}

/// US phone number patterns.
pub fn pii_phone() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}").unwrap()
    })
}

/// US Social Security Number pattern.
pub fn pii_ssn() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b").unwrap())
}

/// Credit card number patterns (Visa, MC, Amex, Discover).
pub fn pii_credit_card() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap()
    })
}

/// IPv4 address pattern.
pub fn pii_ipv4() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
            .unwrap()
    })
}

/// IPv6 address pattern.
pub fn pii_ipv6() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b").unwrap()
    })
}

/// US street address pattern.
pub fn pii_street_address() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)\b",
        )
        .unwrap()
    })
}

// ---------------------------------------------------------------------------
// Secrets patterns (output screening)
// ---------------------------------------------------------------------------

/// AWS Access Key ID pattern.
pub fn secret_aws_access_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap())
}

/// AWS Secret Access Key pattern.
pub fn secret_aws_secret_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r#"(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}"#).unwrap())
}

/// Generic API key/token pattern.
pub fn secret_api_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}"#).unwrap()
    })
}

/// GitHub token patterns (ghp_, gho_, ghu_, ghs_, ghr_).
pub fn secret_github_token() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b").unwrap())
}

/// Bearer/JWT token pattern.
pub fn secret_bearer_token() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap()
    })
}

/// Private key header pattern.
pub fn secret_private_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap()
    })
}

/// Password in code/config pattern.
pub fn secret_password() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]\S+"#).unwrap()
    })
}

/// Database connection string patterns.
pub fn secret_database_url() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)(?:mongodb|postgres|mysql|redis)://[^\s'"]+"#).unwrap()
    })
}

/// Slack token patterns.
pub fn secret_slack_token() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9\-]+\b").unwrap())
}

// ---------------------------------------------------------------------------
// Base64/encoded payload patterns (shared)
// ---------------------------------------------------------------------------

/// Substantial base64-encoded blocks.
pub fn encoded_base64() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
            .unwrap()
    })
}

/// Long hex-encoded strings.
pub fn encoded_hex() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?:0x)?[0-9a-fA-F]{32,}").unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compile_all(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("Failed to compile security pattern '{}': {}", p, e);
                None
            }
        })
        .collect()
}
