//! Secrets detection (merged from security-mcp).
//!
//! Detects AWS keys, API keys, GitHub tokens, bearer/JWT tokens,
//! private keys, passwords in code, database connection strings,
//! Slack tokens, and high-entropy strings.

use super::detectors::{Detector, Direction, Finding, Severity};
use super::patterns;

/// Detects secrets and credentials in content.
pub struct SecretDetector {
    /// Enable AWS key detection.
    pub detect_aws: bool,
    /// Enable generic API key detection.
    pub detect_api_keys: bool,
    /// Enable GitHub token detection.
    pub detect_github: bool,
    /// Enable bearer/JWT token detection.
    pub detect_bearer: bool,
    /// Enable private key detection.
    pub detect_private_keys: bool,
    /// Enable password-in-code detection.
    pub detect_passwords: bool,
    /// Enable database URL detection.
    pub detect_database_urls: bool,
    /// Enable Slack token detection.
    pub detect_slack: bool,
    /// Enable high-entropy string detection.
    pub detect_high_entropy: bool,
    /// Minimum entropy threshold for flagging (bits per character).
    pub entropy_threshold: f64,
    /// Minimum string length for entropy analysis.
    pub entropy_min_length: usize,
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self {
            detect_aws: true,
            detect_api_keys: true,
            detect_github: true,
            detect_bearer: true,
            detect_private_keys: true,
            detect_passwords: true,
            detect_database_urls: true,
            detect_slack: true,
            detect_high_entropy: true,
            entropy_threshold: 4.5,
            entropy_min_length: 20,
        }
    }
}

impl Detector for SecretDetector {
    fn name(&self) -> &str {
        "secrets"
    }

    fn supports_direction(&self, direction: Direction) -> bool {
        matches!(
            direction,
            Direction::Output | Direction::McpToolResult | Direction::McpToolCall
        )
    }

    fn detect(&self, content: &str, _direction: Direction) -> Vec<Finding> {
        let mut findings = Vec::new();

        if self.detect_aws {
            for m in patterns::secret_aws_access_key().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "aws_access_key".into(),
                    description: "AWS Access Key ID detected".into(),
                    matched_content: m.as_str().to_string(),
                    severity: Severity::Critical,
                    confidence: 0.95,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[AWS_KEY_REDACTED]".into()),
                });
            }

            for m in patterns::secret_aws_secret_key().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "aws_secret_key".into(),
                    description: "AWS Secret Access Key detected".into(),
                    matched_content: "[REDACTED]".into(),
                    severity: Severity::Critical,
                    confidence: 0.95,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[AWS_SECRET_REDACTED]".into()),
                });
            }
        }

        if self.detect_api_keys {
            for m in patterns::secret_api_key().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "api_key".into(),
                    description: "API key or token detected".into(),
                    matched_content: "[REDACTED]".into(),
                    severity: Severity::High,
                    confidence: 0.80,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[API_KEY_REDACTED]".into()),
                });
            }
        }

        if self.detect_github {
            for m in patterns::secret_github_token().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "github_token".into(),
                    description: "GitHub token detected".into(),
                    matched_content: format!("{}...", &m.as_str()[..8.min(m.len())]),
                    severity: Severity::Critical,
                    confidence: 0.95,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[GITHUB_TOKEN_REDACTED]".into()),
                });
            }
        }

        if self.detect_bearer {
            for m in patterns::secret_bearer_token().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "bearer_token".into(),
                    description: "Bearer/JWT token detected".into(),
                    matched_content: "[REDACTED]".into(),
                    severity: Severity::High,
                    confidence: 0.85,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[BEARER_TOKEN_REDACTED]".into()),
                });
            }
        }

        if self.detect_private_keys {
            for m in patterns::secret_private_key().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "private_key".into(),
                    description: "Private key detected".into(),
                    matched_content: "-----BEGIN PRIVATE KEY-----".into(),
                    severity: Severity::Critical,
                    confidence: 0.99,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[PRIVATE_KEY_REDACTED]".into()),
                });
            }
        }

        if self.detect_passwords {
            for m in patterns::secret_password().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "password".into(),
                    description: "Password in code/config detected".into(),
                    matched_content: "[REDACTED]".into(),
                    severity: Severity::Critical,
                    confidence: 0.80,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[PASSWORD_REDACTED]".into()),
                });
            }
        }

        if self.detect_database_urls {
            for m in patterns::secret_database_url().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "database_url".into(),
                    description: "Database connection string detected".into(),
                    matched_content: "[REDACTED]".into(),
                    severity: Severity::Critical,
                    confidence: 0.90,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[DATABASE_URL_REDACTED]".into()),
                });
            }
        }

        if self.detect_slack {
            for m in patterns::secret_slack_token().find_iter(content) {
                findings.push(Finding {
                    detector: "secrets".into(),
                    category: "slack_token".into(),
                    description: "Slack token detected".into(),
                    matched_content: format!("{}...", &m.as_str()[..8.min(m.len())]),
                    severity: Severity::High,
                    confidence: 0.90,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[SLACK_TOKEN_REDACTED]".into()),
                });
            }
        }

        if self.detect_high_entropy {
            findings.extend(self.detect_entropy(content));
        }

        findings
    }
}

impl SecretDetector {
    /// Detect high-entropy strings that may be unrecognized secrets.
    fn detect_entropy(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Split by whitespace and check each token
        for word in content.split_whitespace() {
            if word.len() >= self.entropy_min_length && is_secret_like(word) {
                let entropy = shannon_entropy(word);
                if entropy > self.entropy_threshold {
                    findings.push(Finding {
                        detector: "secrets".into(),
                        category: "high_entropy".into(),
                        description: format!(
                            "High-entropy string detected (entropy: {:.2} bits/char)",
                            entropy
                        ),
                        matched_content: format!(
                            "{}...{}",
                            &word[..4.min(word.len())],
                            &word[word.len().saturating_sub(4)..]
                        ),
                        severity: Severity::Medium,
                        confidence: ((entropy - self.entropy_threshold) / 2.0).min(0.8) as f32,
                        offset: None,
                        length: Some(word.len()),
                        redaction: Some("[HIGH_ENTROPY_REDACTED]".into()),
                    });
                }
            }
        }

        findings
    }
}

/// Calculate Shannon entropy of a string (bits per character).
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check if a string looks like it could be a secret (mix of character classes).
fn is_secret_like(s: &str) -> bool {
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let mostly_alnum = s.chars().filter(|c| c.is_ascii_alphanumeric()).count() as f64
        / s.len() as f64
        > 0.7;

    // Must have at least 2 character classes and be mostly alphanumeric
    let classes = has_upper as u8 + has_lower as u8 + has_digit as u8;
    classes >= 2 && mostly_alnum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let detector = SecretDetector::default();
        let findings = detector.detect("My key is AKIAIOSFODNN7EXAMPLE", Direction::Output);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "aws_access_key"));
    }

    #[test]
    fn test_github_token_detection() {
        let detector = SecretDetector::default();
        let findings = detector.detect(
            "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
            Direction::Output,
        );
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "github_token"));
    }

    #[test]
    fn test_clean_content() {
        let detector = SecretDetector::default();
        let findings = detector.detect("The weather is sunny today.", Direction::Output);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (all same char)
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        // High entropy (random-looking)
        assert!(shannon_entropy("aB3dE5fG7hJ9kL1mN") > 3.5);
    }
}
