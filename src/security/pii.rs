//! PII (Personally Identifiable Information) detection (merged from security-mcp).
//!
//! Detects email addresses, phone numbers, SSNs, credit card numbers,
//! IP addresses, and street addresses.

use super::detectors::{Detector, Direction, Finding, Severity};
use super::patterns;

/// Detects personally identifiable information in content.
pub struct PiiDetector {
    /// Enable email detection.
    pub detect_email: bool,
    /// Enable phone number detection.
    pub detect_phone: bool,
    /// Enable SSN detection.
    pub detect_ssn: bool,
    /// Enable credit card detection.
    pub detect_credit_card: bool,
    /// Enable IP address detection.
    pub detect_ip: bool,
    /// Enable street address detection.
    pub detect_address: bool,
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self {
            detect_email: true,
            detect_phone: true,
            detect_ssn: true,
            detect_credit_card: true,
            detect_ip: true,
            detect_address: true,
        }
    }
}

impl Detector for PiiDetector {
    fn name(&self) -> &str {
        "pii"
    }

    fn supports_direction(&self, direction: Direction) -> bool {
        matches!(
            direction,
            Direction::Output | Direction::McpToolResult | Direction::McpToolCall
        )
    }

    fn detect(&self, content: &str, _direction: Direction) -> Vec<Finding> {
        let mut findings = Vec::new();

        if self.detect_email {
            for m in patterns::pii_email().find_iter(content) {
                findings.push(Finding {
                    detector: "pii".into(),
                    category: "email".into(),
                    description: "Email address detected".into(),
                    matched_content: m.as_str().to_string(),
                    severity: Severity::High,
                    confidence: 0.90,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some(redact_email(m.as_str())),
                });
            }
        }

        if self.detect_phone {
            for m in patterns::pii_phone().find_iter(content) {
                findings.push(Finding {
                    detector: "pii".into(),
                    category: "phone".into(),
                    description: "Phone number detected".into(),
                    matched_content: m.as_str().to_string(),
                    severity: Severity::High,
                    confidence: 0.75,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("(***) ***-****".into()),
                });
            }
        }

        if self.detect_ssn {
            for m in patterns::pii_ssn().find_iter(content) {
                // Skip likely false positives: check if adjacent content suggests SSN context
                let start = m.start().saturating_sub(30);
                let end = (m.end() + 30).min(content.len());
                let context = &content[start..end].to_lowercase();
                let has_ssn_context = context.contains("ssn")
                    || context.contains("social security")
                    || context.contains("social-security")
                    || context.contains("tax id")
                    || m.as_str().contains('-');

                if has_ssn_context {
                    findings.push(Finding {
                        detector: "pii".into(),
                        category: "ssn".into(),
                        description: "Social Security Number detected".into(),
                        matched_content: m.as_str().to_string(),
                        severity: Severity::Critical,
                        confidence: if m.as_str().contains('-') { 0.85 } else { 0.60 },
                        offset: Some(m.start()),
                        length: Some(m.len()),
                        redaction: Some("***-**-****".into()),
                    });
                }
            }
        }

        if self.detect_credit_card {
            for m in patterns::pii_credit_card().find_iter(content) {
                let number = m.as_str().replace(['-', ' '], "");
                if luhn_check(&number) {
                    findings.push(Finding {
                        detector: "pii".into(),
                        category: "credit_card".into(),
                        description: "Credit card number detected".into(),
                        matched_content: m.as_str().to_string(),
                        severity: Severity::Critical,
                        confidence: 0.95,
                        offset: Some(m.start()),
                        length: Some(m.len()),
                        redaction: Some("****-****-****-****".into()),
                    });
                }
            }
        }

        if self.detect_ip {
            for m in patterns::pii_ipv4().find_iter(content) {
                // Skip common non-sensitive IPs
                let ip = m.as_str();
                if !is_common_ip(ip) {
                    findings.push(Finding {
                        detector: "pii".into(),
                        category: "ipv4".into(),
                        description: "IPv4 address detected".into(),
                        matched_content: ip.to_string(),
                        severity: Severity::Medium,
                        confidence: 0.70,
                        offset: Some(m.start()),
                        length: Some(m.len()),
                        redaction: Some("[IPv4_REDACTED]".into()),
                    });
                }
            }

            for m in patterns::pii_ipv6().find_iter(content) {
                findings.push(Finding {
                    detector: "pii".into(),
                    category: "ipv6".into(),
                    description: "IPv6 address detected".into(),
                    matched_content: m.as_str().to_string(),
                    severity: Severity::Medium,
                    confidence: 0.70,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[IPv6_REDACTED]".into()),
                });
            }
        }

        if self.detect_address {
            for m in patterns::pii_street_address().find_iter(content) {
                findings.push(Finding {
                    detector: "pii".into(),
                    category: "street_address".into(),
                    description: "Street address detected".into(),
                    matched_content: m.as_str().to_string(),
                    severity: Severity::Medium,
                    confidence: 0.65,
                    offset: Some(m.start()),
                    length: Some(m.len()),
                    redaction: Some("[ADDRESS_REDACTED]".into()),
                });
            }
        }

        findings
    }
}

/// Redact an email address: `user@example.com` -> `u***@***`
fn redact_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        if local.is_empty() {
            return "***@***".into();
        }
        format!("{}***@***", &local[..1])
    } else {
        "[EMAIL_REDACTED]".into()
    }
}

/// Luhn algorithm for credit card validation.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Check if an IP is a common non-sensitive address (loopback, version numbers, etc.).
fn is_common_ip(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("0.")
        || ip == "0.0.0.0"
        || ip.starts_with("255.")
        || ip.starts_with("10.0.0.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let detector = PiiDetector::default();
        let findings = detector.detect("Contact us at user@example.com for info", Direction::Output);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, "email");
        assert_eq!(findings[0].redaction.as_deref(), Some("u***@***"));
    }

    #[test]
    fn test_credit_card_luhn() {
        assert!(luhn_check("4111111111111111")); // Valid Visa test number
        assert!(!luhn_check("4111111111111112")); // Invalid
    }

    #[test]
    fn test_clean_content() {
        let detector = PiiDetector::default();
        let findings = detector.detect("The weather is sunny today.", Direction::Output);
        assert!(findings.is_empty());
    }
}
