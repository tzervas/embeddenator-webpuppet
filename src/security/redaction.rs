//! Content redaction engine.
//!
//! Applies redaction masks to content based on security findings,
//! replacing sensitive data with safe placeholders.

use super::detectors::Finding;

/// Applies redactions to content based on findings.
///
/// Processes findings in reverse offset order to maintain correct positions
/// during string mutation. Falls back to simple string replacement when
/// offsets are not available.
pub fn redact(content: &str, findings: &[Finding]) -> String {
    // Collect findings that have redaction suggestions and valid offsets
    let mut offset_redactions: Vec<(usize, usize, &str)> = Vec::new();
    let mut fallback_redactions: Vec<(&str, &str)> = Vec::new();

    for finding in findings {
        if let Some(ref redaction) = finding.redaction {
            if let (Some(offset), Some(length)) = (finding.offset, finding.length) {
                offset_redactions.push((offset, length, redaction));
            } else {
                // Fall back to string replacement
                fallback_redactions.push((&finding.matched_content, redaction));
            }
        }
    }

    let mut result = content.to_string();

    // Apply offset-based redactions in reverse order (to preserve positions)
    offset_redactions.sort_by(|a, b| b.0.cmp(&a.0));
    for (offset, length, redaction) in &offset_redactions {
        let end = (*offset + *length).min(result.len());
        if *offset < result.len() {
            result.replace_range(*offset..end, redaction);
        }
    }

    // Apply fallback string replacements for findings without offsets
    for (original, redaction) in &fallback_redactions {
        if !original.is_empty() && !original.starts_with('[') && !original.contains("...") {
            result = result.replace(*original, redaction);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::detectors::{Finding, Severity};

    #[test]
    fn test_offset_based_redaction() {
        let content = "My email is user@example.com and my SSN is 123-45-6789";
        let findings = vec![
            Finding {
                detector: "pii".into(),
                category: "email".into(),
                description: "Email".into(),
                matched_content: "user@example.com".into(),
                severity: Severity::High,
                confidence: 0.9,
                offset: Some(12),
                length: Some(16),
                redaction: Some("u***@***".into()),
            },
            Finding {
                detector: "pii".into(),
                category: "ssn".into(),
                description: "SSN".into(),
                matched_content: "123-45-6789".into(),
                severity: Severity::Critical,
                confidence: 0.9,
                offset: Some(43),
                length: Some(11),
                redaction: Some("***-**-****".into()),
            },
        ];

        let result = redact(content, &findings);
        assert!(result.contains("u***@***"));
        assert!(result.contains("***-**-****"));
        assert!(!result.contains("user@example.com"));
        assert!(!result.contains("123-45-6789"));
    }

    #[test]
    fn test_no_redactions() {
        let content = "This is clean content.";
        let result = redact(content, &[]);
        assert_eq!(result, content);
    }
}
