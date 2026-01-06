//! Input and output sanitization for web search and AI interactions.
//!
//! This module provides comprehensive sanitization to prevent:
//! - Prompt injection attacks
//! - Code injection attempts  
//! - PII and secrets leakage
//! - Proprietary information exposure
//! - Malicious payloads and encoded attacks
//!
//! The sanitization works at multiple levels:
//! - Input validation and cleaning before sending to providers
//! - Output filtering and redaction after receiving responses
//! - Containerized execution for additional isolation

use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

/// Result of input/output sanitization.
#[derive(Debug, Clone)]
pub struct SanitizationResult {
    /// The sanitized content.
    pub sanitized: String,
    /// Original content before sanitization.
    pub original: String,
    /// Issues found and remediated.
    pub issues: Vec<SanitizationIssue>,
    /// Risk score (0.0 = clean, 1.0 = highly dangerous).
    pub risk_score: f32,
    /// Whether the content was blocked (too dangerous).
    pub blocked: bool,
    /// Redacted sensitive data patterns.
    pub redacted_patterns: Vec<String>,
}

/// Types of sanitization issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizationIssue {
    /// Prompt injection attempt detected.
    PromptInjection {
        pattern: String,
        confidence: f32,
        location: String,
    },
    /// Code injection attempt.
    CodeInjection {
        language: String,
        payload: String,
        severity: f32,
    },
    /// Sensitive data detected.
    SensitiveData {
        data_type: SensitiveDataType,
        pattern: String,
        redacted: bool,
    },
    /// Malicious URL or domain.
    MaliciousUrl {
        url: String,
        threat_type: String,
    },
    /// Encoded payload (base64, hex, etc.).
    EncodedPayload {
        encoding: String,
        decoded_snippet: String,
    },
    /// File path or system information disclosure.
    SystemDisclosure {
        disclosure_type: String,
        pattern: String,
    },
    /// Proprietary information patterns.
    ProprietaryInfo {
        info_type: String,
        confidence: f32,
    },
}

/// Types of sensitive data we detect and redact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensitiveDataType {
    /// Email addresses.
    Email,
    /// Phone numbers.
    PhoneNumber,
    /// Social Security Numbers.
    SSN,
    /// Credit card numbers.
    CreditCard,
    /// API keys and tokens.
    ApiKey,
    /// IP addresses.
    IpAddress,
    /// Database connection strings.
    DatabaseUrl,
    /// File paths.
    FilePath,
    /// Private keys.
    PrivateKey,
    /// Passwords.
    Password,
    /// Custom proprietary patterns.
    Custom(String),
}

/// Configuration for sanitization.
#[derive(Debug, Clone)]
pub struct SanitizationConfig {
    /// Block content with risk score above this threshold.
    pub block_threshold: f32,
    /// Redact sensitive data instead of blocking.
    pub redact_sensitive: bool,
    /// Maximum allowed input length.
    pub max_input_length: usize,
    /// Maximum allowed output length.
    pub max_output_length: usize,
    /// Custom sensitive data patterns.
    pub custom_patterns: HashMap<String, String>,
    /// Allowed domains for URLs.
    pub allowed_domains: HashSet<String>,
    /// Blocked domains for URLs.  
    pub blocked_domains: HashSet<String>,
    /// Enable deep content analysis.
    pub deep_analysis: bool,
    /// Proprietary keywords to detect.
    pub proprietary_keywords: HashSet<String>,
    /// Container execution settings.
    pub container_config: ContainerConfig,
}

/// Configuration for containerized execution.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Docker image to use.
    pub image: String,
    /// CPU limit.
    pub cpu_limit: String,
    /// Memory limit.
    pub memory_limit: String,
    /// Network mode (none for isolation).
    pub network_mode: String,
    /// Execution timeout.
    pub timeout_seconds: u32,
    /// Temporary directory for file exchanges.
    pub temp_dir: String,
}

impl Default for SanitizationConfig {
    fn default() -> Self {
        let mut proprietary_keywords = HashSet::new();
        proprietary_keywords.insert("confidential".into());
        proprietary_keywords.insert("internal".into());
        proprietary_keywords.insert("proprietary".into());
        proprietary_keywords.insert("trade secret".into());
        proprietary_keywords.insert("do not distribute".into());
        proprietary_keywords.insert("nda".into());
        proprietary_keywords.insert("non-disclosure".into());

        let mut allowed_domains = HashSet::new();
        allowed_domains.insert("wikipedia.org".into());
        allowed_domains.insert("github.com".into());
        allowed_domains.insert("stackoverflow.com".into());
        allowed_domains.insert("rust-lang.org".into());
        allowed_domains.insert("docs.rs".into());

        Self {
            block_threshold: 0.8,
            redact_sensitive: true,
            max_input_length: 100_000,  // 100KB
            max_output_length: 1_000_000, // 1MB
            custom_patterns: HashMap::new(),
            allowed_domains,
            blocked_domains: HashSet::new(),
            deep_analysis: true,
            proprietary_keywords,
            container_config: ContainerConfig::default(),
        }
    }
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: "embeddenator-sanitization:latest".into(),
            cpu_limit: "1.0".into(),
            memory_limit: "512m".into(),
            network_mode: "none".into(),
            timeout_seconds: 30,
            temp_dir: "/tmp/webpuppet-sanitization".into(),
        }
    }
}

/// Comprehensive input and output sanitizer.
#[derive(Debug, Clone)]
pub struct Sanitizer {
    config: SanitizationConfig,
    /// Compiled regex patterns for efficiency.
    patterns: CompiledPatterns,
}

/// Pre-compiled regex patterns for performance.
#[derive(Debug, Clone)]
struct CompiledPatterns {
    // Prompt injection patterns
    prompt_injection: Vec<(Regex, f32, String)>,
    
    // Code injection patterns
    code_injection: Vec<(Regex, String, f32)>,
    
    // Sensitive data patterns  
    email: Regex,
    phone: Regex,
    ssn: Regex,
    credit_card: Regex,
    api_key: Regex,
    ip_address: Regex,
    database_url: Regex,
    file_path: Regex,
    private_key: Regex,
    password: Regex,
    
    // URL patterns
    url: Regex,
    
    // Encoded payload patterns
    base64: Regex,
    hex: Regex,
    unicode_escape: Regex,
    
    // System disclosure patterns
    system_path: Regex,
    environment_var: Regex,
}

impl Sanitizer {
    /// Create a new sanitizer with default configuration.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_config(SanitizationConfig::default())
    }

    /// Create a sanitizer with custom configuration.
    pub fn with_config(config: SanitizationConfig) -> anyhow::Result<Self> {
        let patterns = CompiledPatterns::new(&config)?;
        
        Ok(Self { config, patterns })
    }

    /// Sanitize input before sending to AI providers.
    pub fn sanitize_input(&self, input: &str) -> anyhow::Result<SanitizationResult> {
        let mut issues = Vec::new();
        let mut risk_score = 0.0f32;
        let original = input.to_string();
        
        // Check input length
        if input.len() > self.config.max_input_length {
            return Ok(SanitizationResult {
                sanitized: String::new(),
                original,
                issues: vec![SanitizationIssue::SystemDisclosure {
                    disclosure_type: "Excessive input length".into(),
                    pattern: format!("{} > {}", input.len(), self.config.max_input_length),
                }],
                risk_score: 1.0,
                blocked: true,
                redacted_patterns: vec!["Input too long".into()],
            });
        }

        let mut sanitized = input.to_string();

        // 1. Check for prompt injection
        let injection_issues = self.detect_prompt_injection(&sanitized);
        for issue in &injection_issues {
            if let SanitizationIssue::PromptInjection { confidence, .. } = issue {
                risk_score = risk_score.max(*confidence);
            }
        }
        issues.extend(injection_issues);

        // 2. Check for code injection
        let code_issues = self.detect_code_injection(&sanitized);
        for issue in &code_issues {
            if let SanitizationIssue::CodeInjection { severity, .. } = issue {
                risk_score = risk_score.max(*severity);
            }
        }
        issues.extend(code_issues);

        // 3. Detect and redact sensitive data
        let (clean_text, sensitive_issues) = self.detect_and_redact_sensitive(&sanitized);
        sanitized = clean_text;
        issues.extend(sensitive_issues);

        // 4. Check for malicious URLs
        let url_issues = self.check_malicious_urls(&sanitized);
        for issue in &url_issues {
            risk_score = risk_score.max(0.7); // URLs are medium risk
        }
        issues.extend(url_issues);

        // 5. Check for encoded payloads
        let encoded_issues = self.detect_encoded_payloads(&sanitized);
        for issue in &encoded_issues {
            risk_score = risk_score.max(0.6);
        }
        issues.extend(encoded_issues);

        // 6. Check for proprietary information
        let proprietary_issues = self.detect_proprietary_info(&sanitized);
        for issue in &proprietary_issues {
            if let SanitizationIssue::ProprietaryInfo { confidence, .. } = issue {
                risk_score = risk_score.max(*confidence);
            }
        }
        issues.extend(proprietary_issues);

        let blocked = risk_score > self.config.block_threshold;
        let redacted_patterns = issues.iter()
            .filter_map(|issue| match issue {
                SanitizationIssue::SensitiveData { pattern, redacted: true, .. } => Some(pattern.clone()),
                _ => None,
            })
            .collect();

        Ok(SanitizationResult {
            sanitized: if blocked { String::new() } else { sanitized },
            original,
            issues,
            risk_score,
            blocked,
            redacted_patterns,
        })
    }

    /// Sanitize output from AI providers.
    pub fn sanitize_output(&self, output: &str) -> anyhow::Result<SanitizationResult> {
        let mut issues = Vec::new();
        let mut risk_score = 0.0f32;
        let original = output.to_string();

        // Check output length
        if output.len() > self.config.max_output_length {
            return Ok(SanitizationResult {
                sanitized: output.chars().take(self.config.max_output_length).collect(),
                original,
                issues: vec![SanitizationIssue::SystemDisclosure {
                    disclosure_type: "Output truncated".into(), 
                    pattern: format!("{} > {}", output.len(), self.config.max_output_length),
                }],
                risk_score: 0.3,
                blocked: false,
                redacted_patterns: vec!["Output truncated".into()],
            });
        }

        let mut sanitized = output.to_string();

        // 1. Detect and redact sensitive data in output
        let (clean_text, sensitive_issues) = self.detect_and_redact_sensitive(&sanitized);
        sanitized = clean_text;
        issues.extend(sensitive_issues);

        // 2. Check for system information disclosure
        let system_issues = self.detect_system_disclosure(&sanitized);
        for issue in &system_issues {
            risk_score = risk_score.max(0.5);
        }
        issues.extend(system_issues);

        // 3. Check for proprietary information leakage
        let proprietary_issues = self.detect_proprietary_info(&sanitized);
        for issue in &proprietary_issues {
            if let SanitizationIssue::ProprietaryInfo { confidence, .. } = issue {
                risk_score = risk_score.max(*confidence);
            }
        }
        issues.extend(proprietary_issues);

        // 4. Check for malicious URLs in output
        let url_issues = self.check_malicious_urls(&sanitized);
        issues.extend(url_issues);

        let blocked = risk_score > self.config.block_threshold;
        let redacted_patterns = issues.iter()
            .filter_map(|issue| match issue {
                SanitizationIssue::SensitiveData { pattern, redacted: true, .. } => Some(pattern.clone()),
                _ => None,
            })
            .collect();

        Ok(SanitizationResult {
            sanitized: if blocked { "[BLOCKED: High risk content]".into() } else { sanitized },
            original,
            issues,
            risk_score,
            blocked,
            redacted_patterns,
        })
    }

    /// Execute websearch in containerized environment for additional security.
    pub async fn containerized_websearch(
        &self,
        query: &str,
        provider: &str,
    ) -> anyhow::Result<String> {
        // First sanitize the input
        let sanitized_input = self.sanitize_input(query)?;
        if sanitized_input.blocked {
            return Err(anyhow::anyhow!("Query blocked due to security concerns"));
        }

        // Create temporary files for communication with container
        let temp_dir = Path::new(&self.config.container_config.temp_dir);
        std::fs::create_dir_all(temp_dir)?;

        let input_file = temp_dir.join("query.txt");
        let output_file = temp_dir.join("result.txt");
        let config_file = temp_dir.join("config.json");

        std::fs::write(&input_file, &sanitized_input.sanitized)?;

        // Create container configuration
        let container_config = serde_json::json!({
            "provider": provider,
            "timeout": self.config.container_config.timeout_seconds,
            "input_file": "/tmp/query.txt",
            "output_file": "/tmp/result.txt"
        });
        std::fs::write(&config_file, container_config.to_string())?;

        // Run containerized search
        let result = self.run_container_search(&input_file, &output_file, &config_file).await?;

        // Sanitize output
        let sanitized_output = self.sanitize_output(&result)?;
        if sanitized_output.blocked {
            return Err(anyhow::anyhow!("Search result blocked due to security concerns"));
        }

        // Cleanup
        let _ = std::fs::remove_file(input_file);
        let _ = std::fs::remove_file(output_file);
        let _ = std::fs::remove_file(config_file);

        Ok(sanitized_output.sanitized)
    }

    /// Run the actual containerized search.
    async fn run_container_search(
        &self,
        input_file: &Path,
        output_file: &Path,
        config_file: &Path,
    ) -> anyhow::Result<String> {
        use tokio::process::Command;

        let container_name = format!("webpuppet-search-{}", uuid::Uuid::new_v4());
        
        let output = Command::new("docker")
            .args(&[
                "run",
                "--rm",
                "--name", &container_name,
                "--cpus", &self.config.container_config.cpu_limit,
                "--memory", &self.config.container_config.memory_limit,
                "--network", &self.config.container_config.network_mode,
                "--volume", &format!("{}:/tmp/query.txt:ro", input_file.display()),
                "--volume", &format!("{}:/tmp/result.txt:rw", output_file.display()),
                "--volume", &format!("{}:/tmp/config.json:ro", config_file.display()),
                &self.config.container_config.image,
                "timeout", &self.config.container_config.timeout_seconds.to_string(),
                "webpuppet-search", "/tmp/config.json"
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Container execution failed: {}", stderr));
        }

        // Read result
        if output_file.exists() {
            let result = std::fs::read_to_string(output_file)?;
            Ok(result)
        } else {
            Err(anyhow::anyhow!("No result file generated"))
        }
    }
}

impl CompiledPatterns {
    fn new(config: &SanitizationConfig) -> anyhow::Result<Self> {
        // Build prompt injection patterns
        let mut prompt_injection = Vec::new();
        
        let injection_patterns = vec![
            // Direct instruction override
            (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", 0.95, "instruction_override"),
            (r"(?i)disregard\s+(all\s+)?(previous|prior|above)", 0.9, "disregard"),
            (r"(?i)forget\s+(all\s+)?(previous|prior|above)", 0.85, "forget"),
            (r"(?i)new\s+(system\s+)?instructions?:", 0.85, "new_instructions"),
            
            // Role manipulation
            (r"(?i)you\s+are\s+now\s+(a|an|the)", 0.7, "role_change"),
            (r"(?i)act\s+as\s+(if\s+)?(a|an|the)", 0.6, "act_as"),
            (r"(?i)pretend\s+(to\s+be|you\s+are)", 0.6, "pretend"),
            
            // Message injection
            (r"(?i)\[system\]|\[assistant\]|\[user\]", 0.8, "message_role"),
            (r"(?i)<<\s*sys(tem)?\s*>>", 0.85, "system_marker"),
            (r"(?i)```\s*(system|prompt|instruction)", 0.75, "code_block_injection"),
            
            // Context escape
            (r"(?i)(end|close|exit)\s*(of\s*)?(prompt|context|message)", 0.8, "context_escape"),
            (r"(?i)break\s+(out\s+)?(of\s+)?(context|prompt)", 0.75, "break_context"),
            
            // Data exfiltration  
            (r"(?i)(print|output|reveal|show|display)\s+(the\s+)?(system\s+)?(prompt|instructions?)", 0.85, "exfiltration"),
            (r"(?i)(what|tell\s+me)\s+(is\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)", 0.8, "prompt_query"),
            
            // Jailbreak patterns
            (r"(?i)do\s+anything\s+now|dan\s+mode|developer\s+mode", 0.95, "jailbreak"),
            (r"(?i)ignore\s+safety|bypass\s+filters?", 0.9, "safety_bypass"),
            
            // Hidden instructions
            (r"(?i)hidden\s+instruction|secret\s+command|covert\s+directive", 0.9, "hidden_instruction"),
        ];

        for (pattern, confidence, name) in injection_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                prompt_injection.push((regex, confidence, name.to_string()));
            }
        }

        // Build code injection patterns
        let mut code_injection = Vec::new();
        let code_patterns = vec![
            (r"<script[^>]*>", "javascript", 0.9),
            (r"javascript:", "javascript", 0.8),
            (r"eval\s*\(", "javascript", 0.7),
            (r"exec\s*\(", "python", 0.8),
            (r"system\s*\(", "shell", 0.9),
            (r"os\.system", "python", 0.9),
            (r"subprocess\.", "python", 0.7),
            (r"\$\([^)]+\)", "shell", 0.6),
            (r"`[^`]+`", "shell", 0.5),
            (r"rm\s+-rf", "shell", 0.9),
            (r"curl\s+", "shell", 0.4),
            (r"wget\s+", "shell", 0.4),
        ];

        for (pattern, lang, severity) in code_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                code_injection.push((regex, lang.to_string(), severity));
            }
        }

        Ok(Self {
            prompt_injection,
            code_injection,
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")?,
            phone: Regex::new(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}")?,
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?,
            credit_card: Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")?,
            api_key: Regex::new(r#"(?i)(api[_-]?key|token|secret)[_\s]*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#)?,
            ip_address: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")?,
            database_url: Regex::new(r"(?i)(mysql|postgresql|mongodb|redis)://[^\s]+")?,
            file_path: Regex::new(r"(?i)(?:[c-z]:\\|/[a-z]+)(?:\\|/)[^\s]*")?,
            private_key: Regex::new(r"(?i)-----BEGIN[A-Z\s]+PRIVATE KEY-----")?,
            password: Regex::new(r#"(?i)(password|pwd|pass)[_\s]*[=:]\s*['"]?([^\s'\"]{4,})['"]?"#)?,
            url: Regex::new(r"https?://[^\s]+")?,
            base64: Regex::new(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")?,
            hex: Regex::new(r"(?i)(?:0x)?[a-f0-9]{16,}")?,
            unicode_escape: Regex::new(r"\\u[0-9a-fA-F]{4}")?,
            system_path: Regex::new(r"(?i)/(?:etc|usr|var|tmp|home)/[^\s]*")?,
            environment_var: Regex::new(r"\$[A-Z_][A-Z0-9_]*")?,
        })
    }
}

// Implementation methods for detection...
impl Sanitizer {
    fn detect_prompt_injection(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();
        
        for (regex, confidence, pattern_name) in &self.patterns.prompt_injection {
            if let Some(mat) = regex.find(input) {
                issues.push(SanitizationIssue::PromptInjection {
                    pattern: pattern_name.clone(),
                    confidence: *confidence,
                    location: format!("Position {}-{}", mat.start(), mat.end()),
                });
            }
        }
        
        issues
    }

    fn detect_code_injection(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();
        
        for (regex, language, severity) in &self.patterns.code_injection {
            if let Some(mat) = regex.find(input) {
                issues.push(SanitizationIssue::CodeInjection {
                    language: language.clone(),
                    payload: mat.as_str().to_string(),
                    severity: *severity,
                });
            }
        }
        
        issues
    }

    fn detect_and_redact_sensitive(&self, input: &str) -> (String, Vec<SanitizationIssue>) {
        let mut sanitized = input.to_string();
        let mut issues = Vec::new();

        // Helper macro for redaction
        macro_rules! redact_pattern {
            ($regex:expr, $data_type:expr, $replacement:expr) => {
                if $regex.is_match(&sanitized) {
                    let matches: Vec<_> = $regex.find_iter(&sanitized).map(|m| (m.range(), m.as_str().to_string())).collect();
                    for (range, text) in matches.iter().rev() {
                        issues.push(SanitizationIssue::SensitiveData {
                            data_type: $data_type,
                            pattern: text.clone(),
                            redacted: self.config.redact_sensitive,
                        });
                        
                        if self.config.redact_sensitive {
                            sanitized.replace_range(range.clone(), $replacement);
                        }
                    }
                }
            };
        }

        redact_pattern!(self.patterns.email, SensitiveDataType::Email, "[EMAIL_REDACTED]");
        redact_pattern!(self.patterns.phone, SensitiveDataType::PhoneNumber, "[PHONE_REDACTED]");
        redact_pattern!(self.patterns.ssn, SensitiveDataType::SSN, "[SSN_REDACTED]");
        redact_pattern!(self.patterns.credit_card, SensitiveDataType::CreditCard, "[CARD_REDACTED]");
        redact_pattern!(self.patterns.api_key, SensitiveDataType::ApiKey, "[API_KEY_REDACTED]");
        redact_pattern!(self.patterns.ip_address, SensitiveDataType::IpAddress, "[IP_REDACTED]");
        redact_pattern!(self.patterns.database_url, SensitiveDataType::DatabaseUrl, "[DB_URL_REDACTED]");
        redact_pattern!(self.patterns.private_key, SensitiveDataType::PrivateKey, "[PRIVATE_KEY_REDACTED]");
        redact_pattern!(self.patterns.password, SensitiveDataType::Password, "[PASSWORD_REDACTED]");
        redact_pattern!(self.patterns.file_path, SensitiveDataType::FilePath, "[PATH_REDACTED]");

        (sanitized, issues)
    }

    fn check_malicious_urls(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();
        
        for mat in self.patterns.url.find_iter(input) {
            let url = mat.as_str();
            
            // Extract domain
            if let Ok(parsed_url) = url::Url::parse(url) {
                if let Some(domain) = parsed_url.domain() {
                    // Check against blocked domains
                    if self.config.blocked_domains.contains(domain) {
                        issues.push(SanitizationIssue::MaliciousUrl {
                            url: url.to_string(),
                            threat_type: "Blocked domain".to_string(),
                        });
                    }
                    // Check against allowed domains (if not in allowed list and allowed list is not empty)
                    else if !self.config.allowed_domains.is_empty() && !self.config.allowed_domains.contains(domain) {
                        issues.push(SanitizationIssue::MaliciousUrl {
                            url: url.to_string(),
                            threat_type: "Unauthorized domain".to_string(),
                        });
                    }
                }
            }
        }
        
        issues
    }

    fn detect_encoded_payloads(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();

        // Check for base64 encoded data
        for mat in self.patterns.base64.find_iter(input) {
            let encoded = mat.as_str();
            if encoded.len() > 20 { // Only check longer sequences
                if let Ok(decoded) = base64_helper::decode(encoded) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let snippet = if decoded_str.len() > 50 {
                            format!("{}...", &decoded_str[..50])
                        } else {
                            decoded_str
                        };
                        
                        issues.push(SanitizationIssue::EncodedPayload {
                            encoding: "base64".to_string(),
                            decoded_snippet: snippet,
                        });
                    }
                }
            }
        }

        // Check for hex encoded data
        for mat in self.patterns.hex.find_iter(input) {
            let encoded = mat.as_str();
            if encoded.len() > 16 { // Only check longer sequences
                issues.push(SanitizationIssue::EncodedPayload {
                    encoding: "hex".to_string(),
                    decoded_snippet: format!("Hex data: {}", &encoded[..16.min(encoded.len())]),
                });
            }
        }

        issues
    }

    fn detect_system_disclosure(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();

        // Check for system paths
        for mat in self.patterns.system_path.find_iter(input) {
            issues.push(SanitizationIssue::SystemDisclosure {
                disclosure_type: "System path".to_string(),
                pattern: mat.as_str().to_string(),
            });
        }

        // Check for environment variables
        for mat in self.patterns.environment_var.find_iter(input) {
            issues.push(SanitizationIssue::SystemDisclosure {
                disclosure_type: "Environment variable".to_string(),
                pattern: mat.as_str().to_string(),
            });
        }

        issues
    }

    fn detect_proprietary_info(&self, input: &str) -> Vec<SanitizationIssue> {
        let mut issues = Vec::new();
        let lower_input = input.to_lowercase();

        for keyword in &self.config.proprietary_keywords {
            if lower_input.contains(&keyword.to_lowercase()) {
                issues.push(SanitizationIssue::ProprietaryInfo {
                    info_type: keyword.clone(),
                    confidence: 0.7,
                });
            }
        }

        issues
    }
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self::new().expect("Failed to create default sanitizer")
    }
}

// Base64 decode helper using existing base64 crate
mod base64_helper {
    pub fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.decode(input).map_err(|_| "Invalid base64")
    }
}