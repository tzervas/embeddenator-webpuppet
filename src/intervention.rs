//! Human intervention system for browser automation.
//!
//! This module provides mechanisms for:
//! - Pausing automation for manual intervention (captchas, 2FA, etc.)
//! - Detecting situations requiring human input
//! - Resuming automation after manual steps
//! - Timeout handling for intervention windows
//!
//! ## Design Philosophy
//!
//! The webpuppet is designed as a **human-in-the-loop** system:
//! - Agents automate repetitive tasks (navigation, typing, clicking)
//! - Humans handle edge cases (captchas, auth challenges, verification)
//! - The system can pause and wait for manual completion
//! - Visual browser mode allows real-time observation
//!
//! ## Example
//!
//! ```rust,ignore
//! use embeddenator_webpuppet::{WebPuppet, InterventionHandler, InterventionReason};
//!
//! let handler = InterventionHandler::new()
//!     .with_timeout(Duration::from_secs(300))  // 5 min for captcha
//!     .with_callback(|reason| {
//!         println!("⚠️  Manual intervention needed: {:?}", reason);
//!         // Could also send desktop notification, play sound, etc.
//!     });
//!
//! let puppet = WebPuppet::builder()
//!     .headless(false)  // IMPORTANT: visible browser for intervention
//!     .with_intervention_handler(handler)
//!     .build()
//!     .await?;
//!
//! // Automation proceeds until intervention needed
//! let result = puppet.prompt_with_intervention(provider, request).await?;
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// Reasons why human intervention may be required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterventionReason {
    /// CAPTCHA challenge detected.
    Captcha {
        /// Type of captcha (reCAPTCHA, hCaptcha, etc.)
        captcha_type: Option<String>,
    },
    /// Two-factor authentication required.
    TwoFactorAuth {
        /// Method (SMS, TOTP, email, etc.)
        method: Option<String>,
    },
    /// Login/authentication required.
    LoginRequired,
    /// Email/phone verification needed.
    Verification {
        /// What needs verification.
        target: String,
    },
    /// Rate limit or cooldown.
    RateLimited {
        /// Suggested wait time.
        wait_seconds: Option<u64>,
    },
    /// Browser popup or dialog.
    BrowserDialog {
        /// Dialog message if available.
        message: Option<String>,
    },
    /// Cookie consent banner.
    CookieConsent,
    /// Age verification.
    AgeVerification,
    /// Account selection (multiple accounts).
    AccountSelection,
    /// Terms of service acceptance.
    TermsAcceptance,
    /// Generic intervention needed.
    Manual {
        /// Description of what's needed.
        description: String,
    },
    /// Automation explicitly paused by user/agent.
    Paused,
}

impl std::fmt::Display for InterventionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterventionReason::Captcha { captcha_type } => {
                write!(f, "CAPTCHA")?;
                if let Some(t) = captcha_type {
                    write!(f, " ({})", t)?;
                }
                Ok(())
            }
            InterventionReason::TwoFactorAuth { method } => {
                write!(f, "2FA")?;
                if let Some(m) = method {
                    write!(f, " via {}", m)?;
                }
                Ok(())
            }
            InterventionReason::LoginRequired => write!(f, "Login required"),
            InterventionReason::Verification { target } => {
                write!(f, "Verification needed: {}", target)
            }
            InterventionReason::RateLimited { wait_seconds } => {
                write!(f, "Rate limited")?;
                if let Some(s) = wait_seconds {
                    write!(f, " (wait {}s)", s)?;
                }
                Ok(())
            }
            InterventionReason::BrowserDialog { message } => {
                write!(f, "Browser dialog")?;
                if let Some(m) = message {
                    write!(f, ": {}", m)?;
                }
                Ok(())
            }
            InterventionReason::CookieConsent => write!(f, "Cookie consent"),
            InterventionReason::AgeVerification => write!(f, "Age verification"),
            InterventionReason::AccountSelection => write!(f, "Account selection"),
            InterventionReason::TermsAcceptance => write!(f, "Terms acceptance"),
            InterventionReason::Manual { description } => write!(f, "{}", description),
            InterventionReason::Paused => write!(f, "Automation paused"),
        }
    }
}

/// Current state of intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterventionState {
    /// Automation running normally.
    Running,
    /// Waiting for human intervention.
    WaitingForHuman,
    /// Human completed intervention, resuming.
    Resuming,
    /// Intervention timed out.
    TimedOut,
    /// Intervention cancelled.
    Cancelled,
}

/// Callback function type for intervention notifications.
pub type InterventionCallback = Box<dyn Fn(&InterventionReason) + Send + Sync>;

/// Signal sent when intervention is complete.
#[derive(Debug, Clone)]
pub struct InterventionComplete {
    /// Whether the intervention was successful.
    pub success: bool,
    /// Optional message from the user.
    pub message: Option<String>,
}

/// Configuration for intervention handling.
#[derive(Clone)]
pub struct InterventionConfig {
    /// Maximum time to wait for human intervention.
    pub timeout: Duration,
    /// Whether to auto-detect captchas.
    pub detect_captcha: bool,
    /// Whether to auto-detect 2FA prompts.
    pub detect_2fa: bool,
    /// Whether to auto-dismiss cookie banners.
    pub auto_dismiss_cookies: bool,
    /// Selectors that indicate captcha presence.
    pub captcha_selectors: Vec<String>,
    /// Selectors that indicate 2FA prompts.
    pub twofa_selectors: Vec<String>,
    /// Play sound on intervention.
    pub play_sound: bool,
    /// Show desktop notification.
    pub desktop_notification: bool,
}

impl Default for InterventionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            detect_captcha: true,
            detect_2fa: true,
            auto_dismiss_cookies: false, // Respect user choice
            captcha_selectors: vec![
                // reCAPTCHA
                r#"iframe[src*="recaptcha"]"#.into(),
                r#"iframe[src*="google.com/recaptcha"]"#.into(),
                r#".g-recaptcha"#.into(),
                r#"#recaptcha"#.into(),
                // hCaptcha
                r#"iframe[src*="hcaptcha"]"#.into(),
                r#".h-captcha"#.into(),
                // Cloudflare
                r#"iframe[src*="challenges.cloudflare"]"#.into(),
                r#"#cf-wrapper"#.into(),
                r#".cf-turnstile"#.into(),
                // Generic
                r#"[class*="captcha"]"#.into(),
                r#"[id*="captcha"]"#.into(),
            ],
            twofa_selectors: vec![
                r#"input[name*="otp"]"#.into(),
                r#"input[name*="2fa"]"#.into(),
                r#"input[name*="totp"]"#.into(),
                r#"input[autocomplete="one-time-code"]"#.into(),
                r#"[class*="two-factor"]"#.into(),
                r#"[class*="2fa"]"#.into(),
                r#"[class*="verification-code"]"#.into(),
            ],
            play_sound: false,
            desktop_notification: true,
        }
    }
}

/// Handler for human intervention during automation.
pub struct InterventionHandler {
    config: InterventionConfig,
    state: Arc<RwLock<InterventionState>>,
    current_reason: Arc<RwLock<Option<InterventionReason>>>,
    callback: Option<InterventionCallback>,
    /// Channel to signal intervention complete.
    complete_tx: Option<mpsc::Sender<InterventionComplete>>,
    complete_rx: Arc<RwLock<Option<mpsc::Receiver<InterventionComplete>>>>,
}

impl InterventionHandler {
    /// Create a new intervention handler with default config.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1);
        Self {
            config: InterventionConfig::default(),
            state: Arc::new(RwLock::new(InterventionState::Running)),
            current_reason: Arc::new(RwLock::new(None)),
            callback: None,
            complete_tx: Some(tx),
            complete_rx: Arc::new(RwLock::new(Some(rx))),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: InterventionConfig) -> Self {
        let mut handler = Self::new();
        handler.config = config;
        handler
    }

    /// Set timeout for intervention.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set callback for intervention notifications.
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&InterventionReason) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Enable/disable captcha detection.
    pub fn detect_captcha(mut self, detect: bool) -> Self {
        self.config.detect_captcha = detect;
        self
    }

    /// Enable/disable 2FA detection.
    pub fn detect_2fa(mut self, detect: bool) -> Self {
        self.config.detect_2fa = detect;
        self
    }

    /// Get current state.
    pub fn state(&self) -> InterventionState {
        *self.state.read()
    }

    /// Get current intervention reason, if any.
    pub fn current_reason(&self) -> Option<InterventionReason> {
        self.current_reason.read().clone()
    }

    /// Check if waiting for human.
    pub fn is_waiting(&self) -> bool {
        self.state() == InterventionState::WaitingForHuman
    }

    /// Request human intervention.
    pub async fn request_intervention(&self, reason: InterventionReason) -> Result<InterventionComplete> {
        // Update state
        *self.state.write() = InterventionState::WaitingForHuman;
        *self.current_reason.write() = Some(reason.clone());

        // Notify via callback
        if let Some(ref callback) = self.callback {
            callback(&reason);
        }

        // Log
        tracing::warn!(
            reason = %reason,
            timeout_secs = self.config.timeout.as_secs(),
            "Human intervention requested"
        );

        // Send notification
        self.send_notification(&reason);

        // Wait for completion or timeout
        let start = Instant::now();
        
        // Take the receiver
        let mut rx_guard = self.complete_rx.write();
        let rx = rx_guard.take();
        drop(rx_guard);

        if let Some(mut rx) = rx {
            let result = tokio::select! {
                complete = rx.recv() => {
                    // Put receiver back
                    *self.complete_rx.write() = Some(rx);
                    
                    match complete {
                        Some(c) => {
                            *self.state.write() = InterventionState::Resuming;
                            *self.current_reason.write() = None;
                            tracing::info!(
                                success = c.success,
                                elapsed_secs = start.elapsed().as_secs(),
                                "Intervention completed"
                            );
                            Ok(c)
                        }
                        None => {
                            *self.state.write() = InterventionState::Cancelled;
                            Err(Error::InterventionCancelled)
                        }
                    }
                }
                _ = tokio::time::sleep(self.config.timeout) => {
                    // Put receiver back
                    *self.complete_rx.write() = Some(rx);
                    
                    *self.state.write() = InterventionState::TimedOut;
                    tracing::error!(
                        timeout_secs = self.config.timeout.as_secs(),
                        "Intervention timed out"
                    );
                    Err(Error::InterventionTimeout(self.config.timeout.as_secs()))
                }
            };
            result
        } else {
            Err(Error::Internal("intervention channel unavailable".into()))
        }
    }

    /// Signal that intervention is complete (call from human/UI).
    pub fn complete(&self, success: bool, message: Option<String>) {
        if let Some(ref tx) = self.complete_tx {
            let _ = tx.try_send(InterventionComplete { success, message });
        }
    }

    /// Signal successful completion.
    pub fn done(&self) {
        self.complete(true, None);
    }

    /// Signal intervention failed/cancelled.
    pub fn cancel(&self) {
        self.complete(false, Some("Cancelled by user".into()));
        *self.state.write() = InterventionState::Cancelled;
    }

    /// Pause automation (manual pause, not for captcha).
    pub fn pause(&self) {
        *self.state.write() = InterventionState::WaitingForHuman;
        *self.current_reason.write() = Some(InterventionReason::Paused);
        tracing::info!("Automation paused");
    }

    /// Resume from pause.
    pub fn resume(&self) {
        if *self.state.read() == InterventionState::WaitingForHuman {
            *self.state.write() = InterventionState::Resuming;
            *self.current_reason.write() = None;
            self.done();
            tracing::info!("Automation resumed");
        }
    }

    /// Get captcha selectors for detection.
    pub fn captcha_selectors(&self) -> &[String] {
        &self.config.captcha_selectors
    }

    /// Get 2FA selectors for detection.
    pub fn twofa_selectors(&self) -> &[String] {
        &self.config.twofa_selectors
    }

    /// Send desktop notification (platform-specific).
    fn send_notification(&self, reason: &InterventionReason) {
        if !self.config.desktop_notification {
            return;
        }

        // Use notify-send on Linux (requires libnotify)
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("notify-send")
                .args([
                    "--urgency=critical",
                    "--app-name=webpuppet",
                    "Human Intervention Required",
                    &reason.to_string(),
                ])
                .spawn();
        }

        // Could add macOS/Windows notification support here
    }
}

impl Default for InterventionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for InterventionHandler {
    fn clone(&self) -> Self {
        // Create new channels for clone
        let (tx, rx) = mpsc::channel(1);
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            current_reason: Arc::clone(&self.current_reason),
            callback: None, // Callbacks can't be cloned
            complete_tx: Some(tx),
            complete_rx: Arc::new(RwLock::new(Some(rx))),
        }
    }
}

/// Detector for situations requiring human intervention.
pub struct InterventionDetector {
    config: InterventionConfig,
}

impl InterventionDetector {
    /// Create a new detector with default config.
    pub fn new() -> Self {
        Self {
            config: InterventionConfig::default(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: InterventionConfig) -> Self {
        Self { config }
    }

    /// Check page HTML for captcha indicators.
    pub fn detect_captcha(&self, html: &str) -> Option<InterventionReason> {
        if !self.config.detect_captcha {
            return None;
        }

        let html_lower = html.to_lowercase();

        // Check for common captcha indicators
        let captcha_indicators = [
            ("recaptcha", "reCAPTCHA"),
            ("hcaptcha", "hCaptcha"),
            ("cloudflare", "Cloudflare Challenge"),
            ("turnstile", "Cloudflare Turnstile"),
            ("captcha", "CAPTCHA"),
            ("robot", "Robot verification"),
            ("human verification", "Human verification"),
        ];

        for (indicator, name) in captcha_indicators {
            if html_lower.contains(indicator) {
                return Some(InterventionReason::Captcha {
                    captcha_type: Some(name.to_string()),
                });
            }
        }

        None
    }

    /// Check page HTML for 2FA indicators.
    pub fn detect_2fa(&self, html: &str) -> Option<InterventionReason> {
        if !self.config.detect_2fa {
            return None;
        }

        let html_lower = html.to_lowercase();

        let twofa_indicators = [
            ("two-factor", "Two-factor"),
            ("2fa", "2FA"),
            ("verification code", "Verification code"),
            ("authenticator", "Authenticator app"),
            ("one-time", "One-time code"),
            ("security code", "Security code"),
            ("sms code", "SMS"),
            ("phone verification", "Phone"),
        ];

        for (indicator, method) in twofa_indicators {
            if html_lower.contains(indicator) {
                return Some(InterventionReason::TwoFactorAuth {
                    method: Some(method.to_string()),
                });
            }
        }

        None
    }

    /// Check page HTML for login requirement.
    pub fn detect_login_required(&self, html: &str, url: &str) -> Option<InterventionReason> {
        let html_lower = html.to_lowercase();
        let url_lower = url.to_lowercase();

        // URL-based detection
        if url_lower.contains("/login")
            || url_lower.contains("/signin")
            || url_lower.contains("/auth")
        {
            return Some(InterventionReason::LoginRequired);
        }

        // Content-based detection
        let login_indicators = [
            "sign in to continue",
            "log in to continue",
            "please sign in",
            "please log in",
            "session expired",
            "authentication required",
        ];

        for indicator in login_indicators {
            if html_lower.contains(indicator) {
                return Some(InterventionReason::LoginRequired);
            }
        }

        None
    }

    /// Check for rate limiting.
    pub fn detect_rate_limit(&self, html: &str) -> Option<InterventionReason> {
        let html_lower = html.to_lowercase();

        let rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "slow down",
            "please wait",
            "try again later",
            "temporarily blocked",
        ];

        for indicator in rate_limit_indicators {
            if html_lower.contains(indicator) {
                // Try to extract wait time
                let wait_seconds = extract_wait_time(&html_lower);
                return Some(InterventionReason::RateLimited { wait_seconds });
            }
        }

        None
    }

    /// Run all detection checks.
    pub fn detect_all(&self, html: &str, url: &str) -> Option<InterventionReason> {
        // Priority order: Captcha > 2FA > Rate limit > Login
        self.detect_captcha(html)
            .or_else(|| self.detect_2fa(html))
            .or_else(|| self.detect_rate_limit(html))
            .or_else(|| self.detect_login_required(html, url))
    }
}

impl Default for InterventionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to extract wait time from HTML (e.g., "try again in 30 seconds").
fn extract_wait_time(html: &str) -> Option<u64> {
    // Simple regex-free extraction
    let patterns = [
        ("wait ", " second"),
        ("wait ", " minute"),
        ("try again in ", " second"),
        ("try again in ", " minute"),
    ];

    for (prefix, suffix) in patterns {
        if let Some(start) = html.find(prefix) {
            let after_prefix = &html[start + prefix.len()..];
            if let Some(end) = after_prefix.find(suffix) {
                let num_str = &after_prefix[..end].trim();
                if let Ok(num) = num_str.parse::<u64>() {
                    // Convert minutes to seconds if needed
                    if suffix.contains("minute") {
                        return Some(num * 60);
                    }
                    return Some(num);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captcha_detection() {
        let detector = InterventionDetector::new();

        let html_recaptcha = r#"<iframe src="https://www.google.com/recaptcha/api"></iframe>"#;
        assert!(detector.detect_captcha(html_recaptcha).is_some());

        let html_hcaptcha = r#"<div class="h-captcha"></div>"#;
        assert!(detector.detect_captcha(html_hcaptcha).is_some());

        let html_normal = r#"<html><body>Hello world</body></html>"#;
        assert!(detector.detect_captcha(html_normal).is_none());
    }

    #[test]
    fn test_2fa_detection() {
        let detector = InterventionDetector::new();

        let html_2fa = r#"<input name="otp" placeholder="Enter verification code">"#;
        assert!(detector.detect_2fa(html_2fa).is_some());

        let html_normal = r#"<input name="email" placeholder="Enter email">"#;
        assert!(detector.detect_2fa(html_normal).is_none());
    }

    #[test]
    fn test_rate_limit_detection() {
        let detector = InterventionDetector::new();

        let html_limited = r#"<div>Too many requests. Please try again later.</div>"#;
        let reason = detector.detect_rate_limit(html_limited);
        assert!(matches!(reason, Some(InterventionReason::RateLimited { .. })));
    }

    #[test]
    fn test_wait_time_extraction() {
        assert_eq!(extract_wait_time("wait 30 seconds"), Some(30));
        assert_eq!(extract_wait_time("try again in 5 minutes"), Some(300));
        assert_eq!(extract_wait_time("no wait time here"), None);
    }

    #[test]
    fn test_intervention_reason_display() {
        let reason = InterventionReason::Captcha {
            captcha_type: Some("reCAPTCHA".into()),
        };
        assert_eq!(format!("{}", reason), "CAPTCHA (reCAPTCHA)");

        let reason = InterventionReason::TwoFactorAuth {
            method: Some("SMS".into()),
        };
        assert_eq!(format!("{}", reason), "2FA via SMS");
    }

    #[tokio::test]
    async fn test_intervention_handler_resume() {
        let handler = InterventionHandler::new().with_timeout(Duration::from_millis(100));

        // Pause
        handler.pause();
        assert!(handler.is_waiting());

        // Resume
        handler.resume();
        
        // State should be resuming
        assert_eq!(handler.state(), InterventionState::Resuming);
    }
}
