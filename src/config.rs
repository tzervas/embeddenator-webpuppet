//! Configuration for webpuppet browser automation.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for WebPuppet.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Browser configuration.
    pub browser: BrowserConfig,
    /// Provider-specific settings.
    pub providers: ProvidersConfig,
    /// Session management settings.
    pub session: SessionConfig,
    /// Rate limiting settings.
    pub rate_limit: RateLimitConfig,
}

/// Browser-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    /// Run browser in headless mode.
    pub headless: bool,
    /// Path to browser executable (auto-detect if None).
    pub executable_path: Option<PathBuf>,
    /// User data directory for profiles.
    pub user_data_dir: Option<PathBuf>,
    /// Browser window width.
    pub window_width: u32,
    /// Browser window height.
    pub window_height: u32,
    /// Additional browser arguments.
    pub args: Vec<String>,
    /// Request timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Enable devtools (debug mode).
    pub devtools: bool,
    /// Sandbox mode (disable for containers).
    pub sandbox: bool,
    /// Dual-head mode: launches a visible monitoring window alongside headless automation.
    pub dual_head: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            headless: true,
            executable_path: None,
            user_data_dir: None,
            window_width: 1920,
            window_height: 1080,
            args: vec![
                "--disable-gpu".into(),
                "--disable-dev-shm-usage".into(),
                "--no-first-run".into(),
            ],
            timeout: Duration::from_secs(60),
            devtools: false,
            sandbox: true,
            dual_head: false,
        }
    }
}

/// Provider-specific configurations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProvidersConfig {
    /// Grok (X.ai) configuration.
    #[cfg(feature = "grok")]
    pub grok: GrokConfig,
    /// Claude (Anthropic) configuration.
    #[cfg(feature = "claude")]
    pub claude: ClaudeConfig,
    /// Gemini (Google) configuration.
    #[cfg(feature = "gemini")]
    pub gemini: GeminiConfig,
}

/// Grok-specific settings.
#[cfg(feature = "grok")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrokConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input (if supported).
    pub file_input_selector: Option<String>,
    /// Model variant to use.
    pub model: String,
}

#[cfg(feature = "grok")]
impl Default for GrokConfig {
    fn default() -> Self {
        Self {
            login_url: "https://x.com/i/grok".into(),
            chat_url: "https://x.com/i/grok".into(),
            input_selector: r#"textarea[data-testid="grokInput"]"#.into(),
            submit_selector: r#"button[data-testid="grokSend"]"#.into(),
            response_selector: r#"div[data-testid="grokResponse"]"#.into(),
            ready_selector: r#"textarea[data-testid="grokInput"]"#.into(),
            file_input_selector: Some(r#"input[type="file"]"#.into()),
            model: "grok-2".into(),
        }
    }
}

/// Claude-specific settings.
#[cfg(feature = "claude")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input.
    pub file_input_selector: Option<String>,
    /// Organization (if applicable).
    pub organization: Option<String>,
}

#[cfg(feature = "claude")]
impl Default for ClaudeConfig {
    fn default() -> Self {
        Self {
            login_url: "https://claude.ai/login".into(),
            chat_url: "https://claude.ai/new".into(),
            input_selector: r#"div[contenteditable="true"]"#.into(),
            submit_selector: r#"button[aria-label="Send message"]"#.into(),
            response_selector: r#"div.prose"#.into(),
            ready_selector: r#"div[contenteditable="true"]"#.into(),
            file_input_selector: Some(r#"input[type="file"]"#.into()),
            organization: None,
        }
    }
}

/// Gemini-specific settings.
#[cfg(feature = "gemini")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input.
    pub file_input_selector: Option<String>,
    /// Google account to use.
    pub google_account: Option<String>,
}

#[cfg(feature = "gemini")]
impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            login_url: "https://gemini.google.com".into(),
            chat_url: "https://gemini.google.com/app".into(),
            input_selector: r#"rich-textarea"#.into(),
            submit_selector: r#"button[aria-label="Send message"]"#.into(),
            response_selector: r#"message-content"#.into(),
            ready_selector: r#"rich-textarea"#.into(),
            file_input_selector: Some(r#"input[type="file"]"#.into()),
            google_account: None,
        }
    }
}

/// ChatGPT (OpenAI) configuration.
#[cfg(feature = "chatgpt")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatGptConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input.
    pub file_input_selector: Option<String>,
    /// Model to use (gpt-4o, gpt-4, etc).
    pub model: String,
}

#[cfg(feature = "chatgpt")]
impl Default for ChatGptConfig {
    fn default() -> Self {
        Self {
            login_url: "https://chat.openai.com".into(),
            chat_url: "https://chat.openai.com".into(),
            input_selector: r#"textarea[data-id="root"]"#.into(),
            submit_selector: r#"button[data-testid="send-button"]"#.into(),
            response_selector: r#"div[data-message-author-role="assistant"]"#.into(),
            ready_selector: r#"textarea[data-id="root"]"#.into(),
            file_input_selector: Some(r#"input[type="file"]"#.into()),
            model: "gpt-4o".into(),
        }
    }
}

/// Perplexity AI configuration.
#[cfg(feature = "perplexity")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerplexityConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input.
    pub file_input_selector: Option<String>,
}

#[cfg(feature = "perplexity")]
impl Default for PerplexityConfig {
    fn default() -> Self {
        Self {
            login_url: "https://www.perplexity.ai".into(),
            chat_url: "https://www.perplexity.ai".into(),
            input_selector: r#"textarea[placeholder*="Ask"]"#.into(),
            submit_selector: r#"button[aria-label="Submit query"]"#.into(),
            response_selector: r#"div.prose"#.into(),
            ready_selector: r#"textarea[placeholder*="Ask"]"#.into(),
            file_input_selector: Some(r#"input[type="file"]"#.into()),
        }
    }
}

/// NotebookLM (Google) configuration.
#[cfg(feature = "notebooklm")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookLmConfig {
    /// Login URL.
    pub login_url: String,
    /// Chat URL.
    pub chat_url: String,
    /// CSS selector for input field.
    pub input_selector: String,
    /// CSS selector for submit button.
    pub submit_selector: String,
    /// CSS selector for response container.
    pub response_selector: String,
    /// CSS selector to wait for page ready.
    pub ready_selector: String,
    /// CSS selector for file input.
    pub file_input_selector: Option<String>,
}

#[cfg(feature = "notebooklm")]
impl Default for NotebookLmConfig {
    fn default() -> Self {
        Self {
            login_url: "https://notebooklm.google.com".into(),
            chat_url: "https://notebooklm.google.com".into(),
            input_selector: r#"textarea[aria-label*="Ask"]"#.into(),
            submit_selector: r#"button[aria-label="Send"]"#.into(),
            response_selector: r#"div.response-content"#.into(),
            ready_selector: r#"textarea[aria-label*="Ask"]"#.into(),
            file_input_selector: Some(r#"button[aria-label="Add source"]"#.into()),
        }
    }
}

/// Session management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Directory for session storage.
    pub storage_dir: Option<PathBuf>,
    /// Session timeout before re-auth.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Keep cookies between sessions.
    pub persist_cookies: bool,
    /// Encrypt stored session data.
    pub encrypt_storage: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            storage_dir: None,
            timeout: Duration::from_secs(3600 * 24), // 24 hours
            persist_cookies: true,
            encrypt_storage: true,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Minimum delay between requests.
    #[serde(with = "humantime_serde")]
    pub min_delay: Duration,
    /// Maximum delay between requests.
    #[serde(with = "humantime_serde")]
    pub max_delay: Duration,
    /// Requests per minute limit.
    pub requests_per_minute: u32,
    /// Add human-like delays.
    pub humanize: bool,
    /// Jitter percentage for delays (0-100).
    pub jitter_percent: u8,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
            requests_per_minute: 20,
            humanize: true,
            jitter_percent: 30,
        }
    }
}

impl Config {
    /// Load configuration from file.
    pub fn from_file(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Save configuration to file.
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Create a builder for configuration.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder for Config.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Set headless mode.
    pub fn headless(mut self, headless: bool) -> Self {
        self.config.browser.headless = headless;
        self
    }

    /// Set browser executable path.
    pub fn executable_path(mut self, path: PathBuf) -> Self {
        self.config.browser.executable_path = Some(path);
        self
    }

    /// Set user data directory.
    pub fn user_data_dir(mut self, path: PathBuf) -> Self {
        self.config.browser.user_data_dir = Some(path);
        self
    }

    /// Set request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.browser.timeout = timeout;
        self
    }

    /// Enable devtools.
    pub fn devtools(mut self, enabled: bool) -> Self {
        self.config.browser.devtools = enabled;
        self
    }

    /// Disable sandbox (for containers).
    pub fn no_sandbox(mut self) -> Self {
        self.config.browser.sandbox = false;
        self.config.browser.args.push("--no-sandbox".into());
        self
    }

    /// Set session storage directory.
    pub fn session_dir(mut self, path: PathBuf) -> Self {
        self.config.session.storage_dir = Some(path);
        self
    }

    /// Set rate limit.
    pub fn rate_limit(mut self, requests_per_minute: u32) -> Self {
        self.config.rate_limit.requests_per_minute = requests_per_minute;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Config {
        self.config
    }
}
