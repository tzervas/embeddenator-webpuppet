//! Provider trait definitions for AI web UI automation.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::error::Result;
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Supported AI providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Grok by X.ai (Twitter/X).
    #[cfg(feature = "grok")]
    Grok,
    /// Claude by Anthropic.
    #[cfg(feature = "claude")]
    Claude,
    /// Gemini by Google.
    #[cfg(feature = "gemini")]
    Gemini,
    /// ChatGPT by OpenAI.
    #[cfg(feature = "chatgpt")]
    ChatGpt,
    /// Perplexity AI (search-focused).
    #[cfg(feature = "perplexity")]
    Perplexity,
    /// NotebookLM by Google (research assistant).
    #[cfg(feature = "notebooklm")]
    NotebookLm,
    /// Kaggle (dataset search/catalog).
    #[cfg(feature = "kaggle")]
    Kaggle,
}

impl Provider {
    /// Get the provider name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "grok")]
            Provider::Grok => "grok",
            #[cfg(feature = "claude")]
            Provider::Claude => "claude",
            #[cfg(feature = "gemini")]
            Provider::Gemini => "gemini",
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt => "chatgpt",
            #[cfg(feature = "perplexity")]
            Provider::Perplexity => "perplexity",
            #[cfg(feature = "notebooklm")]
            Provider::NotebookLm => "notebooklm",
            #[cfg(feature = "kaggle")]
            Provider::Kaggle => "kaggle",
        }
    }

    /// Get the base URL for this provider.
    pub fn base_url(&self) -> &'static str {
        match self {
            #[cfg(feature = "grok")]
            Provider::Grok => "https://x.com/i/grok",
            #[cfg(feature = "claude")]
            Provider::Claude => "https://claude.ai",
            #[cfg(feature = "gemini")]
            Provider::Gemini => "https://gemini.google.com",
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt => "https://chat.openai.com",
            #[cfg(feature = "perplexity")]
            Provider::Perplexity => "https://www.perplexity.ai",
            #[cfg(feature = "notebooklm")]
            Provider::NotebookLm => "https://notebooklm.google.com",
            #[cfg(feature = "kaggle")]
            Provider::Kaggle => "https://www.kaggle.com",
        }
    }

    /// Parse provider from string (use parse() method instead for FromStr trait).
    pub fn from_string(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "grok")]
            "grok" | "xai" | "x" => Some(Provider::Grok),
            #[cfg(feature = "claude")]
            "claude" | "anthropic" => Some(Provider::Claude),
            #[cfg(feature = "gemini")]
            "gemini" | "google" | "bard" => Some(Provider::Gemini),
            #[cfg(feature = "chatgpt")]
            "chatgpt" | "openai" | "gpt" => Some(Provider::ChatGpt),
            #[cfg(feature = "perplexity")]
            "perplexity" | "pplx" => Some(Provider::Perplexity),
            #[cfg(feature = "notebooklm")]
            "notebooklm" | "notebook" | "nlm" => Some(Provider::NotebookLm),
            #[cfg(feature = "kaggle")]
            "kaggle" => Some(Provider::Kaggle),
            _ => None,
        }
    }

    /// List all available providers.
    pub fn all() -> Vec<Provider> {
        vec![
            #[cfg(feature = "grok")]
            Provider::Grok,
            #[cfg(feature = "claude")]
            Provider::Claude,
            #[cfg(feature = "gemini")]
            Provider::Gemini,
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt,
            #[cfg(feature = "perplexity")]
            Provider::Perplexity,
            #[cfg(feature = "notebooklm")]
            Provider::NotebookLm,
            #[cfg(feature = "kaggle")]
            Provider::Kaggle,
        ]
    }

    /// List web-search capable providers.
    pub fn search_providers() -> Vec<Provider> {
        vec![
            #[cfg(feature = "grok")]
            Provider::Grok,
            #[cfg(feature = "perplexity")]
            Provider::Perplexity,
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt,
            #[cfg(feature = "kaggle")]
            Provider::Kaggle,
        ]
    }

    /// List providers with large context windows.
    pub fn large_context_providers() -> Vec<Provider> {
        vec![
            #[cfg(feature = "notebooklm")]
            Provider::NotebookLm, // 500k+
            #[cfg(feature = "gemini")]
            Provider::Gemini, // 1M+
            #[cfg(feature = "claude")]
            Provider::Claude, // 200k
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt, // 128k
            #[cfg(feature = "grok")]
            Provider::Grok, // 128k
        ]
    }
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_string(s).ok_or_else(|| format!("Unknown provider: {}", s))
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Capabilities that a provider supports.
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// Supports multi-turn conversations.
    pub conversation: bool,
    /// Supports image input.
    pub vision: bool,
    /// Supports file attachments.
    pub file_upload: bool,
    /// Supports code execution.
    pub code_execution: bool,
    /// Supports web search.
    pub web_search: bool,
    /// Maximum context length (tokens, approximate).
    pub max_context: Option<usize>,
    /// Available model variants.
    pub models: Vec<String>,
}

/// Trait for AI provider implementations.
///
/// Each provider must implement this trait to enable browser automation
/// for their specific web UI.
#[async_trait]
pub trait ProviderTrait: Send + Sync {
    /// Get the provider identifier.
    fn provider(&self) -> Provider;

    /// Get provider capabilities.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Check if the session is authenticated.
    async fn is_authenticated(&self, session: &Session) -> Result<bool>;

    /// Perform authentication flow.
    ///
    /// This may involve:
    /// - Navigating to login page
    /// - Waiting for manual login (if 2FA required)
    /// - Extracting and storing auth cookies
    async fn authenticate(&self, session: &mut Session) -> Result<()>;

    /// Send a prompt and get a response.
    ///
    /// This is the main interaction method that:
    /// 1. Navigates to chat interface
    /// 2. Enters the prompt
    /// 3. Submits and waits for response
    /// 4. Extracts and returns the response text
    async fn send_prompt(
        &self,
        session: &Session,
        request: &PromptRequest,
    ) -> Result<PromptResponse>;

    /// Start a new conversation (clear context).
    async fn new_conversation(&self, session: &Session) -> Result<String>;

    /// Continue an existing conversation.
    async fn continue_conversation(
        &self,
        session: &Session,
        conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse>;

    /// Get the current page URL.
    async fn current_url(&self, session: &Session) -> Result<String>;

    /// Wait for the page to be ready for interaction.
    async fn wait_ready(&self, session: &Session) -> Result<()>;

    /// Extract response text from the page.
    async fn extract_response(&self, session: &Session) -> Result<String>;

    /// Check for and handle rate limiting.
    async fn check_rate_limit(&self, session: &Session) -> Result<Option<std::time::Duration>>;
}

/// Helper struct for storing provider metadata.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProviderMetadata {
    /// Provider identifier.
    pub provider: Provider,
    /// Human-readable name.
    pub display_name: String,
    /// Description.
    pub description: String,
    /// Documentation URL.
    pub docs_url: Option<String>,
    /// Terms of service URL.
    pub tos_url: Option<String>,
    /// Custom CSS selectors (overrides).
    pub selectors: HashMap<String, String>,
}

impl ProviderMetadata {
    /// Create metadata for a provider.
    #[allow(dead_code)]
    pub fn new(provider: Provider) -> Self {
        match provider {
            #[cfg(feature = "grok")]
            Provider::Grok => Self {
                provider,
                display_name: "Grok".into(),
                description: "X.ai's conversational AI".into(),
                docs_url: Some("https://x.ai".into()),
                tos_url: Some("https://x.com/tos".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "claude")]
            Provider::Claude => Self {
                provider,
                display_name: "Claude".into(),
                description: "Anthropic's helpful AI assistant".into(),
                docs_url: Some("https://docs.anthropic.com".into()),
                tos_url: Some("https://www.anthropic.com/legal/consumer-terms".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "gemini")]
            Provider::Gemini => Self {
                provider,
                display_name: "Gemini".into(),
                description: "Google's multimodal AI".into(),
                docs_url: Some("https://ai.google.dev".into()),
                tos_url: Some("https://policies.google.com/terms".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "chatgpt")]
            Provider::ChatGpt => Self {
                provider,
                display_name: "ChatGPT".into(),
                description: "OpenAI's conversational AI".into(),
                docs_url: Some("https://platform.openai.com/docs".into()),
                tos_url: Some("https://openai.com/policies/terms-of-use".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "perplexity")]
            Provider::Perplexity => Self {
                provider,
                display_name: "Perplexity".into(),
                description: "AI-powered search engine".into(),
                docs_url: Some("https://docs.perplexity.ai".into()),
                tos_url: Some("https://www.perplexity.ai/tos".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "notebooklm")]
            Provider::NotebookLm => Self {
                provider,
                display_name: "NotebookLM".into(),
                description: "Google's AI research assistant".into(),
                docs_url: Some("https://notebooklm.google.com".into()),
                tos_url: Some("https://policies.google.com/terms".into()),
                selectors: HashMap::new(),
            },
            #[cfg(feature = "kaggle")]
            Provider::Kaggle => Self {
                provider,
                display_name: "Kaggle".into(),
                description: "Dataset search and catalog".into(),
                docs_url: Some("https://www.kaggle.com/docs".into()),
                tos_url: Some("https://www.kaggle.com/terms".into()),
                selectors: HashMap::new(),
            },
        }
    }
}
