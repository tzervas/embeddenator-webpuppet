//! WebPuppet - main automation orchestrator.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::credentials::CredentialStore;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderTrait};
use crate::ratelimit::RateLimiter;
use crate::security::{ContentScreener, ScreeningConfig, ScreeningResult};
use crate::session::Session;

#[cfg(feature = "chatgpt")]
use crate::providers::ChatGptProvider;
#[cfg(feature = "claude")]
use crate::providers::ClaudeProvider;
#[cfg(feature = "gemini")]
use crate::providers::GeminiProvider;
#[cfg(feature = "grok")]
use crate::providers::GrokProvider;
#[cfg(feature = "kaggle")]
use crate::providers::KaggleProvider;
#[cfg(feature = "notebooklm")]
use crate::providers::NotebookLmProvider;
#[cfg(feature = "perplexity")]
use crate::providers::PerplexityProvider;

/// Request to send to an AI provider.
#[derive(Debug, Clone, Default)]
pub struct PromptRequest {
    /// The message to send.
    pub message: String,
    /// Optional system context/instructions.
    pub context: Option<String>,
    /// Continue existing conversation (if supported).
    pub conversation_id: Option<String>,
    /// Attached files (if supported).
    pub attachments: Vec<Attachment>,
    /// Custom metadata.
    pub metadata: HashMap<String, String>,
}

impl PromptRequest {
    /// Create a new prompt request.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Default::default()
        }
    }

    /// Add context to the request.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Continue an existing conversation.
    pub fn with_conversation(mut self, id: impl Into<String>) -> Self {
        self.conversation_id = Some(id.into());
        self
    }

    /// Add an attachment.
    pub fn with_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

/// File attachment for prompts.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime_type: String,
    /// File content.
    pub data: Vec<u8>,
}

/// Response from an AI provider.
#[derive(Debug, Clone)]
pub struct PromptResponse {
    /// The response text.
    pub text: String,
    /// Provider that generated the response.
    pub provider: Provider,
    /// Conversation ID (if available).
    pub conversation_id: Option<String>,
    /// When the response was received.
    pub timestamp: DateTime<Utc>,
    /// Approximate tokens used (if available).
    pub tokens_used: Option<u32>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

/// Main WebPuppet orchestrator.
pub struct WebPuppet {
    config: Config,
    credentials: Arc<CredentialStore>,
    sessions: Arc<RwLock<HashMap<Provider, Session>>>,
    providers: HashMap<Provider, Arc<dyn ProviderTrait>>,
    rate_limiter: Arc<RateLimiter>,
    screener: Arc<ContentScreener>,
}

impl WebPuppet {
    /// Create a new WebPuppet builder.
    pub fn builder() -> WebPuppetBuilder {
        WebPuppetBuilder::default()
    }

    /// Create a new WebPuppet with default configuration.
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
    }

    /// Get available providers.
    pub fn providers(&self) -> Vec<Provider> {
        self.providers.keys().copied().collect()
    }

    /// Get the declared capabilities for a provider.
    ///
    /// Note: This is currently based on the provider implementation's static
    /// `capabilities()` declaration (not runtime UI detection).
    pub fn provider_capabilities(
        &self,
        provider: Provider,
    ) -> Option<crate::providers::ProviderCapabilities> {
        self.providers.get(&provider).map(|p| p.capabilities())
    }

    /// Check if a provider is available.
    pub fn has_provider(&self, provider: Provider) -> bool {
        self.providers.contains_key(&provider)
    }

    /// Get a session for a provider, creating one if needed.
    pub async fn get_session(&self, provider: Provider) -> Result<Session> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&provider) {
            return Ok(session.clone());
        }
        drop(sessions);

        // Create new session
        let session = Session::new(&self.config, provider, self.credentials.clone()).await?;

        let mut sessions = self.sessions.write().await;
        sessions.insert(provider, session.clone());

        Ok(session)
    }

    /// Authenticate with a provider.
    pub async fn authenticate(&self, provider: Provider) -> Result<()> {
        let provider_impl = self
            .providers
            .get(&provider)
            .ok_or_else(|| Error::UnsupportedProvider(provider.to_string()))?;

        let mut session = self.get_session(provider).await?;

        if !provider_impl.is_authenticated(&session).await? {
            provider_impl.authenticate(&mut session).await?;
        }

        Ok(())
    }

    /// Send a prompt to a provider.
    pub async fn prompt(
        &self,
        provider: Provider,
        request: PromptRequest,
    ) -> Result<PromptResponse> {
        let provider_impl = self
            .providers
            .get(&provider)
            .ok_or_else(|| Error::UnsupportedProvider(provider.to_string()))?;

        // Apply rate limiting
        self.rate_limiter.wait(provider).await;

        let session = self.get_session(provider).await?;

        // Ensure authenticated
        if !provider_impl.is_authenticated(&session).await? {
            return Err(Error::SessionExpired(provider.to_string()));
        }

        // Check for rate limits from provider
        if let Some(delay) = provider_impl.check_rate_limit(&session).await? {
            tracing::warn!("Rate limited by {}, waiting {:?}", provider, delay);
            tokio::time::sleep(delay).await;
        }

        // Send prompt
        let response = if let Some(ref conv_id) = request.conversation_id {
            provider_impl
                .continue_conversation(&session, conv_id, &request)
                .await?
        } else {
            provider_impl.send_prompt(&session, &request).await?
        };

        Ok(response)
    }

    /// Send a prompt and screen the response for security issues.
    ///
    /// This method automatically filters out:
    /// - Invisible text (1pt fonts, zero-width characters)
    /// - Background-matching text
    /// - Potential prompt injection attempts
    /// - Encoded payloads
    pub async fn prompt_screened(
        &self,
        provider: Provider,
        request: PromptRequest,
    ) -> Result<(PromptResponse, ScreeningResult)> {
        let mut response = self.prompt(provider, request).await?;

        // Screen the response
        let screening = self.screener.screen(&response.text);

        // Replace response text with sanitized version
        if !screening.passed {
            tracing::warn!(
                "Response from {} flagged with risk score {:.2}: {:?}",
                provider,
                screening.risk_score,
                screening
                    .issues
                    .iter()
                    .map(|i| format!("{:?}", i))
                    .collect::<Vec<_>>()
            );
        }

        // Use sanitized text
        response.text = screening.sanitized.clone();

        Ok((response, screening))
    }

    /// Send a prompt to the best available provider with screening.
    pub async fn prompt_any_screened(
        &self,
        request: PromptRequest,
    ) -> Result<(PromptResponse, ScreeningResult)> {
        let providers = self.providers();

        if providers.is_empty() {
            return Err(Error::Config("No providers configured".into()));
        }

        let mut last_error = None;
        for provider in providers {
            match self.prompt_screened(provider, request.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!("Provider {} failed: {}", provider, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Config("All providers failed".into())))
    }

    /// Get the content screener for manual use.
    pub fn screener(&self) -> &ContentScreener {
        &self.screener
    }

    /// Send a prompt to the best available provider.
    pub async fn prompt_any(&self, request: PromptRequest) -> Result<PromptResponse> {
        let providers = self.providers();

        if providers.is_empty() {
            return Err(Error::Config("No providers configured".into()));
        }

        // Try providers in order until one succeeds
        let mut last_error = None;
        for provider in providers {
            match self.prompt(provider, request.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!("Provider {} failed: {}", provider, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Config("All providers failed".into())))
    }

    /// Start a new conversation with a provider.
    pub async fn new_conversation(&self, provider: Provider) -> Result<String> {
        let provider_impl = self
            .providers
            .get(&provider)
            .ok_or_else(|| Error::UnsupportedProvider(provider.to_string()))?;

        let session = self.get_session(provider).await?;
        provider_impl.new_conversation(&session).await
    }

    /// Close all browser sessions.
    pub async fn close(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        for (_, session) in sessions.drain() {
            session.close().await.ok();
        }
        Ok(())
    }
}

/// Builder for WebPuppet.
#[derive(Default)]
pub struct WebPuppetBuilder {
    config: Option<Config>,
    screening_config: Option<ScreeningConfig>,
    providers: Vec<Provider>,
    headless: bool,
}

impl WebPuppetBuilder {
    /// Set custom configuration.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Enable a specific provider.
    pub fn with_provider(mut self, provider: Provider) -> Self {
        if !self.providers.contains(&provider) {
            self.providers.push(provider);
        }
        self
    }

    /// Enable all available providers.
    pub fn with_all_providers(mut self) -> Self {
        self.providers = Provider::all();
        self
    }

    /// Set headless mode.
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Set custom screening configuration.
    pub fn with_screening_config(mut self, config: ScreeningConfig) -> Self {
        self.screening_config = Some(config);
        self
    }

    /// Build the WebPuppet instance.
    pub async fn build(self) -> Result<WebPuppet> {
        let mut config = self.config.unwrap_or_default();
        config.browser.headless = self.headless;

        let credentials = Arc::new(CredentialStore::new()?);
        let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limit));

        // Initialize providers
        let mut providers: HashMap<Provider, Arc<dyn ProviderTrait>> = HashMap::new();

        let enabled_providers = if self.providers.is_empty() {
            Provider::all()
        } else {
            self.providers
        };

        for provider in enabled_providers {
            match provider {
                #[cfg(feature = "grok")]
                Provider::Grok => {
                    providers.insert(provider, Arc::new(GrokProvider::new()));
                }
                #[cfg(feature = "claude")]
                Provider::Claude => {
                    providers.insert(provider, Arc::new(ClaudeProvider::new()));
                }
                #[cfg(feature = "gemini")]
                Provider::Gemini => {
                    providers.insert(provider, Arc::new(GeminiProvider::new()));
                }
                #[cfg(feature = "chatgpt")]
                Provider::ChatGpt => {
                    providers.insert(provider, Arc::new(ChatGptProvider::new()));
                }
                #[cfg(feature = "perplexity")]
                Provider::Perplexity => {
                    providers.insert(provider, Arc::new(PerplexityProvider::new()));
                }
                #[cfg(feature = "notebooklm")]
                Provider::NotebookLm => {
                    providers.insert(provider, Arc::new(NotebookLmProvider::new()));
                }
                #[cfg(feature = "kaggle")]
                Provider::Kaggle => {
                    providers.insert(provider, Arc::new(KaggleProvider::new()));
                }
                // Handle providers not enabled by features
                #[allow(unreachable_patterns)]
                _ => {
                    tracing::debug!("Provider {:?} not enabled via features", provider);
                }
            }
        }

        // Initialize content screener
        let screener = Arc::new(
            self.screening_config
                .map(ContentScreener::with_config)
                .unwrap_or_default(),
        );

        Ok(WebPuppet {
            config,
            credentials,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            providers,
            rate_limiter,
            screener,
        })
    }
}

/// Convenience function for quick prompts.
pub async fn quick_prompt(
    provider: Provider,
    message: impl Into<String>,
) -> Result<PromptResponse> {
    let puppet = WebPuppet::builder()
        .with_provider(provider)
        .headless(true)
        .build()
        .await?;

    puppet.authenticate(provider).await?;

    let response = puppet.prompt(provider, PromptRequest::new(message)).await?;

    puppet.close().await?;

    Ok(response)
}
