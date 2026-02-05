//! WebPuppet - main automation orchestrator with mandatory security screening.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::credentials::CredentialStore;
use crate::display::DisplayMode;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderTrait};
use crate::ratelimit::RateLimiter;
use crate::security::pipeline::{PipelineConfig, PipelineResult, SecurityPipeline};
use crate::security::proxy::McpSecurityProxy;
use crate::security::screening::{ContentScreener, ScreeningConfig, ScreeningResult};
use crate::security::Direction;
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

/// Main WebPuppet orchestrator with integrated security pipeline.
///
/// All prompts are screened through the security pipeline by default.
/// Input is screened for injection attacks before sending to providers.
/// Output is screened for PII, secrets, and content manipulation before
/// being returned to the caller.
pub struct WebPuppet {
    config: Config,
    credentials: Arc<CredentialStore>,
    sessions: Arc<RwLock<HashMap<Provider, Session>>>,
    providers: HashMap<Provider, Arc<dyn ProviderTrait>>,
    rate_limiter: Arc<RateLimiter>,
    /// Legacy content screener (for backward compatibility).
    screener: Arc<ContentScreener>,
    /// Unified security pipeline (mandatory).
    pipeline: Arc<SecurityPipeline>,
    /// MCP security proxy for tool call routing enforcement.
    mcp_proxy: Arc<McpSecurityProxy>,
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

    /// Send a prompt to a provider with mandatory security screening.
    ///
    /// Both the input (prompt) and output (response) are screened through
    /// the security pipeline. Input is checked for injection attacks;
    /// output is checked for PII, secrets, and content manipulation.
    ///
    /// Returns the response along with the pipeline screening results
    /// for both input and output.
    pub async fn prompt(
        &self,
        provider: Provider,
        request: PromptRequest,
    ) -> Result<PromptResponse> {
        // Screen input through the security pipeline
        let input_screening = self.pipeline.screen_input(&request.message);
        if !input_screening.is_allowed() {
            tracing::warn!(
                "Input to {} BLOCKED by security pipeline: {} finding(s), risk={:.2}",
                provider,
                input_screening.findings.len(),
                input_screening.risk_score,
            );
            return Err(Error::SecurityBlocked {
                direction: "input".into(),
                findings: input_screening.findings.len(),
                risk_score: input_screening.risk_score,
            });
        }

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
        let mut response = if let Some(ref conv_id) = request.conversation_id {
            provider_impl
                .continue_conversation(&session, conv_id, &request)
                .await?
        } else {
            provider_impl.send_prompt(&session, &request).await?
        };

        // Screen output through the security pipeline
        let output_screening = self.pipeline.screen_output(&response.text);
        if !output_screening.is_allowed() {
            tracing::warn!(
                "Response from {} BLOCKED by security pipeline: {} finding(s), risk={:.2}",
                provider,
                output_screening.findings.len(),
                output_screening.risk_score,
            );
            return Err(Error::SecurityBlocked {
                direction: "output".into(),
                findings: output_screening.findings.len(),
                risk_score: output_screening.risk_score,
            });
        }

        // Apply redacted content if available
        if let Some(ref redacted) = output_screening.redacted_content {
            response.text = redacted.clone();
        }

        Ok(response)
    }

    /// Send a prompt with full screening results returned.
    ///
    /// Like [`prompt`], but also returns the pipeline results for both
    /// input and output screening so callers can inspect findings.
    pub async fn prompt_screened(
        &self,
        provider: Provider,
        request: PromptRequest,
    ) -> Result<(PromptResponse, ScreeningResult)> {
        let mut response = self.prompt(provider, request).await?;

        // Also run legacy content screener for backward compatibility
        let screening = self.screener.screen(&response.text);

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

    /// Get the legacy content screener for manual use.
    pub fn screener(&self) -> &ContentScreener {
        &self.screener
    }

    /// Get the unified security pipeline.
    pub fn pipeline(&self) -> &SecurityPipeline {
        &self.pipeline
    }

    /// Get the MCP security proxy.
    pub fn mcp_proxy(&self) -> &McpSecurityProxy {
        &self.mcp_proxy
    }

    /// Screen arbitrary content through the security pipeline.
    pub fn screen(&self, content: &str, direction: Direction) -> PipelineResult {
        self.pipeline.screen(content, direction)
    }

    /// Send a prompt to the best available provider.
    pub async fn prompt_any(&self, request: PromptRequest) -> Result<PromptResponse> {
        let providers = self.providers();

        if providers.is_empty() {
            return Err(Error::Config("No providers configured".into()));
        }

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
    pipeline_config: Option<PipelineConfig>,
    providers: Vec<Provider>,
    display_mode: Option<DisplayMode>,
    headless: Option<bool>,
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

    /// Set headless mode (legacy, prefer `display_mode`).
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = Some(headless);
        self
    }

    /// Set display mode: Headless, HeadsUp, or Dashboard.
    pub fn display_mode(mut self, mode: DisplayMode) -> Self {
        self.display_mode = Some(mode);
        self
    }

    /// Set custom screening configuration (legacy ContentScreener).
    pub fn with_screening_config(mut self, config: ScreeningConfig) -> Self {
        self.screening_config = Some(config);
        self
    }

    /// Set custom security pipeline configuration.
    pub fn with_pipeline_config(mut self, config: PipelineConfig) -> Self {
        self.pipeline_config = Some(config);
        self
    }

    /// Build the WebPuppet instance.
    pub async fn build(self) -> Result<WebPuppet> {
        let mut config = self.config.unwrap_or_default();

        // Apply display mode
        if let Some(mode) = self.display_mode {
            config.browser.display_mode = mode;
            config.browser.headless = mode.is_headless();
            config.browser.dual_head = mode.is_dual_head();
        } else if let Some(headless) = self.headless {
            config.browser.headless = headless;
            if headless {
                config.browser.display_mode = DisplayMode::Headless;
            } else {
                config.browser.display_mode = DisplayMode::HeadsUp;
            }
        }

        // Apply pipeline config if provided
        if let Some(pipeline_config) = self.pipeline_config {
            config.security.pipeline = pipeline_config;
        }

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
                #[allow(unreachable_patterns)]
                _ => {
                    tracing::debug!("Provider {:?} not enabled via features", provider);
                }
            }
        }

        // Initialize legacy content screener
        let screener = Arc::new(
            self.screening_config
                .map(ContentScreener::with_config)
                .unwrap_or_default(),
        );

        // Initialize security pipeline (mandatory)
        let pipeline = Arc::new(SecurityPipeline::with_config(
            config.security.pipeline.clone(),
        ));

        // Initialize MCP security proxy
        let mcp_proxy = Arc::new(McpSecurityProxy::new(pipeline.clone()));

        // Register configured MCP servers
        for server_config in &config.security.mcp_servers {
            mcp_proxy.register_server(server_config.clone()).await;
        }

        tracing::info!(
            display_mode = %config.browser.display_mode,
            screening_enforced = config.security.enforce_screening,
            mcp_servers = config.security.mcp_servers.len(),
            "WebPuppet initialized with integrated security pipeline"
        );

        Ok(WebPuppet {
            config,
            credentials,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            providers,
            rate_limiter,
            screener,
            pipeline,
            mcp_proxy,
        })
    }
}

/// Convenience function for quick prompts (with mandatory screening).
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

    let response = puppet
        .prompt(provider, PromptRequest::new(message))
        .await?;

    puppet.close().await?;

    Ok(response)
}
