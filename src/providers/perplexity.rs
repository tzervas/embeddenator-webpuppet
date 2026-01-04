//! Perplexity AI provider implementation.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::PerplexityConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Perplexity AI web UI provider.
pub struct PerplexityProvider {
    config: PerplexityConfig,
}

impl PerplexityProvider {
    /// Create a new Perplexity provider with default config.
    pub fn new() -> Self {
        Self {
            config: PerplexityConfig::default(),
        }
    }

    /// Create a new Perplexity provider with custom config.
    pub fn with_config(config: PerplexityConfig) -> Self {
        Self { config }
    }

    /// Navigate to Perplexity chat interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // Perplexity shows a loading indicator while searching/generating
        session
            .wait_for_element_hidden(
                r#"div[data-testid="loading-indicator"]"#,
                Duration::from_secs(120),
            )
            .await
            .map_err(|_| Error::Timeout(120_000))?;

        // Wait for sources to load
        tokio::time::sleep(Duration::from_millis(1000)).await;
        Ok(())
    }

    /// Wait for page to be ready.
    async fn wait_ready(&self, session: &Session) -> Result<()> {
        session
            .wait_for_element(&self.config.input_selector, Duration::from_secs(30))
            .await
            .map_err(|_| Error::Timeout(30_000))?;
        Ok(())
    }
}

impl Default for PerplexityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for PerplexityProvider {
    fn provider(&self) -> Provider {
        Provider::Perplexity
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: false, // Perplexity doesn't support image input in free tier
            file_upload: true, // Pro tier supports files
            code_execution: false,
            web_search: true, // Primary feature - real-time search
            max_context: Some(32_000),
            models: vec![
                "default".into(),
                "sonar-pro".into(),
                "sonar".into(),
            ],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        let url = session.current_url().await?;

        // Perplexity works without login, but check for pro features
        if url.contains("/sign-in") {
            return Ok(false);
        }

        // Check for search input
        session
            .element_exists(&self.config.input_selector)
            .await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to Perplexity
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Perplexity can work without auth
        if self.is_authenticated(session).await? {
            tracing::info!("Perplexity ready (may be unauthenticated)");
            return Ok(());
        }

        tracing::info!("Waiting for manual authentication to Perplexity...");

        // Wait for the input to be available
        session
            .wait_for_element(&self.config.input_selector, Duration::from_secs(60))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "perplexity".into(),
                reason: "Could not find input - page may not have loaded".into(),
            })?;

        tracing::info!("Perplexity ready");
        Ok(())
    }

    async fn send_prompt(
        &self,
        session: &Session,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Ensure we're on the search page
        self.navigate_to_chat(session).await?;
        self.wait_ready(session).await?;

        // Type the query
        session
            .type_text(&self.config.input_selector, &request.message)
            .await?;

        // Submit
        session.press_key("Enter").await?;

        // Wait for response (including sources)
        self.wait_for_response(session).await?;

        // Extract response
        let text = self.extract_response(session).await?;

        Ok(PromptResponse {
            text,
            provider: Provider::Perplexity,
            conversation_id: session.conversation_id().cloned(),
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            metadata: Default::default(),
        })
    }

    async fn continue_conversation(
        &self,
        session: &Session,
        _conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Perplexity maintains context in thread
        self.send_prompt(session, request).await
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Navigate to new search
        session.navigate(&self.config.chat_url).await?;
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
        // Get the answer content
        let responses = session
            .query_all(&self.config.response_selector)
            .await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))?;

        if responses.is_empty() {
            return Err(Error::ExtractionFailed("No response found".into()));
        }

        let last_response = responses.last().unwrap();
        let text = session
            .get_text_content(last_response)
            .await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))?;

        // Also try to get sources
        let sources = session
            .query_all(r#"a[data-testid="source-link"]"#)
            .await
            .ok();

        let mut result = text;
        if let Some(sources) = sources {
            if !sources.is_empty() {
                result.push_str("\n\n**Sources:**\n");
                // Note: We'd need to extract href from each source
            }
        }

        Ok(result)
    }

    async fn check_rate_limit(&self, session: &Session) -> Result<Option<Duration>> {
        // Check for rate limit indicators
        if session
            .element_exists("div:contains('rate limit')")
            .await
            .unwrap_or(false)
        {
            return Ok(Some(Duration::from_secs(60)));
        }

        Ok(None)
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        // Wait for the search interface to be ready
        session.wait_for_element(&self.config.ready_selector, Duration::from_secs(30)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perplexity_capabilities() {
        let provider = PerplexityProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.web_search); // Primary feature
        assert!(!caps.vision); // Not in free tier
    }
}
