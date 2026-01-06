//! Grok (X.ai) provider implementation.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::GrokConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Grok web UI provider (X.ai via Twitter/X).
pub struct GrokProvider {
    config: GrokConfig,
}

impl GrokProvider {
    /// Create a new Grok provider with default config.
    pub fn new() -> Self {
        Self {
            config: GrokConfig::default(),
        }
    }

    /// Create a new Grok provider with custom config.
    pub fn with_config(config: GrokConfig) -> Self {
        Self { config }
    }

    /// Navigate to Grok chat interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // Grok shows a typing indicator while generating
        session
            .wait_for_element_hidden(
                r#"div[data-testid="grokTypingIndicator"]"#,
                Duration::from_secs(120),
            )
            .await
            .map_err(|_| Error::Timeout(120_000))?;

        // Additional wait for response stabilization
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
}

impl Default for GrokProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for GrokProvider {
    fn provider(&self) -> Provider {
        Provider::Grok
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: true,
            file_upload: true, // Grok supports file uploads
            code_execution: false,
            web_search: true, // Grok has real-time web access
            max_context: Some(128_000), // Grok 2 has 128k context
            models: vec![
                "grok-2".into(),
                "grok-2-mini".into(),
            ],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        let url = session.current_url().await?;

        // If redirected to login, not authenticated
        if url.contains("/login") || url.contains("/i/flow/login") {
            return Ok(false);
        }

        // Check for Grok interface element
        session
            .element_exists(&self.config.input_selector)
            .await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to Grok (will redirect to X login if not authenticated)
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Check if already authenticated
        if self.is_authenticated(session).await? {
            tracing::info!("Already authenticated to Grok");
            return Ok(());
        }

        // X uses complex OAuth flow with potential 2FA
        tracing::info!("Waiting for manual authentication to X/Grok...");
        tracing::info!("Please complete the login in the browser window.");
        tracing::info!("If you have 2FA enabled, you'll need to approve it.");

        // Wait for redirect to Grok interface (indicates successful login)
        session
            .wait_for_url_contains("/i/grok", Duration::from_secs(300))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "grok".into(),
                reason: "Login timeout - please complete authentication manually".into(),
            })?;

        // Verify we're authenticated
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !self.is_authenticated(session).await? {
            return Err(Error::AuthenticationFailed {
                provider: "grok".into(),
                reason: "Authentication verification failed".into(),
            });
        }

        // Save cookies for future sessions
        session.save_cookies().await?;

        tracing::info!("Successfully authenticated to Grok");
        Ok(())
    }

    async fn send_prompt(
        &self,
        session: &Session,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Ensure we're on the chat page
        self.navigate_to_chat(session).await?;
        self.wait_ready(session).await?;

        // Find and focus the input element
        session
            .click(&self.config.input_selector)
            .await
            .map_err(|_| Error::ElementNotFound {
                selector: self.config.input_selector.clone(),
            })?;

        // Type the prompt
        session
            .type_text(&self.config.input_selector, &request.message)
            .await
            .map_err(|e| Error::Browser(e.to_string()))?;

        // Handle attachments if any
        if !request.attachments.is_empty() {
            if let Some(ref selector) = self.config.file_input_selector {
                let mut paths = Vec::new();
                for attachment in &request.attachments {
                    let temp_dir = std::env::temp_dir().join("webpuppet_uploads_grok");
                    std::fs::create_dir_all(&temp_dir).map_err(|e| Error::Browser(e.to_string()))?;
                    let file_path = temp_dir.join(&attachment.name);
                    std::fs::write(&file_path, &attachment.data).map_err(|e| Error::Browser(e.to_string()))?;
                    paths.push(file_path);
                }

                session.upload_files(selector, &paths).await?;
                // Give Grok a moment to process the upload
                tokio::time::sleep(Duration::from_secs(2)).await;
            } else {
                tracing::warn!("Grok provider does not have a file input selector configured");
            }
        }

        // Small delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Click send button or press Enter
        session
            .click(&self.config.submit_selector)
            .await
            .map_err(|_| Error::ElementNotFound {
                selector: self.config.submit_selector.clone(),
            })?;

        // Wait for response
        self.wait_for_response(session).await?;

        // Extract the response
        let response_text = self.extract_response(session).await?;

        Ok(PromptResponse {
            text: response_text,
            provider: Provider::Grok,
            conversation_id: session.conversation_id().cloned(),
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            metadata: Default::default(),
        })
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Grok doesn't have explicit conversation IDs in the URL
        // Navigate to fresh Grok page
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        self.wait_ready(session).await?;

        // Generate a local conversation ID
        let conversation_id = uuid::Uuid::new_v4().to_string();
        Ok(conversation_id)
    }

    async fn continue_conversation(
        &self,
        session: &Session,
        _conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Grok maintains conversation state on the page
        // Just send the next prompt without navigation
        self.send_prompt(session, request).await
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        session
            .wait_for_element(&self.config.input_selector, Duration::from_secs(30))
            .await
            .map_err(|_| Error::Timeout(30_000))?;

        Ok(())
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
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

        Ok(text)
    }

    async fn check_rate_limit(&self, session: &Session) -> Result<Option<Duration>> {
        // Check for X/Grok rate limit messages
        let rate_limit_selectors = [
            "div[data-testid='rate-limit']",
            "span:contains('rate limit')",
            "div.rate-limit-warning",
        ];

        for selector in &rate_limit_selectors {
            if session.element_exists(selector).await.unwrap_or(false) {
                // X typically uses 15-minute rate limit windows
                return Ok(Some(Duration::from_secs(900)));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grok_capabilities() {
        let provider = GrokProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.vision);
        assert!(caps.web_search); // Grok has real-time access
        assert!(!caps.file_upload);
        assert_eq!(caps.max_context, Some(128_000));
    }

    #[test]
    fn test_grok_provider_id() {
        let provider = GrokProvider::new();
        assert_eq!(provider.provider(), Provider::Grok);
    }
}
