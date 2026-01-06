//! Claude (Anthropic) provider implementation.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::ClaudeConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Claude web UI provider.
pub struct ClaudeProvider {
    config: ClaudeConfig,
}

impl ClaudeProvider {
    /// Create a new Claude provider with default config.
    pub fn new() -> Self {
        Self {
            config: ClaudeConfig::default(),
        }
    }

    /// Create a new Claude provider with custom config.
    pub fn with_config(config: ClaudeConfig) -> Self {
        Self { config }
    }

    /// Navigate to Claude chat interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete streaming.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // Wait for the streaming indicator to disappear
        // Claude shows a blinking cursor while generating
        session
            .wait_for_element_hidden("div.cursor-blink", Duration::from_secs(120))
            .await
            .map_err(|_| Error::Timeout(120_000))?;

        // Additional wait for response stabilization
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
}

impl Default for ClaudeProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for ClaudeProvider {
    fn provider(&self) -> Provider {
        Provider::Claude
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: true,
            file_upload: true,
            code_execution: false, // Claude doesn't execute code in browser
            web_search: false,
            max_context: Some(200_000), // Claude 3 has 200k context
            models: vec![
                "claude-3-opus".into(),
                "claude-3-sonnet".into(),
                "claude-3-haiku".into(),
            ],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        // Check for the presence of the chat input, which indicates logged in
        let url = session.current_url().await?;

        // If we're on the login page, not authenticated
        if url.contains("/login") {
            return Ok(false);
        }

        // Check for chat input element
        session.element_exists(&self.config.input_selector).await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to login page
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Claude uses Google/email authentication
        // We need to wait for manual login if 2FA is enabled
        tracing::info!("Waiting for manual authentication to Claude...");
        tracing::info!("Please complete the login in the browser window.");

        // Wait for redirect to chat page (indicates successful login)
        session
            .wait_for_url_contains("/chat", Duration::from_secs(300))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "claude".into(),
                reason: "Login timeout - please complete authentication manually".into(),
            })?;

        // Verify we're authenticated
        if !self.is_authenticated(session).await? {
            return Err(Error::AuthenticationFailed {
                provider: "claude".into(),
                reason: "Authentication verification failed".into(),
            });
        }

        // Save cookies for future sessions
        session.save_cookies().await?;

        tracing::info!("Successfully authenticated to Claude");
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

        // Handle attachments if any
        if !request.attachments.is_empty() && self.config.file_input_selector.is_some() {
            let selector = self.config.file_input_selector.as_ref().unwrap();
            let mut paths = Vec::new();

            for attachment in &request.attachments {
                let temp_dir = std::env::temp_dir().join("webpuppet_uploads");
                std::fs::create_dir_all(&temp_dir)?;
                let file_path = temp_dir.join(&attachment.name);
                std::fs::write(&file_path, &attachment.data)?;
                paths.push(file_path);
            }

            session.upload_files(selector, &paths).await?;

            // Wait for upload to complete (indicator)
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Find and focus the input element
        session
            .click(&self.config.input_selector)
            .await
            .map_err(|_| Error::ElementNotFound {
                selector: self.config.input_selector.clone(),
            })?;

        // Type the prompt
        // Claude uses a contenteditable div, so we need to set innerHTML or use keyboard
        session
            .type_text(&self.config.input_selector, &request.message)
            .await
            .map_err(|e| Error::Browser(e.to_string()))?;

        // Small delay to ensure text is entered
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Click send button
        session
            .click(&self.config.submit_selector)
            .await
            .map_err(|_| Error::ElementNotFound {
                selector: self.config.submit_selector.clone(),
            })?;

        // Wait for response to complete
        self.wait_for_response(session).await?;

        // Extract the response
        let response_text = self.extract_response(session).await?;

        Ok(PromptResponse {
            text: response_text,
            provider: Provider::Claude,
            conversation_id: session.conversation_id().cloned(),
            timestamp: chrono::Utc::now(),
            tokens_used: None, // Web UI doesn't expose token counts
            metadata: Default::default(),
        })
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Navigate to new chat URL
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Wait for page to load
        self.wait_ready(session).await?;

        // Extract conversation ID from URL
        let url = session.current_url().await?;
        let conversation_id = url.split('/').next_back().unwrap_or("unknown").to_string();

        Ok(conversation_id)
    }

    async fn continue_conversation(
        &self,
        session: &Session,
        conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Navigate to specific conversation
        let url = format!("https://claude.ai/chat/{}", conversation_id);
        session
            .navigate(&url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Send the prompt
        self.send_prompt(session, request).await
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        // Wait for input element to be present and interactive
        session
            .wait_for_element(&self.config.input_selector, Duration::from_secs(30))
            .await
            .map_err(|_| Error::Timeout(30_000))?;

        Ok(())
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
        // Get all response divs (last one is the most recent)
        let responses = session
            .query_all(&self.config.response_selector)
            .await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))?;

        if responses.is_empty() {
            return Err(Error::ExtractionFailed("No response found".into()));
        }

        // Get the last response's text content
        let last_response = responses.last().unwrap();
        let text = session
            .get_text_content(last_response)
            .await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))?;

        Ok(text)
    }

    async fn check_rate_limit(&self, session: &Session) -> Result<Option<Duration>> {
        // Check for rate limit message
        let rate_limit_selector = "div[data-testid='rate-limit-message']";

        if session.element_exists(rate_limit_selector).await? {
            // Claude typically shows "Please wait before sending another message"
            // Default to 60 second wait
            return Ok(Some(Duration::from_secs(60)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_capabilities() {
        let provider = ClaudeProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.vision);
        assert!(caps.file_upload);
        assert_eq!(caps.max_context, Some(200_000));
    }

    #[test]
    fn test_claude_provider_id() {
        let provider = ClaudeProvider::new();
        assert_eq!(provider.provider(), Provider::Claude);
    }
}
