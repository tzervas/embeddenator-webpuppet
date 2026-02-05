//! ChatGPT (OpenAI) provider implementation.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::ChatGptConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// ChatGPT web UI provider (OpenAI).
pub struct ChatGptProvider {
    config: ChatGptConfig,
}

impl ChatGptProvider {
    /// Create a new ChatGPT provider with default config.
    pub fn new() -> Self {
        Self {
            config: ChatGptConfig::default(),
        }
    }

    /// Create a new ChatGPT provider with custom config.
    pub fn with_config(config: ChatGptConfig) -> Self {
        Self { config }
    }

    /// Navigate to ChatGPT chat interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // ChatGPT shows a stop button while generating
        session
            .wait_for_element_hidden(
                r#"button[data-testid="stop-button"]"#,
                Duration::from_secs(180),
            )
            .await
            .map_err(|_| Error::Timeout(180_000))?;

        // Additional wait for response stabilization
        tokio::time::sleep(Duration::from_millis(500)).await;
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

impl Default for ChatGptProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for ChatGptProvider {
    fn provider(&self) -> Provider {
        Provider::ChatGpt
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: true,
            file_upload: true,
            code_execution: true,       // Code interpreter
            web_search: true,           // Browse with Bing
            max_context: Some(128_000), // GPT-4 Turbo context
            models: vec![
                "gpt-4o".into(),
                "gpt-4o-mini".into(),
                "gpt-4-turbo".into(),
                "gpt-4".into(),
                "o1-preview".into(),
                "o1-mini".into(),
            ],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        let url = session.current_url().await?;

        // If on login page, not authenticated
        if url.contains("/auth/login") || url.contains("login.openai.com") {
            return Ok(false);
        }

        // Check for chat interface element
        session.element_exists(&self.config.input_selector).await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to ChatGPT
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Check if already authenticated
        if self.is_authenticated(session).await? {
            tracing::info!("Already authenticated to ChatGPT");
            return Ok(());
        }

        // OpenAI uses complex OAuth flow
        tracing::info!("Waiting for manual authentication to ChatGPT...");
        tracing::info!("Please complete the login in the browser window.");

        // Wait for redirect to chat interface
        session
            .wait_for_url_contains("/chat", Duration::from_secs(300))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "chatgpt".into(),
                reason: "Login timeout - please complete authentication manually".into(),
            })?;

        // Verify we're authenticated
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !self.is_authenticated(session).await? {
            return Err(Error::AuthenticationFailed {
                provider: "chatgpt".into(),
                reason: "Authentication verification failed".into(),
            });
        }

        // Save cookies for future sessions
        session.save_cookies().await?;

        tracing::info!("Successfully authenticated to ChatGPT");
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

        // Handle attachments
        if !request.attachments.is_empty() {
            if let Some(selector) = self.config.file_input_selector.as_ref() {
                let mut paths = Vec::new();

                for attachment in &request.attachments {
                    let temp_dir = std::env::temp_dir().join("webpuppet_uploads_chatgpt");
                    std::fs::create_dir_all(&temp_dir)?;
                    let file_path = temp_dir.join(&attachment.name);
                    std::fs::write(&file_path, &attachment.data)?;
                    paths.push(file_path);
                }

                session.upload_files(selector, &paths).await?;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        // Type the prompt
        session
            .type_text(&self.config.input_selector, &request.message)
            .await?;

        // Submit
        session.press_key("Enter").await?;

        // Wait for response
        self.wait_for_response(session).await?;

        // Extract response
        let text = self.extract_response(session).await?;

        Ok(PromptResponse {
            text,
            provider: Provider::ChatGpt,
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
        // ChatGPT maintains conversation in the same tab
        self.send_prompt(session, request).await
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Click "New Chat" button
        session
            .click(r#"button[data-testid="new-chat-button"]"#)
            .await
            .ok();

        // Navigate to new chat URL
        session.navigate(&self.config.chat_url).await?;

        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
        // Get all response elements
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
        // Check for rate limit messages
        let rate_limit_selectors = [
            "div.rate-limit-message",
            "div:contains('rate limit')",
            "div:contains('too many requests')",
        ];

        for selector in &rate_limit_selectors {
            if session.element_exists(selector).await.unwrap_or(false) {
                return Ok(Some(Duration::from_secs(60)));
            }
        }

        Ok(None)
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        // Wait for the main chat interface to be ready
        session
            .wait_for_element(&self.config.ready_selector, Duration::from_secs(30))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chatgpt_capabilities() {
        let provider = ChatGptProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.vision);
        assert!(caps.file_upload);
        assert!(caps.code_execution);
        assert!(caps.web_search);
        assert_eq!(caps.max_context, Some(128_000));
    }
}
