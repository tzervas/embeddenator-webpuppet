//! Gemini (Google) provider implementation.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::GeminiConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Gemini web UI provider (Google).
pub struct GeminiProvider {
    config: GeminiConfig,
}

impl GeminiProvider {
    /// Create a new Gemini provider with default config.
    pub fn new() -> Self {
        Self {
            config: GeminiConfig::default(),
        }
    }

    /// Create a new Gemini provider with custom config.
    pub fn with_config(config: GeminiConfig) -> Self {
        Self { config }
    }

    /// Navigate to Gemini chat interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // Gemini shows a streaming animation while generating
        // Wait for the "Stop generating" button to disappear
        session
            .wait_for_element_hidden(
                r#"button[aria-label="Stop generating"]"#,
                Duration::from_secs(180),
            )
            .await
            .map_err(|_| Error::Timeout(180_000))?;

        // Additional wait for response stabilization
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
}

impl Default for GeminiProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for GeminiProvider {
    fn provider(&self) -> Provider {
        Provider::Gemini
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: true,
            file_upload: true,
            code_execution: true, // Gemini can execute code in sandbox
            web_search: true,     // Gemini has web access
            max_context: Some(1_000_000), // Gemini 1.5 Pro has 1M context
            models: vec![
                "gemini-1.5-pro".into(),
                "gemini-1.5-flash".into(),
                "gemini-2.0-flash".into(),
            ],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        let url = session.current_url().await?;

        // Check for Google account selection or login
        if url.contains("accounts.google.com") {
            return Ok(false);
        }

        // Check for Gemini interface
        session
            .element_exists(&self.config.input_selector)
            .await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to Gemini
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Check if already authenticated
        tokio::time::sleep(Duration::from_secs(2)).await;
        if self.is_authenticated(session).await? {
            tracing::info!("Already authenticated to Gemini");
            return Ok(());
        }

        // Google uses OAuth with potential 2FA
        tracing::info!("Waiting for manual authentication to Google/Gemini...");
        tracing::info!("Please complete the login in the browser window.");
        tracing::info!("Select your Google account and approve any 2FA prompts.");

        // Wait for redirect to Gemini app
        session
            .wait_for_url_contains("gemini.google.com/app", Duration::from_secs(300))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "gemini".into(),
                reason: "Login timeout - please complete authentication manually".into(),
            })?;

        // Verify we're authenticated
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !self.is_authenticated(session).await? {
            return Err(Error::AuthenticationFailed {
                provider: "gemini".into(),
                reason: "Authentication verification failed".into(),
            });
        }

        // Save cookies for future sessions
        session.save_cookies().await?;

        tracing::info!("Successfully authenticated to Gemini");
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

        // Gemini uses a custom rich-textarea element
        // We need to find and interact with it properly
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
                    let temp_dir = std::env::temp_dir().join("webpuppet_uploads_gemini");
                    std::fs::create_dir_all(&temp_dir).map_err(|e| Error::Browser(e.to_string()))?;
                    let file_path = temp_dir.join(&attachment.name);
                    std::fs::write(&file_path, &attachment.data).map_err(|e| Error::Browser(e.to_string()))?;
                    paths.push(file_path);
                }

                session.upload_files(selector, &paths).await?;
                // Give Gemini a moment to process the upload
                tokio::time::sleep(Duration::from_secs(2)).await;
            } else {
                tracing::warn!("Gemini provider does not have a file input selector configured");
            }
        }

        // Small delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Click send button
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
            provider: Provider::Gemini,
            conversation_id: session.conversation_id().cloned(),
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            metadata: Default::default(),
        })
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Click "New chat" button
        let new_chat_selector = r#"button[aria-label="New chat"]"#;
        
        if session.element_exists(new_chat_selector).await? {
            session.click(new_chat_selector).await.ok();
        } else {
            // Navigate to fresh page
            session
                .navigate(&self.config.chat_url)
                .await
                .map_err(|e| Error::Navigation(e.to_string()))?;
        }

        self.wait_ready(session).await?;

        // Extract conversation ID from URL if present
        let url = session.current_url().await?;
        let conversation_id = url
            .split('/')
            .last()
            .filter(|s| !s.is_empty() && *s != "app")
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(conversation_id)
    }

    async fn continue_conversation(
        &self,
        session: &Session,
        conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // Check if URL contains conversation ID
        let url = session.current_url().await?;
        
        if !url.contains(conversation_id) {
            // Navigate to conversation
            // Note: Gemini may not support direct conversation URLs
            tracing::warn!("Gemini conversation continuation may not preserve context");
        }

        self.send_prompt(session, request).await
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        // Wait for the input element
        session
            .wait_for_element(&self.config.input_selector, Duration::from_secs(30))
            .await
            .map_err(|_| Error::Timeout(30_000))?;

        Ok(())
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
        // Gemini uses custom message-content elements
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
        // Check for Gemini rate limit indicators
        let rate_limit_selectors = [
            "div.rate-limit-error",
            "div:contains('quota exceeded')",
            "div:contains('try again later')",
        ];

        for selector in &rate_limit_selectors {
            if session.element_exists(selector).await.unwrap_or(false) {
                // Google typically uses per-minute quotas
                return Ok(Some(Duration::from_secs(60)));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemini_capabilities() {
        let provider = GeminiProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.vision);
        assert!(caps.file_upload);
        assert!(caps.code_execution);
        assert!(caps.web_search);
        assert_eq!(caps.max_context, Some(1_000_000));
    }

    #[test]
    fn test_gemini_provider_id() {
        let provider = GeminiProvider::new();
        assert_eq!(provider.provider(), Provider::Gemini);
    }
}
