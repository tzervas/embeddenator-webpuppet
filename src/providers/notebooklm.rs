//! NotebookLM (Google) provider implementation.
//!
//! NotebookLM is unique - it's a research assistant that works with uploaded sources.
//! This provider handles source management and Q&A against those sources.

use async_trait::async_trait;
use std::time::Duration;

use crate::config::NotebookLmConfig;
use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// NotebookLM web UI provider (Google).
pub struct NotebookLmProvider {
    config: NotebookLmConfig,
}

impl NotebookLmProvider {
    /// Create a new NotebookLM provider with default config.
    pub fn new() -> Self {
        Self {
            config: NotebookLmConfig::default(),
        }
    }

    /// Create a new NotebookLM provider with custom config.
    pub fn with_config(config: NotebookLmConfig) -> Self {
        Self { config }
    }

    /// Navigate to NotebookLM interface.
    async fn navigate_to_chat(&self, session: &Session) -> Result<()> {
        session
            .navigate(&self.config.chat_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))
    }

    /// Wait for response to complete.
    async fn wait_for_response(&self, session: &Session) -> Result<()> {
        // NotebookLM shows loading while generating
        session
            .wait_for_element_hidden(r#"div[data-testid="loading"]"#, Duration::from_secs(120))
            .await
            .map_err(|_| Error::Timeout(120_000))?;

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

impl Default for NotebookLmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for NotebookLmProvider {
    fn provider(&self) -> Provider {
        Provider::NotebookLm
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: true,
            vision: false,     // Works with uploaded docs, not images
            file_upload: true, // Primary feature - source uploads
            code_execution: false,
            web_search: false,          // Searches within uploaded sources only
            max_context: Some(500_000), // Very large context for source analysis
            models: vec!["notebooklm".into()],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        let url = session.current_url().await?;

        // Google sign-in
        if url.contains("accounts.google.com") {
            return Ok(false);
        }

        // Check for NotebookLM interface
        session.element_exists(&self.config.input_selector).await
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to NotebookLM
        session
            .navigate(&self.config.login_url)
            .await
            .map_err(|e| Error::Navigation(e.to_string()))?;

        // Check if already authenticated
        if self.is_authenticated(session).await? {
            tracing::info!("Already authenticated to NotebookLM");
            return Ok(());
        }

        tracing::info!("Waiting for Google authentication to NotebookLM...");
        tracing::info!("Please complete the login in the browser window.");

        // Wait for redirect to NotebookLM
        session
            .wait_for_url_contains("notebooklm.google.com", Duration::from_secs(300))
            .await
            .map_err(|_| Error::AuthenticationFailed {
                provider: "notebooklm".into(),
                reason: "Login timeout - please complete Google authentication".into(),
            })?;

        tokio::time::sleep(Duration::from_secs(2)).await;
        if !self.is_authenticated(session).await? {
            return Err(Error::AuthenticationFailed {
                provider: "notebooklm".into(),
                reason: "Authentication verification failed".into(),
            });
        }

        session.save_cookies().await?;
        tracing::info!("Successfully authenticated to NotebookLM");
        Ok(())
    }

    async fn send_prompt(
        &self,
        session: &Session,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        self.wait_ready(session).await?;

        // Handle attachments if any
        if !request.attachments.is_empty() {
            if let Some(ref selector) = self.config.file_input_selector {
                let mut paths = Vec::new();
                for attachment in &request.attachments {
                    let temp_dir = std::env::temp_dir().join("webpuppet_uploads_notebooklm");
                    std::fs::create_dir_all(&temp_dir)
                        .map_err(|e| Error::Browser(e.to_string()))?;
                    let file_path = temp_dir.join(&attachment.name);
                    std::fs::write(&file_path, &attachment.data)
                        .map_err(|e| Error::Browser(e.to_string()))?;
                    paths.push(file_path);
                }

                session.upload_files(selector, &paths).await?;
                // Give NotebookLM a moment to process the upload
                tokio::time::sleep(Duration::from_secs(3)).await;
            } else {
                tracing::warn!(
                    "NotebookLM provider does not have a file input selector configured"
                );
            }
        }

        // Type the question
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
            provider: Provider::NotebookLm,
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
        self.send_prompt(session, request).await
    }

    async fn new_conversation(&self, session: &Session) -> Result<String> {
        // Navigate to NotebookLM home to create new notebook
        self.navigate_to_chat(session).await?;
        Ok(uuid::Uuid::new_v4().to_string())
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
        session
            .get_text_content(last_response)
            .await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))
    }

    async fn check_rate_limit(&self, _session: &Session) -> Result<Option<Duration>> {
        // NotebookLM doesn't have obvious rate limits
        Ok(None)
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        // Wait for the notebook interface to be ready
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
    fn test_notebooklm_capabilities() {
        let provider = NotebookLmProvider::new();
        let caps = provider.capabilities();

        assert!(caps.conversation);
        assert!(caps.file_upload); // Primary feature
        assert!(!caps.web_search); // Only searches sources
        assert_eq!(caps.max_context, Some(500_000)); // Large context
    }
}
