//! Kaggle provider implementation (dataset search/catalog via web UI).
//!
//! This provider treats `PromptRequest.message` as a dataset search query and returns
//! a list of matching dataset pages.

use async_trait::async_trait;
use std::collections::HashSet;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::providers::{Provider, ProviderCapabilities, ProviderTrait};
use crate::puppet::{PromptRequest, PromptResponse};
use crate::session::Session;

/// Kaggle dataset search provider.
pub struct KaggleProvider;

impl KaggleProvider {
    /// Create a new Kaggle provider.
    pub fn new() -> Self {
        Self
    }

    fn search_url(query: &str) -> String {
        // Kaggle supports `?search=...` on /datasets.
        let encoded = urlencoding::encode(query);
        format!("https://www.kaggle.com/datasets?search={}", encoded)
    }

    async fn wait_ready_inner(&self, session: &Session) -> Result<()> {
        // Kaggle is SPA-ish; content can be async.
        // We keep this intentionally loose to avoid brittle selectors.
        session.wait_for_element("body", Duration::from_secs(30)).await?;
        tokio::time::sleep(Duration::from_millis(750)).await;
        Ok(())
    }

    async fn extract_dataset_links(&self, session: &Session, limit: usize) -> Result<Vec<(String, String)>> {
        #[derive(serde::Deserialize)]
        struct LinkItem {
            title: String,
            url: String,
        }

        let script = r#"(() => {
            const base = 'https://www.kaggle.com';
            const anchors = Array.from(document.querySelectorAll('a[href^="/datasets/"]'));

            const normalize = (href) => {
                if (!href) return null;
                const clean = href.split('#')[0].split('?')[0];
                if (!clean.startsWith('/datasets/')) return null;
                const parts = clean.split('/').filter(Boolean);
                // Expected: ['datasets', '<owner>', '<dataset>', ...]
                if (parts.length < 3) return null;
                if (parts[0] !== 'datasets') return null;
                // Exclude listing/search pages.
                if (parts.length === 1) return null;
                if (clean === '/datasets') return null;
                return clean;
            };

            const results = [];
            const seen = new Set();
            for (const a of anchors) {
                const href = normalize(a.getAttribute('href'));
                if (!href) continue;
                const abs = base + href;
                if (seen.has(abs)) continue;

                // Title: prefer aria-label; else textContent.
                const title = (a.getAttribute('aria-label') || a.textContent || '').trim().replace(/\s+/g, ' ');
                if (!title) continue;

                seen.add(abs);
                results.push({ title, url: abs });
                if (results.length >= 25) break;
            }
            return results;
        })()"#;

        let mut items: Vec<LinkItem> = session.evaluate(script).await
            .map_err(|e| Error::ExtractionFailed(e.to_string()))?;

        // De-dupe and cap.
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for item in items.drain(..) {
            if out.len() >= limit {
                break;
            }
            if !seen.insert(item.url.clone()) {
                continue;
            }
            out.push((item.title, item.url));
        }

        Ok(out)
    }

    fn format_results(query: &str, results: &[(String, String)]) -> String {
        if results.is_empty() {
            return format!("No Kaggle datasets found for query: {}", query);
        }

        let mut out = String::new();
        out.push_str(&format!("Kaggle dataset results for: {}\n\n", query));
        for (title, url) in results {
            out.push_str(&format!("- {}: {}\n", title, url));
        }

        out.push_str("\nNote: This provider currently returns dataset page links/metadata only (no automated downloads).\n");
        out
    }
}

impl Default for KaggleProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderTrait for KaggleProvider {
    fn provider(&self) -> Provider {
        Provider::Kaggle
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            conversation: false,
            vision: false,
            file_upload: false,
            code_execution: false,
            web_search: true,
            max_context: None,
            models: vec!["dataset-search".into()],
        }
    }

    async fn is_authenticated(&self, session: &Session) -> Result<bool> {
        // Kaggle dataset catalog is browsable without login.
        // If Kaggle redirects to a sign-in flow, treat as unauthenticated.
        let url = session.current_url().await.unwrap_or_default();
        if url.contains("/account/login") {
            return Ok(false);
        }

        Ok(true)
    }

    async fn authenticate(&self, session: &mut Session) -> Result<()> {
        // Navigate to Kaggle. If the user wants login for gated datasets,
        // they can do it manually in visible mode.
        session.navigate("https://www.kaggle.com").await?;
        self.wait_ready_inner(session).await?;
        Ok(())
    }

    async fn send_prompt(&self, session: &Session, request: &PromptRequest) -> Result<PromptResponse> {
        let query = request.message.trim();
        if query.is_empty() {
            return Err(Error::Config("Kaggle search query is empty".into()));
        }

        session.navigate(&Self::search_url(query)).await?;
        self.wait_ready_inner(session).await?;

        let results = self.extract_dataset_links(session, 10).await?;
        let text = Self::format_results(query, &results);

        Ok(PromptResponse {
            text,
            provider: Provider::Kaggle,
            conversation_id: session.conversation_id().cloned(),
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            metadata: Default::default(),
        })
    }

    async fn new_conversation(&self, _session: &Session) -> Result<String> {
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn continue_conversation(
        &self,
        session: &Session,
        _conversation_id: &str,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        self.send_prompt(session, request).await
    }

    async fn current_url(&self, session: &Session) -> Result<String> {
        session.current_url().await
    }

    async fn wait_ready(&self, session: &Session) -> Result<()> {
        self.wait_ready_inner(session).await
    }

    async fn extract_response(&self, session: &Session) -> Result<String> {
        // Best-effort: return the page title plus URL.
        let title = session.get_title().await.unwrap_or_else(|_| "Kaggle".into());
        let url = session.current_url().await.unwrap_or_default();
        Ok(format!("{}\n{}", title, url))
    }

    async fn check_rate_limit(&self, _session: &Session) -> Result<Option<Duration>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kaggle_capabilities() {
        let provider = KaggleProvider::new();
        let caps = provider.capabilities();
        assert!(caps.web_search);
        assert!(!caps.conversation);
        assert!(!caps.file_upload);
    }
}
