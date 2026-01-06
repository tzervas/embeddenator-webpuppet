//! Provider trait and implementations for AI web UIs.

mod traits;

#[cfg(feature = "chatgpt")]
pub mod chatgpt;
#[cfg(feature = "claude")]
pub mod claude;
#[cfg(feature = "gemini")]
pub mod gemini;
#[cfg(feature = "grok")]
pub mod grok;
#[cfg(feature = "kaggle")]
pub mod kaggle;
#[cfg(feature = "notebooklm")]
pub mod notebooklm;
#[cfg(feature = "perplexity")]
pub mod perplexity;

pub use traits::{Provider, ProviderCapabilities, ProviderTrait};

#[cfg(feature = "chatgpt")]
pub use chatgpt::ChatGptProvider;
#[cfg(feature = "claude")]
pub use claude::ClaudeProvider;
#[cfg(feature = "gemini")]
pub use gemini::GeminiProvider;
#[cfg(feature = "grok")]
pub use grok::GrokProvider;
#[cfg(feature = "kaggle")]
pub use kaggle::KaggleProvider;
#[cfg(feature = "notebooklm")]
pub use notebooklm::NotebookLmProvider;
#[cfg(feature = "perplexity")]
pub use perplexity::PerplexityProvider;
