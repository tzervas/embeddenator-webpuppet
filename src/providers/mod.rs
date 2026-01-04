//! Provider trait and implementations for AI web UIs.

mod traits;

#[cfg(feature = "claude")]
pub mod claude;
#[cfg(feature = "gemini")]
pub mod gemini;
#[cfg(feature = "grok")]
pub mod grok;
#[cfg(feature = "chatgpt")]
pub mod chatgpt;
#[cfg(feature = "perplexity")]
pub mod perplexity;
#[cfg(feature = "notebooklm")]
pub mod notebooklm;
#[cfg(feature = "kaggle")]
pub mod kaggle;

pub use traits::{Provider, ProviderCapabilities, ProviderTrait};

#[cfg(feature = "claude")]
pub use claude::ClaudeProvider;
#[cfg(feature = "gemini")]
pub use gemini::GeminiProvider;
#[cfg(feature = "grok")]
pub use grok::GrokProvider;
#[cfg(feature = "chatgpt")]
pub use chatgpt::ChatGptProvider;
#[cfg(feature = "perplexity")]
pub use perplexity::PerplexityProvider;
#[cfg(feature = "notebooklm")]
pub use notebooklm::NotebookLmProvider;
#[cfg(feature = "kaggle")]
pub use kaggle::KaggleProvider;
