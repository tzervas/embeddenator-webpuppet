# embeddenator-webpuppet

Self-hosted browser automation for AI/chat web UIs and a small set of web tools.

This crate drives a local Chrome/Chromium/Brave browser (via `chromiumoxide`) to interact with provider UIs. It is intended for research/benchmarks and “operator in the loop” workflows (login, 2FA, captchas).

> ⚠️ This automates third‑party web UIs. Use responsibly and comply with applicable terms/policies.

## Overview

`embeddenator-webpuppet` provides puppeteer-like functionality for automating interactions with AI chat interfaces through their web UIs, bypassing API requirements. This is useful for:

- Research and experimentation without API costs
- Accessing features not available via API
- Comparing responses across providers
- Batch processing prompts across multiple AI systems

## Features

- **Providers/tools**: Claude, Grok, Gemini, ChatGPT, Perplexity, NotebookLM, Kaggle (dataset search)
- **Headless browser automation**: Chrome/Chromium via chromiumoxide
- **Session management**: Persistent auth with cookie handling
- **Rate limiting**: Respect provider limits, avoid detection
- **Secure credential storage**: OS keyring integration (never plaintext)
- **Security screening**: Filter invisible text, prompt injections, encoded payloads (sanitizes responses)
- **Permission guardrails**: Default-deny + domain allowlist; blocks destructive operations; HTTPS-only in secure mode

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
embeddenator-webpuppet = { version = "0.1", features = ["all-providers"] }
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `chromium` (default) | Use chromiumoxide for Chrome/Chromium |
| `firefox` | Use fantoccini/WebDriver for Firefox |
| `grok` | Enable Grok (X.ai) provider |
| `claude` | Enable Claude (Anthropic) provider |
| `gemini` | Enable Gemini (Google) provider |
| `chatgpt` | Enable ChatGPT (OpenAI) provider |
| `perplexity` | Enable Perplexity provider |
| `notebooklm` | Enable NotebookLM provider |
| `kaggle` | Enable Kaggle dataset search tool |
| `all-providers` | Enable all AI providers |

## Usage

### Basic Prompt

```rust
use embeddenator_webpuppet::{WebPuppet, Provider, PromptRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create puppet with Claude provider
    let puppet = WebPuppet::builder()
        .with_provider(Provider::Claude)
        .headless(false)  // Set to true after initial auth
        .build()
        .await?;

    // First run: authenticate (opens browser for manual login)
    puppet.authenticate(Provider::Claude).await?;

    // Send prompt
    let response = puppet.prompt(Provider::Claude, PromptRequest {
        message: "Explain the difference between async and threading".into(),
        ..Default::default()
    }).await?;

    println!("Response: {}", response.text);
    
    puppet.close().await?;
    Ok(())
}
```

### Multi-Provider Query

```rust
use embeddenator_webpuppet::{WebPuppet, Provider, PromptRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let puppet = WebPuppet::builder()
        .with_all_providers()
        .headless(true)
        .build()
        .await?;

    let prompt = PromptRequest::new("What is the capital of France?");

    // Query each provider
    for provider in puppet.providers() {
        match puppet.prompt(provider, prompt.clone()).await {
            Ok(response) => {
                println!("[{}]: {}", provider, response.text);
            }
            Err(e) => {
                eprintln!("[{}] Error: {}", provider, e);
            }
        }
    }

    puppet.close().await?;
    Ok(())
}
```

### Conversation Mode

```rust
use embeddenator_webpuppet::{WebPuppet, Provider, PromptRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let puppet = WebPuppet::builder()
        .with_provider(Provider::Claude)
        .build()
        .await?;

    // Start a new conversation
    let conv_id = puppet.new_conversation(Provider::Claude).await?;

    // First message
    let r1 = puppet.prompt(Provider::Claude, 
        PromptRequest::new("My name is Alice")
            .with_conversation(conv_id.clone())
    ).await?;

    // Follow-up (maintains context)
    let r2 = puppet.prompt(Provider::Claude,
        PromptRequest::new("What's my name?")
            .with_conversation(conv_id)
    ).await?;

    println!("Response: {}", r2.text); // Should mention "Alice"
    
    puppet.close().await?;
    Ok(())
}
```

## Authentication Flow

On first use with each provider:

1. Browser opens to provider's login page
2. Complete manual login (supports 2FA)
3. Cookies are saved to OS keyring
4. Subsequent runs use saved session

```rust
// Headless mode only works after initial authentication
let puppet = WebPuppet::builder()
    .with_provider(Provider::Claude)
    .headless(false)  // Must be false for first login
    .build()
    .await?;

puppet.authenticate(Provider::Claude).await?;
// Browser window opens, complete login manually
// After success, cookies are persisted

// Future runs can use headless mode
```

## Configuration

```rust
use embeddenator_webpuppet::{Config, WebPuppet};
use std::time::Duration;

let config = Config::builder()
    .headless(true)
    .timeout(Duration::from_secs(120))
    .rate_limit(30)  // requests per minute
    .no_sandbox()    // Required for containers
    .build();

let puppet = WebPuppet::builder()
    .with_config(config)
    .with_all_providers()
    .build()
    .await?;
```

## Provider Capabilities

Capabilities are declared per provider in code (not runtime UI detection yet). For programmatic access, use `WebPuppet::provider_capabilities()`.

| Provider | Conversation | Vision | File Upload | Code Execution | Web Search | Max Context |
|----------|--------------|--------|-------------|----------------|------------|-------------|
| Claude | ✅ | ✅ | ✅ | ❌ | ❌ | 200k |
| Grok | ✅ | ✅ | ❌ | ❌ | ✅ | 128k |
| Gemini | ✅ | ✅ | ✅ | ✅ | ✅ | 1M |
| ChatGPT | ✅ | ✅ | ✅ | ✅ | ✅ | 128k |
| Perplexity | ✅ | ❌ | ✅ | ❌ | ✅ | 32k |
| NotebookLM | ✅ | ❌ | ✅ | ❌ | ✅ | 500k |
| Kaggle | ❌ | ❌ | ❌ | ❌ | ✅ | — |

## Security

- **Credentials**: Stored in OS keyring, never in plaintext files
- **Browser profiles**: Sandboxed per-provider in local data directory
- **Rate limiting**: Prevents abuse detection with humanized delays
- **Session isolation**: Each provider has independent browser context
- **Response screening**: Automatic filtering of security threats

## Current Limitations

- Provider feature parity is not complete: model/tool toggles and other UI features are not uniformly detected/controlled across providers yet.
- Kaggle support is currently dataset search/catalog only (no automated downloads).

### Content Security Screening

The library includes built-in security screening for AI responses:

```rust
use embeddenator_webpuppet::{WebPuppet, Provider, PromptRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let puppet = WebPuppet::builder()
        .with_provider(Provider::Claude)
        .build()
        .await?;

    // Use screened prompt for automatic security filtering
    let (response, screening) = puppet.prompt_screened(
        Provider::Claude,
        PromptRequest::new("Analyze this code")
    ).await?;

    if !screening.passed {
        eprintln!("⚠️ Security issues detected: {:?}", screening.issues);
    }

    // response.text is already sanitized
    println!("{}", response.text);
    
    puppet.close().await?;
    Ok(())
}
```

#### Detected Security Issues

| Issue Type | Description | Risk Level |
|------------|-------------|------------|
| `InvisibleText` | 1pt fonts, zero-opacity text | High |
| `BackgroundMatchingText` | Same color as background | High |
| `ZeroWidthCharacters` | U+200B, U+FEFF, etc. | Medium |
| `HomoglyphAttack` | Unicode lookalikes | Medium |
| `PromptInjection` | "Ignore previous instructions" | Critical |
| `EncodedPayload` | Base64/hex encoded content | Medium |
| `HiddenElement` | CSS display:none, visibility:hidden | High |
| `CodeInjection` | Script injection attempts | Critical |

#### Custom Screening Configuration

```rust
use embeddenator_webpuppet::{WebPuppet, ScreeningConfig};

let config = ScreeningConfig {
    min_visible_font_size: 8.0,  // Stricter than default 6pt
    detect_prompt_injection: true,
    detect_homoglyphs: true,
    risk_threshold: 0.5,  // Lower = more strict
    custom_injection_patterns: vec![
        r"(?i)reveal.*api.*key".into(),
    ],
    ..Default::default()
};

let puppet = WebPuppet::builder()
    .with_screening_config(config)
    .build()
    .await?;
```

## Architecture

```
embeddenator-webpuppet/
├── src/
│   ├── lib.rs          # Main exports
│   ├── config.rs       # Configuration types
│   ├── credentials.rs  # Keyring credential storage
│   ├── error.rs        # Error types
│   ├── puppet.rs       # Main orchestrator
│   ├── ratelimit.rs    # Rate limiting
│   ├── security.rs     # Content screening & prompt injection filtering
│   ├── session.rs      # Browser session management
│   └── providers/
│       ├── mod.rs      # Provider exports
│       ├── traits.rs   # ProviderTrait definition
│       ├── claude.rs   # Claude implementation
│       ├── gemini.rs   # Gemini implementation
│       └── grok.rs     # Grok implementation
```

## Requirements

- Chrome/Chromium browser (auto-detected, or specify path)
- Linux, macOS, or Windows with keyring support
- For containers: use `--no-sandbox` configuration

## Troubleshooting

### Session Expired

```rust
// Force re-authentication
puppet.authenticate(Provider::Claude).await?;
```

### Rate Limited

The library automatically handles rate limits with exponential backoff. If you're consistently hitting limits, increase the delay:

```rust
let config = Config::builder()
    .rate_limit(10)  // Lower requests/minute
    .build();
```

### Browser Not Found

```rust
use std::path::PathBuf;

let config = Config::builder()
    .executable_path(PathBuf::from("/usr/bin/chromium-browser"))
    .build();
```

## License

MIT License - See [LICENSE](../../LICENSE) for details.

## Disclaimer

This tool is for educational and research purposes only. Use of this tool to automate web interfaces may violate the terms of service of the respective providers. Users are responsible for ensuring their use complies with all applicable terms and laws.
