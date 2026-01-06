# embeddenator-webpuppet

Browser automation library for AI chat web interfaces.

This library provides programmatic control of Chrome/Chromium browsers to interact with AI chat providers through their web UIs. It handles authentication, session management, and response extraction for research and development workflows.

> ⚠️ **Important**: This automates third-party web interfaces. Users must comply with provider terms of service and applicable laws.

## Overview

`embeddenator-webpuppet` enables automated interactions with AI chat interfaces when API access is unavailable, restricted, or when specific web-only features are needed. The library handles:

- Browser session management and authentication
- Rate limiting and anti-detection measures
- Response extraction and content sanitization
- Multi-provider workflow orchestration

## Features

- **Multi-Provider Support**: Claude, Grok, Gemini, ChatGPT, Perplexity, NotebookLM
- **Browser Automation**: Chrome/Chromium control via chromiumoxide
- **Session Persistence**: Secure credential and cookie storage using OS keyring
- **Rate Limiting**: Configurable request throttling with exponential backoff
- **Content Security**: Response screening for common security threats
- **Permission Controls**: Domain allowlisting and operation restrictions

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
embeddenator-webpuppet = { version = "0.1.0-alpha.2", features = ["all-providers"] }
```

**Note**: This is pre-release software. APIs may change between versions.

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

| Provider | Conversation | File Upload | Notes |
|----------|--------------|-------------|-------|
| Claude | ✅ | ✅ | Anthropic's Claude models |
| Grok | ✅ | ❌ | X.ai's Grok models |
| Gemini | ✅ | ✅ | Google's Gemini models |
| ChatGPT | ✅ | ✅ | OpenAI's GPT models |
| Perplexity | ✅ | ✅ | Perplexity AI search |
| NotebookLM | ✅ | ✅ | Google's NotebookLM |

## Security

- **Credentials**: Stored in OS keyring, never in plaintext files
- **Browser profiles**: Sandboxed per-provider in local data directory
- **Rate limiting**: Prevents abuse detection with humanized delays
- **Session isolation**: Each provider has independent browser context
- **Response screening**: Automatic filtering of security threats

## Limitations

- **Pre-release software**: APIs may change without notice
- **Provider UI Dependencies**: Changes to provider web interfaces may break functionality
- **Feature Parity**: Not all provider-specific features are supported uniformly
- **Authentication**: Requires manual login for initial setup
- **Rate Limits**: Subject to provider-imposed usage restrictions

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

## System Requirements

- **Rust**: 1.75.0 or newer (latest stable recommended)
- **Browser**: Chrome 120+, Chromium 120+, or Brave 1.60+ (auto-detected)
- **Operating Systems**:
  - **Linux**: Modern distributions (Ubuntu 22.04+, Fedora 38+, Arch Linux current)
  - **macOS**: 13.0 Ventura or newer (Intel/Apple Silicon)
  - **Windows**: Windows 11 22H2 or newer
- **Keyring**: OS-native credential storage (keyring, Keychain, Windows Credential Manager)
- **Container Support**: Available with `--no-sandbox` configuration

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
