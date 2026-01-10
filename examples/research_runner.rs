//! Research runner for multi-provider AI queries.
//!
//! Run with: cargo run --example research_runner -- --provider claude --prompt io-uring
//!
//! This uses the browser-based webpuppet system (already authenticated).

use std::io::Write;
use std::path::PathBuf;

use webpuppet::{PromptRequest, Provider, ScreeningConfig, WebPuppet};

#[derive(Debug)]
#[allow(dead_code)]
struct ResearchConfig {
    provider: Provider,
    prompt_name: String,
    output_dir: PathBuf,
    headless: bool,
}

fn load_prompt(name: &str) -> Result<String, std::io::Error> {
    let prompts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".github/prompts");

    let prompt_file = prompts_dir.join(format!("research-{}.prompt.md", name));
    std::fs::read_to_string(&prompt_file)
}

fn parse_provider(s: &str) -> Option<Provider> {
    match s.to_lowercase().as_str() {
        "claude" | "anthropic" => Some(Provider::Claude),
        "grok" | "x" | "xai" => Some(Provider::Grok),
        "gemini" | "google" => Some(Provider::Gemini),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    // Parse args
    let mut provider = Provider::Claude;
    let mut prompt_name = "io-uring".to_string();
    let mut headless = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--provider" | "-p" => {
                i += 1;
                if let Some(p) = parse_provider(&args[i]) {
                    provider = p;
                }
            }
            "--prompt" => {
                i += 1;
                prompt_name = args[i].clone();
            }
            "--visible" => {
                headless = false;
            }
            "--help" | "-h" => {
                println!("Research Runner for Embeddenator");
                println!();
                println!("Usage: research_runner [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -p, --provider <NAME>   Provider: claude, grok, gemini");
                println!("  --prompt <NAME>         Prompt name (e.g., io-uring, safe-simd)");
                println!("  --visible               Show browser window");
                println!("  -h, --help              Show this help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    println!("🔬 Research Runner");
    println!("   Provider: {}", provider);
    println!("   Prompt: {}", prompt_name);
    println!("   Headless: {}", headless);
    println!();

    // Load prompt
    let prompt_content = match load_prompt(&prompt_name) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "❌ Failed to load prompt 'research-{}.prompt.md': {}",
                prompt_name, e
            );
            eprintln!();
            eprintln!("Available prompts in .github/prompts/:");
            eprintln!("  - io-uring");
            eprintln!("  - safe-simd");
            eprintln!("  - unsafe-audit");
            eprintln!("  - differential-storage");
            eprintln!("  - dynamic-scheduling");
            return Err(e.into());
        }
    };

    println!("📄 Loaded prompt ({} bytes)", prompt_content.len());

    // Configure screening
    let screening_config = ScreeningConfig {
        detect_prompt_injection: true,
        detect_zero_width: true,
        detect_encoded: true,
        risk_threshold: 0.8, // Slightly permissive for research
        ..Default::default()
    };

    // Create puppet
    println!("🌐 Launching browser...");
    let puppet = WebPuppet::builder()
        .with_provider(provider)
        .headless(headless)
        .with_screening_config(screening_config)
        .build()
        .await?;

    // Check authentication
    println!("🔐 Checking authentication...");
    puppet.authenticate(provider).await?;
    println!("✅ Authenticated with {}", provider);

    // Send prompt
    println!("📤 Sending research prompt...");
    let (response, screening) = puppet
        .prompt_screened(provider, PromptRequest::new(prompt_content))
        .await?;

    // Report screening results
    println!();
    println!("🔒 Security Screening:");
    println!("   Risk Score: {:.2}", screening.risk_score);
    println!("   Passed: {}", screening.passed);
    if !screening.issues.is_empty() {
        println!("   Issues:");
        for issue in &screening.issues {
            println!("     - {:?}", issue);
        }
    }

    // Save response
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("docs/research/responses");
    std::fs::create_dir_all(&output_dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let output_file = output_dir.join(format!(
        "{}_{}_research-{}.md",
        timestamp, provider, prompt_name
    ));

    let mut file = std::fs::File::create(&output_file)?;
    writeln!(file, "# Research Response: {}", prompt_name)?;
    writeln!(file)?;
    writeln!(file, "**Provider**: {}", provider)?;
    writeln!(file, "**Timestamp**: {}", response.timestamp)?;
    writeln!(file, "**Risk Score**: {:.2}", screening.risk_score)?;
    writeln!(file)?;
    writeln!(file, "---")?;
    writeln!(file)?;
    writeln!(file, "{}", response.text)?;

    println!();
    println!("💾 Response saved to: {}", output_file.display());
    println!();
    println!("📝 Response Preview:");
    println!("─────────────────────────────────────────────");
    // Print first 500 chars
    let preview: String = response.text.chars().take(500).collect();
    println!("{}", preview);
    if response.text.len() > 500 {
        println!("... ({} more characters)", response.text.len() - 500);
    }
    println!("─────────────────────────────────────────────");

    // Cleanup
    puppet.close().await?;

    Ok(())
}
