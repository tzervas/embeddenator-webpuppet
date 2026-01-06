//! Browser session management with real chromiumoxide integration.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::handler::viewport::Viewport;
use chromiumoxide::page::Page;
use chromiumoxide::Element;
use futures::StreamExt;
use tokio::sync::RwLock;

use crate::browser::{BrowserDetector, BrowserType};
use crate::config::Config;
use crate::credentials::CredentialStore;
use crate::error::{Error, Result};
use crate::providers::Provider;
use crate::security::DataEncryption;

/// Browser session for a specific provider.
pub struct Session {
    provider: Provider,
    config: Config,
    #[allow(dead_code)]
    credentials: Arc<CredentialStore>,
    profile_dir: PathBuf,
    conversation_id: Option<String>,
    /// The actual browser instance
    browser: Arc<Browser>,
    /// The current page
    page: Arc<RwLock<Page>>,
    /// Secondary browser for monitoring (Dual Head mode)
    secondary_browser: Option<Arc<Browser>>,
    /// Secondary page for monitoring
    secondary_page: Option<Arc<RwLock<Page>>>,
    /// Whether browser is visible (non-headless)
    visible: bool,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            config: self.config.clone(),
            credentials: self.credentials.clone(),
            profile_dir: self.profile_dir.clone(),
            conversation_id: self.conversation_id.clone(),
            browser: self.browser.clone(),
            page: self.page.clone(),
            secondary_browser: self.secondary_browser.clone(),
            secondary_page: self.secondary_page.clone(),
            visible: self.visible,
        }
    }
}

impl Session {
    /// Create a new browser session for a provider.
    pub async fn new(
        config: &Config,
        provider: Provider,
        credentials: Arc<CredentialStore>,
    ) -> Result<Self> {
        // Determine profile directory
        let profile_dir = config
            .session
            .storage_dir
            .clone()
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("embeddenator-webpuppet")
            })
            .join(provider.name());

        // Ensure profile directory exists
        std::fs::create_dir_all(&profile_dir)?;

        // Find a browser to use
        let browser_install = Self::find_browser(config)?;
        
        tracing::info!(
            "Using {} browser at {:?}",
            browser_install.browser_type,
            browser_install.executable_path
        );

        // Build browser config
        let mut builder = BrowserConfig::builder()
            .chrome_executable(&browser_install.executable_path)
            .viewport(Viewport {
                width: config.browser.window_width,
                height: config.browser.window_height,
                device_scale_factor: None,
                emulating_mobile: false,
                is_landscape: false,
                has_touch: false,
            });

        // Set headless mode
        let visible = !config.browser.headless;
        if visible {
            builder = builder.with_head();
            tracing::info!("Browser will be visible (non-headless mode)");
        }

        // Use existing profile for auth persistence
        let user_data_dir = config
            .browser
            .user_data_dir
            .clone()
            .or_else(|| {
                // Use the browser's existing profile for auth
                if browser_install.user_data_dir.exists() {
                    Some(browser_install.user_data_dir.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| profile_dir.clone());

        builder = builder.user_data_dir(&user_data_dir);

        // Add extra args
        if !config.browser.sandbox {
            builder = builder.arg("--no-sandbox");
        }
        
        for arg in &config.browser.args {
            builder = builder.arg(arg);
        }

        // Disable automation detection
        builder = builder
            .arg("--disable-blink-features=AutomationControlled")
            .arg("--disable-features=IsolateOrigins,site-per-process")
            .arg("--disable-site-isolation-trials");

        let browser_config = builder.build().map_err(|e| Error::Browser(e.to_string()))?;

        // Launch primary browser
        let (browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| Error::Browser(format!("Failed to launch browser: {}", e)))?;

        // Spawn handler task for primary browser
        tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::debug!("Primary browser handler event: {:?}", e);
                }
            }
        });

        // Create initial page for primary browser
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| Error::Browser(format!("Failed to create page: {}", e)))?;

        // Handle Dual Head mode
        let mut secondary_browser = None;
        let mut secondary_page = None;

        if config.browser.dual_head {
            tracing::info!("Dual Head mode enabled. Launching secondary monitoring browser.");
            
            // Re-build config for secondary (visible) browser
            let mut sec_builder = BrowserConfig::builder()
                .chrome_executable(&browser_install.executable_path)
                .with_head() // Always visible for monitoring
                .viewport(Viewport {
                    width: config.browser.window_width,
                    height: config.browser.window_height,
                    device_scale_factor: None,
                    emulating_mobile: false,
                    is_landscape: false,
                    has_touch: false,
                });

            // Use a separate temp profile for secondary to avoid locking
            let sec_profile = profile_dir.join("monitoring_head");
            std::fs::create_dir_all(&sec_profile)?;
            sec_builder = sec_builder.user_data_dir(&sec_profile);

            // Add extra args
            if !config.browser.sandbox {
                sec_builder = sec_builder.arg("--no-sandbox");
            }
            
            for arg in &config.browser.args {
                sec_builder = sec_builder.arg(arg);
            }

            let sec_config = sec_builder.build().map_err(|e| Error::Browser(e.to_string()))?;

            // Launch secondary browser
            let (sec_browser, mut sec_handler) = Browser::launch(sec_config)
                .await
                .map_err(|e| Error::Browser(format!("Failed to launch secondary browser: {}", e)))?;

            // Spawn handler task for secondary
            tokio::spawn(async move {
                while let Some(event) = sec_handler.next().await {
                    if let Err(e) = event {
                        tracing::debug!("Secondary browser handler event: {:?}", e);
                    }
                }
            });

            let sec_page = sec_browser
                .new_page("about:blank")
                .await
                .map_err(|e| Error::Browser(format!("Failed to create secondary page: {}", e)))?;

            secondary_browser = Some(Arc::new(sec_browser));
            secondary_page = Some(Arc::new(RwLock::new(sec_page)));
        }

        tracing::info!("Browser session created for {}", provider);

        Ok(Self {
            provider,
            config: config.clone(),
            credentials,
            profile_dir,
            conversation_id: None,
            browser: Arc::new(browser),
            page: Arc::new(RwLock::new(page)),
            secondary_browser,
            secondary_page,
            visible,
        })
    }

    /// Find a suitable browser to use.
    fn find_browser(config: &Config) -> Result<crate::browser::BrowserInstallation> {
        // Check if user specified a browser
        if let Some(ref path) = config.browser.executable_path {
            if path.exists() {
                let path_str = path.to_string_lossy().to_lowercase();
                let browser_type = if path_str.contains("brave") {
                    BrowserType::Brave
                } else if path_str.contains("chromium") {
                    BrowserType::Chromium
                } else if path_str.contains("edge") {
                    BrowserType::Edge
                } else {
                    BrowserType::Chrome
                };

                return Ok(crate::browser::BrowserInstallation {
                    browser_type,
                    executable_path: path.clone(),
                    user_data_dir: config
                        .browser
                        .user_data_dir
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(".")),
                    version: None,
                });
            }
        }

        // Auto-detect browsers
        let browsers = BrowserDetector::detect_all();
        
        if browsers.is_empty() {
            return Err(Error::Browser(
                "No supported browser found. Please install Brave, Chrome, or Chromium.".into(),
            ));
        }

        // Prefer Brave > Chrome > Chromium > Edge
        let browser = browsers
            .into_iter()
            .min_by_key(|b| match b.browser_type {
                BrowserType::Brave => 0,
                BrowserType::Chrome => 1,
                BrowserType::Chromium => 2,
                BrowserType::Edge => 3,
            })
            .unwrap();

        Ok(browser)
    }

    /// Get whether the browser is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Get the provider for this session.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Get the current conversation ID, if any.
    pub fn conversation_id(&self) -> Option<&String> {
        self.conversation_id.as_ref()
    }

    /// Set the conversation ID.
    pub fn set_conversation_id(&mut self, id: String) {
        self.conversation_id = Some(id);
    }

    /// Navigate to a URL.
    pub async fn navigate(&self, url: &str) -> Result<()> {
        tracing::info!("Navigating to: {}", url);
        
        let page = self.page.read().await;
        page.goto(url)
            .await
            .map_err(|e| Error::Browser(format!("Navigation failed: {}", e)))?;

        // Mirror to secondary head if active
        if let Some(ref sec_page_lock) = self.secondary_page {
            let sec_page = sec_page_lock.read().await;
            let _ = sec_page.goto(url).await;
        }
        
        // Wait for page to stabilize
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        Ok(())
    }

    /// Get the current page URL.
    pub async fn current_url(&self) -> Result<String> {
        let page = self.page.read().await;
        page.url()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get URL: {}", e)))?
            .ok_or_else(|| Error::Browser("No URL available".into()))
    }

    /// Wait for a URL to contain a substring.
    pub async fn wait_for_url_contains(&self, substring: &str, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            let url = self.current_url().await?;
            if url.contains(substring) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(Error::Timeout(timeout.as_millis() as u64))
    }

    /// Wait for an element to be present.
    pub async fn wait_for_element(&self, selector: &str, timeout: Duration) -> Result<Element> {
        tracing::debug!("Waiting for element: {}", selector);
        
        let page = self.page.read().await;
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            if let Ok(element) = page.find_element(selector).await {
                return Ok(element);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Err(Error::Timeout(timeout.as_millis() as u64))
    }

    /// Wait for an element to be hidden/removed.
    pub async fn wait_for_element_hidden(&self, selector: &str, timeout: Duration) -> Result<()> {
        tracing::debug!("Waiting for element to hide: {}", selector);
        
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            if !self.element_exists(selector).await.unwrap_or(false) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Err(Error::Timeout(timeout.as_millis() as u64))
    }

    /// Check if an element exists.
    pub async fn element_exists(&self, selector: &str) -> Result<bool> {
        let page = self.page.read().await;
        match page.find_element(selector).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Click on an element.
    pub async fn click(&self, selector: &str) -> Result<()> {
        tracing::debug!("Clicking element: {}", selector);
        
        let page = self.page.read().await;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| Error::Browser(format!("Element not found ({}): {}", selector, e)))?;
        
        element
            .click()
            .await
            .map_err(|e| Error::Browser(format!("Click failed: {}", e)))?;
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }

    /// Type text into an element.
    pub async fn type_text(&self, selector: &str, text: &str) -> Result<()> {
        tracing::debug!("Typing text into: {}", selector);
        
        let page = self.page.read().await;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| Error::Browser(format!("Element not found ({}): {}", selector, e)))?;
        
        // Click to focus
        element
            .click()
            .await
            .map_err(|e| Error::Browser(format!("Click to focus failed: {}", e)))?;
        
        // Type the text
        element
            .type_str(text)
            .await
            .map_err(|e| Error::Browser(format!("Typing failed: {}", e)))?;
        
        Ok(())
    }

    /// Upload files to an input element.
    pub async fn upload_files(&self, selector: &str, paths: &[PathBuf]) -> Result<()> {
        tracing::debug!("Uploading {} files to: {}", paths.len(), selector);
        
        let page = self.page.read().await;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| Error::Browser(format!("Element not found ({}): {}", selector, e)))?;
        
        let path_strs: Vec<String> = paths.iter()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()).to_string_lossy().to_string())
            .collect();
            
        use chromiumoxide::cdp::browser_protocol::dom::SetFileInputFilesParams;
        
        let cmd = SetFileInputFilesParams::builder()
            .files(path_strs)
            .node_id(element.node_id)
            .build()
            .map_err(|e| Error::Browser(e))?;

        page.execute(cmd)
            .await
            .map_err(|e| Error::Browser(format!("File upload failed: {}", e)))?;
            
        Ok(())
    }

    /// Press a key (e.g., "Enter", "Tab")
    pub async fn press_key(&self, key: &str) -> Result<()> {
        tracing::debug!("Pressing key: {}", key);
        
        // Use JavaScript to simulate key press
        let script = format!(
            r#"
            (function() {{
                const event = new KeyboardEvent('keydown', {{
                    key: '{}',
                    code: '{}',
                    keyCode: {},
                    which: {},
                    bubbles: true
                }});
                document.activeElement.dispatchEvent(event);
                
                const upEvent = new KeyboardEvent('keyup', {{
                    key: '{}',
                    code: '{}',
                    keyCode: {},
                    which: {},
                    bubbles: true
                }});
                document.activeElement.dispatchEvent(upEvent);
            }})()
            "#,
            key, key, key_code(key), key_code(key),
            key, key, key_code(key), key_code(key)
        );
        
        let page = self.page.read().await;
        page.evaluate(script)
            .await
            .map_err(|e| Error::Browser(format!("Key press failed: {}", e)))?;
        
        Ok(())
    }
    
    /// Save cookies for session persistence with encryption.
    pub async fn save_cookies(&self) -> Result<()> {
        let cookie_path = self.profile_dir.join("cookies.json.enc");
        tracing::debug!("Saving encrypted cookies to: {:?}", cookie_path);
        
        let page = self.page.read().await;
        let cookies = page
            .get_cookies()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get cookies: {}", e)))?;
        
        let json = serde_json::to_string(&cookies)
            .map_err(|e| Error::Internal(format!("Failed to serialize cookies: {}", e)))?;

        // Encrypt the cookies
        let master_key = self.get_encryption_key()?;
        let encryption = DataEncryption::new(&master_key, b"static_salt_for_cookies");
        let encrypted = encryption.encrypt(json.as_bytes())
            .map_err(|e| Error::Internal(format!("Encryption failed: {}", e)))?;

        std::fs::write(cookie_path, encrypted)?;
        
        Ok(())
    }

    /// Load cookies from previous session.
    pub async fn load_cookies(&self) -> Result<()> {
        let cookie_path = self.profile_dir.join("cookies.json.enc");
        
        if cookie_path.exists() {
            tracing::debug!("Loading encrypted cookies from: {:?}", cookie_path);
            let encrypted = std::fs::read(&cookie_path)?;
            
            let master_key = self.get_encryption_key()?;
            let encryption = DataEncryption::new(&master_key, b"static_salt_for_cookies");
            
            let decrypted = encryption.decrypt(&encrypted)
                .map_err(|e| Error::Internal(format!("Decryption failed: {}", e)))?;
            
            let cookies: Vec<chromiumoxide::cdp::browser_protocol::network::Cookie> = 
                serde_json::from_slice(&decrypted)
                .map_err(|e| Error::Internal(format!("Failed to deserialize cookies: {}", e)))?;

            // Convert Cookie to CookieParam for set_cookies
            use chromiumoxide::cdp::browser_protocol::network::CookieParam;
            let cookie_params: Vec<CookieParam> = cookies.into_iter().map(|c| {
                let json = serde_json::to_value(&c).unwrap();
                serde_json::from_value(json).unwrap()
            }).collect();

            let page = self.page.read().await;
            page.set_cookies(cookie_params)
                .await
                .map_err(|e| Error::Browser(format!("Failed to set cookies: {}", e)))?;
        }
        
        Ok(())
    }

    /// Helper to get or create an encryption key for this session.
    fn get_encryption_key(&self) -> Result<String> {
        match self.credentials.get(self.provider, "cookie_encryption_key")? {
            Some(key) => Ok(key),
            None => {
                let new_key = uuid::Uuid::new_v4().to_string();
                self.credentials.store(self.provider, "cookie_encryption_key", &new_key)?;
                Ok(new_key)
            }
        }
    }
    
    /// Get text content of an element handle (for compatibility with provider code).
    pub async fn get_text_content(&self, element: &Element) -> Result<String> {
        element
            .inner_text()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get text: {}", e)))?
            .ok_or_else(|| Error::Browser("No text content".into()))
    }

    /// Query all elements matching a selector.
    pub async fn query_all(&self, selector: &str) -> Result<Vec<Element>> {
        tracing::debug!("Querying all: {}", selector);
        
        let page = self.page.read().await;
        page.find_elements(selector)
            .await
            .map_err(|e| Error::Browser(format!("Query failed: {}", e)))
    }

    /// Get text content of an element by selector.
    pub async fn get_text(&self, selector: &str) -> Result<String> {
        let page = self.page.read().await;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| Error::Browser(format!("Element not found ({}): {}", selector, e)))?;
        
        element
            .inner_text()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get text: {}", e)))?
            .ok_or_else(|| Error::Browser("No text content".into()))
    }

    /// Get inner HTML of an element.
    pub async fn get_inner_html(&self, selector: &str) -> Result<String> {
        let page = self.page.read().await;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| Error::Browser(format!("Element not found ({}): {}", selector, e)))?;
        
        element
            .inner_html()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get HTML: {}", e)))?
            .ok_or_else(|| Error::Browser("No HTML content".into()))
    }

    /// Execute JavaScript and return result.
    pub async fn evaluate<T: serde::de::DeserializeOwned>(&self, script: &str) -> Result<T> {
        let page = self.page.read().await;
        page.evaluate(script)
            .await
            .map_err(|e| Error::Browser(format!("Script evaluation failed: {}", e)))?
            .into_value()
            .map_err(|e| Error::Browser(format!("Script result conversion failed: {}", e)))
    }

    /// Take a screenshot.
    pub async fn screenshot(&self, path: Option<&std::path::Path>) -> Result<Vec<u8>> {
        tracing::debug!("Taking screenshot");
        
        let page = self.page.read().await;
        let screenshot = page
            .screenshot(
                chromiumoxide::page::ScreenshotParams::builder()
                    .format(CaptureScreenshotFormat::Png)
                    .build(),
            )
            .await
            .map_err(|e| Error::Browser(format!("Screenshot failed: {}", e)))?;
        
        if let Some(path) = path {
            std::fs::write(path, &screenshot)?;
        }
        
        Ok(screenshot)
    }

    /// Get page HTML content.
    pub async fn get_page_content(&self) -> Result<String> {
        let page = self.page.read().await;
        page.content()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get content: {}", e)))
    }

    /// Get page title.
    pub async fn get_title(&self) -> Result<String> {
        let page = self.page.read().await;
        page.get_title()
            .await
            .map_err(|e| Error::Browser(format!("Failed to get title: {}", e)))?
            .ok_or_else(|| Error::Browser("No title".into()))
    }

    /// Close the browser session.
    pub async fn close(&self) -> Result<()> {
        tracing::info!("Closing session for {}", self.provider);
        // Browser closes on drop
        Ok(())
    }
}

/// Convert key name to key code for JavaScript keyboard events.
fn key_code(key: &str) -> u32 {
    match key {
        "Enter" | "Return" => 13,
        "Tab" => 9,
        "Escape" | "Esc" => 27,
        "Backspace" => 8,
        "Delete" => 46,
        "ArrowUp" => 38,
        "ArrowDown" => 40,
        "ArrowLeft" => 37,
        "ArrowRight" => 39,
        "Home" => 36,
        "End" => 35,
        "PageUp" => 33,
        "PageDown" => 34,
        "Space" | " " => 32,
        _ => 0, // Default for unknown keys
    }
}
