//! Browser detection and configuration for system browsers.
//!
//! Supports using system-installed browsers (Brave, Chrome, Chromium) with
//! existing user profiles and authentication.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Supported browser types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserType {
    /// Brave browser (Chromium-based).
    Brave,
    /// Google Chrome.
    Chrome,
    /// Chromium (open source).
    Chromium,
    /// Microsoft Edge (Chromium-based).
    Edge,
}

impl BrowserType {
    /// Get the display name of the browser.
    pub fn name(&self) -> &'static str {
        match self {
            BrowserType::Brave => "Brave",
            BrowserType::Chrome => "Chrome",
            BrowserType::Chromium => "Chromium",
            BrowserType::Edge => "Edge",
        }
    }
}

impl std::fmt::Display for BrowserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Detected browser installation.
#[derive(Debug, Clone)]
pub struct BrowserInstallation {
    /// Type of browser.
    pub browser_type: BrowserType,
    /// Path to executable.
    pub executable_path: PathBuf,
    /// User data directory (profiles).
    pub user_data_dir: PathBuf,
    /// Version string (if detectable).
    pub version: Option<String>,
}

impl BrowserInstallation {
    /// Check if this installation appears valid.
    pub fn is_valid(&self) -> bool {
        self.executable_path.exists()
    }

    /// Get the default profile directory.
    pub fn default_profile_dir(&self) -> PathBuf {
        self.user_data_dir.join("Default")
    }

    /// List available profiles.
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let mut profiles = Vec::new();

        if !self.user_data_dir.exists() {
            return Ok(profiles);
        }

        for entry in std::fs::read_dir(&self.user_data_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy().to_string();

                // Check for profile indicators
                if name == "Default" || name.starts_with("Profile ") {
                    // Verify it has preferences
                    if path.join("Preferences").exists() {
                        profiles.push(name);
                    }
                }
            }
        }

        Ok(profiles)
    }
}

/// Browser detector for finding system-installed browsers.
pub struct BrowserDetector;

impl BrowserDetector {
    /// Detect all installed browsers on the system.
    pub fn detect_all() -> Vec<BrowserInstallation> {
        let mut browsers = Vec::new();

        // Try each browser type
        if let Some(brave) = Self::detect_brave() {
            browsers.push(brave);
        }
        if let Some(chrome) = Self::detect_chrome() {
            browsers.push(chrome);
        }
        if let Some(chromium) = Self::detect_chromium() {
            browsers.push(chromium);
        }
        if let Some(edge) = Self::detect_edge() {
            browsers.push(edge);
        }

        browsers
    }

    /// Detect Brave browser installation.
    pub fn detect_brave() -> Option<BrowserInstallation> {
        // Linux paths (Debian/Ubuntu package installation)
        let linux_paths = [
            "/usr/bin/brave-browser",
            "/usr/bin/brave",
            "/opt/brave.com/brave/brave",
            "/snap/bin/brave",
        ];

        // Linux user data directories
        let linux_data_dirs = [
            dirs::config_dir().map(|d| d.join("BraveSoftware/Brave-Browser")),
            dirs::home_dir().map(|d| d.join(".config/BraveSoftware/Brave-Browser")),
        ];

        // Find executable
        let executable = linux_paths.iter().map(PathBuf::from).find(|p| p.exists());

        // Find user data dir
        let user_data_dir = linux_data_dirs
            .iter()
            .filter_map(|d| d.clone())
            .find(|p| p.exists());

        match (executable, user_data_dir) {
            (Some(exec), Some(data_dir)) => {
                let version = Self::detect_version(&exec);
                Some(BrowserInstallation {
                    browser_type: BrowserType::Brave,
                    executable_path: exec,
                    user_data_dir: data_dir,
                    version,
                })
            }
            (Some(exec), None) => {
                // Try default data dir
                let default_data = dirs::config_dir()
                    .map(|d| d.join("BraveSoftware/Brave-Browser"))
                    .unwrap_or_else(|| PathBuf::from("~/.config/BraveSoftware/Brave-Browser"));

                Some(BrowserInstallation {
                    browser_type: BrowserType::Brave,
                    executable_path: exec,
                    user_data_dir: default_data,
                    version: None,
                })
            }
            _ => None,
        }
    }

    /// Detect Chrome browser installation.
    pub fn detect_chrome() -> Option<BrowserInstallation> {
        let linux_paths = [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
        ];

        let linux_data_dirs = [
            dirs::config_dir().map(|d| d.join("google-chrome")),
            dirs::home_dir().map(|d| d.join(".config/google-chrome")),
        ];

        let executable = linux_paths.iter().map(PathBuf::from).find(|p| p.exists());

        let user_data_dir = linux_data_dirs
            .iter()
            .filter_map(|d| d.clone())
            .find(|p| p.exists());

        match (executable, user_data_dir) {
            (Some(exec), Some(data_dir)) => {
                let version = Self::detect_version(&exec);
                Some(BrowserInstallation {
                    browser_type: BrowserType::Chrome,
                    executable_path: exec,
                    user_data_dir: data_dir,
                    version,
                })
            }
            _ => None,
        }
    }

    /// Detect Chromium browser installation.
    pub fn detect_chromium() -> Option<BrowserInstallation> {
        let linux_paths = [
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
        ];

        let linux_data_dirs = [
            dirs::config_dir().map(|d| d.join("chromium")),
            dirs::home_dir().map(|d| d.join(".config/chromium")),
        ];

        let executable = linux_paths.iter().map(PathBuf::from).find(|p| p.exists());

        let user_data_dir = linux_data_dirs
            .iter()
            .filter_map(|d| d.clone())
            .find(|p| p.exists());

        match (executable, user_data_dir) {
            (Some(exec), Some(data_dir)) => {
                let version = Self::detect_version(&exec);
                Some(BrowserInstallation {
                    browser_type: BrowserType::Chromium,
                    executable_path: exec,
                    user_data_dir: data_dir,
                    version,
                })
            }
            _ => None,
        }
    }

    /// Detect Edge browser installation.
    pub fn detect_edge() -> Option<BrowserInstallation> {
        let linux_paths = [
            "/usr/bin/microsoft-edge-stable",
            "/usr/bin/microsoft-edge",
            "/opt/microsoft/msedge/msedge",
        ];

        let linux_data_dirs = [
            dirs::config_dir().map(|d| d.join("microsoft-edge")),
            dirs::home_dir().map(|d| d.join(".config/microsoft-edge")),
        ];

        let executable = linux_paths.iter().map(PathBuf::from).find(|p| p.exists());

        let user_data_dir = linux_data_dirs
            .iter()
            .filter_map(|d| d.clone())
            .find(|p| p.exists());

        match (executable, user_data_dir) {
            (Some(exec), Some(data_dir)) => {
                let version = Self::detect_version(&exec);
                Some(BrowserInstallation {
                    browser_type: BrowserType::Edge,
                    executable_path: exec,
                    user_data_dir: data_dir,
                    version,
                })
            }
            _ => None,
        }
    }

    /// Detect browser by type.
    pub fn detect(browser_type: BrowserType) -> Option<BrowserInstallation> {
        match browser_type {
            BrowserType::Brave => Self::detect_brave(),
            BrowserType::Chrome => Self::detect_chrome(),
            BrowserType::Chromium => Self::detect_chromium(),
            BrowserType::Edge => Self::detect_edge(),
        }
    }

    /// Get the preferred browser (Brave > Chrome > Chromium > Edge).
    pub fn preferred() -> Option<BrowserInstallation> {
        Self::detect_brave()
            .or_else(Self::detect_chrome)
            .or_else(Self::detect_chromium)
            .or_else(Self::detect_edge)
    }

    /// Detect browser version from executable.
    fn detect_version(executable: &PathBuf) -> Option<String> {
        std::process::Command::new(executable)
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8(output.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
    }
}

/// Builder for browser launch configuration.
#[derive(Debug, Clone)]
pub struct BrowserLaunchConfig {
    /// Browser installation to use.
    pub installation: BrowserInstallation,
    /// Profile name to use (None for Default).
    pub profile: Option<String>,
    /// Run in headless mode.
    pub headless: bool,
    /// Use existing user data (includes auth).
    pub use_existing_profile: bool,
    /// Additional command-line arguments.
    pub extra_args: Vec<String>,
    /// Disable browser sandbox (required for some containers).
    pub no_sandbox: bool,
    /// Enable remote debugging port.
    pub remote_debugging_port: Option<u16>,
}

impl BrowserLaunchConfig {
    /// Create a new launch config for a browser installation.
    pub fn new(installation: BrowserInstallation) -> Self {
        Self {
            installation,
            profile: None,
            headless: true,
            use_existing_profile: true,
            extra_args: Vec::new(),
            no_sandbox: false,
            remote_debugging_port: Some(9222),
        }
    }

    /// Use a specific profile.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set headless mode.
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Use existing profile with authentication.
    pub fn use_existing_profile(mut self, use_existing: bool) -> Self {
        self.use_existing_profile = use_existing;
        self
    }

    /// Add extra command-line argument.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    /// Disable sandbox (for containers/restricted environments).
    pub fn no_sandbox(mut self) -> Self {
        self.no_sandbox = true;
        self
    }

    /// Set remote debugging port.
    pub fn remote_debugging_port(mut self, port: u16) -> Self {
        self.remote_debugging_port = Some(port);
        self
    }

    /// Generate command-line arguments for browser launch.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // User data directory
        if self.use_existing_profile {
            args.push(format!(
                "--user-data-dir={}",
                self.installation.user_data_dir.display()
            ));
        }

        // Profile selection
        if let Some(ref profile) = self.profile {
            args.push(format!("--profile-directory={}", profile));
        }

        // Headless mode
        if self.headless {
            args.push("--headless=new".into());
        }

        // Sandbox
        if self.no_sandbox {
            args.push("--no-sandbox".into());
            args.push("--disable-setuid-sandbox".into());
        }

        // Remote debugging
        if let Some(port) = self.remote_debugging_port {
            args.push(format!("--remote-debugging-port={}", port));
        }

        // Standard args for automation
        args.extend([
            "--disable-gpu".into(),
            "--disable-dev-shm-usage".into(),
            "--disable-extensions".into(), // Disable extensions to avoid interference
            "--disable-background-networking".into(),
            "--disable-sync".into(),
            "--no-first-run".into(),
            "--metrics-recording-only".into(),
            "--disable-default-apps".into(),
        ]);

        // Extra args
        args.extend(self.extra_args.clone());

        args
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if !self.installation.executable_path.exists() {
            return Err(Error::BrowserNotFound(
                self.installation.executable_path.display().to_string(),
            ));
        }

        if self.use_existing_profile && !self.installation.user_data_dir.exists() {
            return Err(Error::Config(format!(
                "User data directory not found: {}",
                self.installation.user_data_dir.display()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_browsers() {
        let browsers = BrowserDetector::detect_all();
        println!("Detected browsers:");
        for browser in &browsers {
            println!(
                "  - {} at {:?} (valid: {})",
                browser.browser_type,
                browser.executable_path,
                browser.is_valid()
            );
        }
    }

    #[test]
    fn test_launch_config_args() {
        let brave = BrowserInstallation {
            browser_type: BrowserType::Brave,
            executable_path: PathBuf::from("/usr/bin/brave-browser"),
            user_data_dir: PathBuf::from("/home/user/.config/BraveSoftware/Brave-Browser"),
            version: None,
        };

        let config = BrowserLaunchConfig::new(brave)
            .headless(true)
            .with_profile("Default");

        let args = config.to_args();
        assert!(args.contains(&"--headless=new".to_string()));
        assert!(args.iter().any(|a| a.starts_with("--user-data-dir=")));
        assert!(args.iter().any(|a| a.starts_with("--profile-directory=")));
    }
}
