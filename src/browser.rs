//! Browser detection and configuration for system browsers.
//!
//! Supports using system-installed browsers with existing user profiles and authentication.
//!
//! # Supported Browsers
//!
//! ## Chromium-based (Full CDP automation support)
//! - **Brave** - Privacy-focused browser
//! - **Chrome** - Google Chrome
//! - **Chromium** - Open source base
//! - **Edge** - Microsoft Edge
//! - **Opera** - Opera browser
//! - **Vivaldi** - Power-user browser
//!
//! ## Gecko-based (Detection only, automation requires geckodriver)
//! - **Firefox** - Mozilla Firefox
//!
//! ## WebKit-based (Detection only, macOS only)
//! - **Safari** - Apple Safari (requires manual `safaridriver --enable`)
//!
//! # Platform Support
//!
//! Detection paths are provided for:
//! - Linux (Debian/Ubuntu, Fedora, Arch, Snap, Flatpak)
//! - macOS (Application bundles)
//! - Windows (Program Files paths)

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Supported browser types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserType {
    /// Brave browser (Chromium-based, full automation support).
    Brave,
    /// Google Chrome (Chromium-based, full automation support).
    Chrome,
    /// Chromium open source browser (full automation support).
    Chromium,
    /// Microsoft Edge (Chromium-based, full automation support).
    Edge,
    /// Opera browser (Chromium-based, full automation support).
    Opera,
    /// Vivaldi browser (Chromium-based, full automation support).
    Vivaldi,
    /// Mozilla Firefox (Gecko-based, detection only - automation requires geckodriver).
    Firefox,
    /// Apple Safari (WebKit-based, macOS only, detection only - requires safaridriver).
    Safari,
}

impl BrowserType {
    /// Get the display name of the browser.
    pub fn name(&self) -> &'static str {
        match self {
            BrowserType::Brave => "Brave",
            BrowserType::Chrome => "Chrome",
            BrowserType::Chromium => "Chromium",
            BrowserType::Edge => "Edge",
            BrowserType::Opera => "Opera",
            BrowserType::Vivaldi => "Vivaldi",
            BrowserType::Firefox => "Firefox",
            BrowserType::Safari => "Safari",
        }
    }

    /// Check if this browser type supports CDP (Chrome DevTools Protocol) automation.
    ///
    /// Chromium-based browsers support CDP directly via chromiumoxide.
    /// Firefox and Safari require separate WebDriver implementations.
    pub fn supports_cdp(&self) -> bool {
        matches!(
            self,
            BrowserType::Brave
                | BrowserType::Chrome
                | BrowserType::Chromium
                | BrowserType::Edge
                | BrowserType::Opera
                | BrowserType::Vivaldi
        )
    }

    /// Check if this browser is Chromium-based.
    pub fn is_chromium_based(&self) -> bool {
        self.supports_cdp()
    }

    /// Get the browser engine name.
    pub fn engine(&self) -> &'static str {
        match self {
            BrowserType::Firefox => "Gecko",
            BrowserType::Safari => "WebKit",
            _ => "Chromium/Blink",
        }
    }

    /// Get all supported browser types.
    pub fn all() -> &'static [BrowserType] {
        &[
            BrowserType::Brave,
            BrowserType::Chrome,
            BrowserType::Chromium,
            BrowserType::Edge,
            BrowserType::Opera,
            BrowserType::Vivaldi,
            BrowserType::Firefox,
            BrowserType::Safari,
        ]
    }

    /// Get browser types that support full CDP automation.
    pub fn cdp_supported() -> &'static [BrowserType] {
        &[
            BrowserType::Brave,
            BrowserType::Chrome,
            BrowserType::Chromium,
            BrowserType::Edge,
            BrowserType::Opera,
            BrowserType::Vivaldi,
        ]
    }
}

impl std::fmt::Display for BrowserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for BrowserType {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "brave" => Ok(BrowserType::Brave),
            "chrome" | "google-chrome" => Ok(BrowserType::Chrome),
            "chromium" => Ok(BrowserType::Chromium),
            "edge" | "microsoft-edge" | "msedge" => Ok(BrowserType::Edge),
            "opera" => Ok(BrowserType::Opera),
            "vivaldi" => Ok(BrowserType::Vivaldi),
            "firefox" | "mozilla-firefox" => Ok(BrowserType::Firefox),
            "safari" => Ok(BrowserType::Safari),
            _ => Err(Error::Config(format!("Unknown browser type: {}", s))),
        }
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

        // Chromium-based browsers (full CDP support)
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
        if let Some(opera) = Self::detect_opera() {
            browsers.push(opera);
        }
        if let Some(vivaldi) = Self::detect_vivaldi() {
            browsers.push(vivaldi);
        }

        // Non-Chromium browsers (detection only)
        if let Some(firefox) = Self::detect_firefox() {
            browsers.push(firefox);
        }
        if let Some(safari) = Self::detect_safari() {
            browsers.push(safari);
        }

        browsers
    }

    /// Detect all browsers that support CDP automation.
    pub fn detect_cdp_capable() -> Vec<BrowserInstallation> {
        Self::detect_all()
            .into_iter()
            .filter(|b| b.browser_type.supports_cdp())
            .collect()
    }

    /// Detect Brave browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_brave() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/brave-browser",
            "/usr/bin/brave",
            "/opt/brave.com/brave/brave",
            "/snap/bin/brave",
            "/var/lib/flatpak/exports/bin/com.brave.Browser",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("BraveSoftware/Brave-Browser")),
            dirs::home_dir().map(|d| d.join(".config/BraveSoftware/Brave-Browser")),
            dirs::home_dir()
                .map(|d| d.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser")),
        ];

        Self::detect_browser_generic(BrowserType::Brave, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_brave() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"];

        let data_dirs = [dirs::home_dir()
            .map(|d| d.join("Library/Application Support/BraveSoftware/Brave-Browser"))];

        Self::detect_browser_generic(BrowserType::Brave, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_brave() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        ];

        let data_dirs =
            [dirs::data_local_dir().map(|d| d.join("BraveSoftware\\Brave-Browser\\User Data"))];

        Self::detect_browser_generic(BrowserType::Brave, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_brave() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Chrome browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_chrome() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
            "/snap/bin/google-chrome",
            "/var/lib/flatpak/exports/bin/com.google.Chrome",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("google-chrome")),
            dirs::home_dir().map(|d| d.join(".config/google-chrome")),
            dirs::home_dir().map(|d| d.join(".var/app/com.google.Chrome/config/google-chrome")),
        ];

        Self::detect_browser_generic(BrowserType::Chrome, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_chrome() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"];

        let data_dirs =
            [dirs::home_dir().map(|d| d.join("Library/Application Support/Google/Chrome"))];

        Self::detect_browser_generic(BrowserType::Chrome, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_chrome() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ];

        let data_dirs = [dirs::data_local_dir().map(|d| d.join("Google\\Chrome\\User Data"))];

        Self::detect_browser_generic(BrowserType::Chrome, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_chrome() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Chromium browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_chromium() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
            "/var/lib/flatpak/exports/bin/org.chromium.Chromium",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("chromium")),
            dirs::home_dir().map(|d| d.join(".config/chromium")),
            dirs::home_dir().map(|d| d.join(".var/app/org.chromium.Chromium/config/chromium")),
        ];

        Self::detect_browser_generic(BrowserType::Chromium, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_chromium() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Chromium.app/Contents/MacOS/Chromium"];

        let data_dirs = [dirs::home_dir().map(|d| d.join("Library/Application Support/Chromium"))];

        Self::detect_browser_generic(BrowserType::Chromium, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_chromium() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Chromium\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Chromium\\Application\\chrome.exe",
        ];

        let data_dirs = [dirs::data_local_dir().map(|d| d.join("Chromium\\User Data"))];

        Self::detect_browser_generic(BrowserType::Chromium, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_chromium() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Edge browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_edge() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/microsoft-edge-stable",
            "/usr/bin/microsoft-edge",
            "/opt/microsoft/msedge/msedge",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("microsoft-edge")),
            dirs::home_dir().map(|d| d.join(".config/microsoft-edge")),
        ];

        Self::detect_browser_generic(BrowserType::Edge, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_edge() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"];

        let data_dirs =
            [dirs::home_dir().map(|d| d.join("Library/Application Support/Microsoft Edge"))];

        Self::detect_browser_generic(BrowserType::Edge, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_edge() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        ];

        let data_dirs = [dirs::data_local_dir().map(|d| d.join("Microsoft\\Edge\\User Data"))];

        Self::detect_browser_generic(BrowserType::Edge, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_edge() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Opera browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_opera() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/opera",
            "/snap/bin/opera",
            "/var/lib/flatpak/exports/bin/com.opera.Opera",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("opera")),
            dirs::home_dir().map(|d| d.join(".config/opera")),
            dirs::home_dir().map(|d| d.join(".var/app/com.opera.Opera/config/opera")),
        ];

        Self::detect_browser_generic(BrowserType::Opera, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_opera() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Opera.app/Contents/MacOS/Opera"];

        let data_dirs =
            [dirs::home_dir()
                .map(|d| d.join("Library/Application Support/com.operasoftware.Opera"))];

        Self::detect_browser_generic(BrowserType::Opera, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_opera() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Opera\\opera.exe",
            "C:\\Program Files (x86)\\Opera\\opera.exe",
        ];

        let data_dirs = [
            dirs::data_local_dir().map(|d| d.join("Opera Software\\Opera Stable")),
            dirs::home_dir().map(|d| d.join("AppData\\Roaming\\Opera Software\\Opera Stable")),
        ];

        Self::detect_browser_generic(BrowserType::Opera, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_opera() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Vivaldi browser installation.
    #[cfg(target_os = "linux")]
    pub fn detect_vivaldi() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/vivaldi-stable",
            "/usr/bin/vivaldi",
            "/opt/vivaldi/vivaldi",
        ];

        let data_dirs = [
            dirs::config_dir().map(|d| d.join("vivaldi")),
            dirs::home_dir().map(|d| d.join(".config/vivaldi")),
        ];

        Self::detect_browser_generic(BrowserType::Vivaldi, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_vivaldi() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Vivaldi.app/Contents/MacOS/Vivaldi"];

        let data_dirs = [dirs::home_dir().map(|d| d.join("Library/Application Support/Vivaldi"))];

        Self::detect_browser_generic(BrowserType::Vivaldi, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_vivaldi() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Vivaldi\\Application\\vivaldi.exe",
            "C:\\Program Files (x86)\\Vivaldi\\Application\\vivaldi.exe",
        ];

        let data_dirs = [dirs::data_local_dir().map(|d| d.join("Vivaldi\\User Data"))];

        Self::detect_browser_generic(BrowserType::Vivaldi, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_vivaldi() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Firefox browser installation.
    ///
    /// Note: Firefox uses Gecko engine and requires geckodriver for WebDriver automation.
    /// Currently provides detection only; full automation is not yet implemented.
    #[cfg(target_os = "linux")]
    pub fn detect_firefox() -> Option<BrowserInstallation> {
        let paths = [
            "/usr/bin/firefox",
            "/usr/bin/firefox-esr",
            "/snap/bin/firefox",
            "/var/lib/flatpak/exports/bin/org.mozilla.firefox",
        ];

        let data_dirs = [
            dirs::home_dir().map(|d| d.join(".mozilla/firefox")),
            dirs::home_dir().map(|d| d.join(".var/app/org.mozilla.firefox/.mozilla/firefox")),
        ];

        Self::detect_browser_generic(BrowserType::Firefox, &paths, &data_dirs)
    }

    #[cfg(target_os = "macos")]
    pub fn detect_firefox() -> Option<BrowserInstallation> {
        let paths = ["/Applications/Firefox.app/Contents/MacOS/firefox"];

        let data_dirs = [dirs::home_dir().map(|d| d.join("Library/Application Support/Firefox"))];

        Self::detect_browser_generic(BrowserType::Firefox, &paths, &data_dirs)
    }

    #[cfg(target_os = "windows")]
    pub fn detect_firefox() -> Option<BrowserInstallation> {
        let paths = [
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
        ];

        let data_dirs = [dirs::home_dir().map(|d| d.join("AppData\\Roaming\\Mozilla\\Firefox"))];

        Self::detect_browser_generic(BrowserType::Firefox, &paths, &data_dirs)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn detect_firefox() -> Option<BrowserInstallation> {
        None
    }

    /// Detect Safari browser installation (macOS only).
    ///
    /// Note: Safari requires manual enabling of WebDriver automation:
    /// `safaridriver --enable` (requires admin privileges)
    #[cfg(target_os = "macos")]
    pub fn detect_safari() -> Option<BrowserInstallation> {
        let safari_path = PathBuf::from("/Applications/Safari.app/Contents/MacOS/Safari");

        if safari_path.exists() {
            let version = Self::detect_version(&safari_path);
            Some(BrowserInstallation {
                browser_type: BrowserType::Safari,
                executable_path: safari_path,
                // Safari doesn't use a traditional user data dir like Chromium browsers
                user_data_dir: dirs::home_dir()
                    .map(|d| d.join("Library/Safari"))
                    .unwrap_or_else(|| PathBuf::from("~/Library/Safari")),
                version,
            })
        } else {
            None
        }
    }

    /// Detect Safari browser (returns None on non-macOS platforms).
    #[cfg(not(target_os = "macos"))]
    pub fn detect_safari() -> Option<BrowserInstallation> {
        // Safari is only available on macOS
        None
    }

    /// Generic browser detection helper.
    fn detect_browser_generic(
        browser_type: BrowserType,
        exec_paths: &[&str],
        data_dirs: &[Option<PathBuf>],
    ) -> Option<BrowserInstallation> {
        let executable = exec_paths.iter().map(PathBuf::from).find(|p| p.exists());

        let user_data_dir = data_dirs
            .iter()
            .filter_map(|d| d.clone())
            .find(|p| p.exists());

        match (executable, user_data_dir) {
            (Some(exec), Some(data_dir)) => {
                let version = Self::detect_version(&exec);
                Some(BrowserInstallation {
                    browser_type,
                    executable_path: exec,
                    user_data_dir: data_dir,
                    version,
                })
            }
            (Some(exec), None) => {
                // Return with default data dir path even if it doesn't exist yet
                let default_data = Self::default_data_dir_for_type(browser_type);
                Some(BrowserInstallation {
                    browser_type,
                    executable_path: exec,
                    user_data_dir: default_data,
                    version: None,
                })
            }
            _ => None,
        }
    }

    /// Get the default data directory path for a browser type.
    #[cfg(target_os = "linux")]
    fn default_data_dir_for_type(browser_type: BrowserType) -> PathBuf {
        let config = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
        match browser_type {
            BrowserType::Brave => config.join("BraveSoftware/Brave-Browser"),
            BrowserType::Chrome => config.join("google-chrome"),
            BrowserType::Chromium => config.join("chromium"),
            BrowserType::Edge => config.join("microsoft-edge"),
            BrowserType::Opera => config.join("opera"),
            BrowserType::Vivaldi => config.join("vivaldi"),
            BrowserType::Firefox => dirs::home_dir()
                .map(|d| d.join(".mozilla/firefox"))
                .unwrap_or_else(|| PathBuf::from("~/.mozilla/firefox")),
            // Safari is not available on Linux - return empty path that won't exist
            BrowserType::Safari => PathBuf::from("/unsupported/safari-not-available-on-linux"),
        }
    }

    #[cfg(target_os = "macos")]
    fn default_data_dir_for_type(browser_type: BrowserType) -> PathBuf {
        let support = dirs::home_dir()
            .map(|d| d.join("Library/Application Support"))
            .unwrap_or_else(|| PathBuf::from("~/Library/Application Support"));
        match browser_type {
            BrowserType::Brave => support.join("BraveSoftware/Brave-Browser"),
            BrowserType::Chrome => support.join("Google/Chrome"),
            BrowserType::Chromium => support.join("Chromium"),
            BrowserType::Edge => support.join("Microsoft Edge"),
            BrowserType::Opera => support.join("com.operasoftware.Opera"),
            BrowserType::Vivaldi => support.join("Vivaldi"),
            BrowserType::Firefox => support.join("Firefox"),
            BrowserType::Safari => dirs::home_dir()
                .map(|d| d.join("Library/Safari"))
                .unwrap_or_else(|| PathBuf::from("~/Library/Safari")),
        }
    }

    #[cfg(target_os = "windows")]
    fn default_data_dir_for_type(browser_type: BrowserType) -> PathBuf {
        let local = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\Users\\Default\\AppData\\Local"));
        match browser_type {
            BrowserType::Brave => local.join("BraveSoftware\\Brave-Browser\\User Data"),
            BrowserType::Chrome => local.join("Google\\Chrome\\User Data"),
            BrowserType::Chromium => local.join("Chromium\\User Data"),
            BrowserType::Edge => local.join("Microsoft\\Edge\\User Data"),
            BrowserType::Opera => local.join("Opera Software\\Opera Stable"),
            BrowserType::Vivaldi => local.join("Vivaldi\\User Data"),
            BrowserType::Firefox => dirs::home_dir()
                .map(|d| d.join("AppData\\Roaming\\Mozilla\\Firefox"))
                .unwrap_or_else(|| {
                    PathBuf::from("C:\\Users\\Default\\AppData\\Roaming\\Mozilla\\Firefox")
                }),
            // Safari is not available on Windows - return empty path that won't exist
            BrowserType::Safari => {
                PathBuf::from("C:\\Unsupported\\safari-not-available-on-windows")
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn default_data_dir_for_type(_browser_type: BrowserType) -> PathBuf {
        PathBuf::from("/tmp")
    }

    /// Detect browser by type.
    pub fn detect(browser_type: BrowserType) -> Option<BrowserInstallation> {
        match browser_type {
            BrowserType::Brave => Self::detect_brave(),
            BrowserType::Chrome => Self::detect_chrome(),
            BrowserType::Chromium => Self::detect_chromium(),
            BrowserType::Edge => Self::detect_edge(),
            BrowserType::Opera => Self::detect_opera(),
            BrowserType::Vivaldi => Self::detect_vivaldi(),
            BrowserType::Firefox => Self::detect_firefox(),
            BrowserType::Safari => Self::detect_safari(),
        }
    }

    /// Get the preferred browser (Brave > Chrome > Chromium > Edge > Opera > Vivaldi).
    ///
    /// Only returns browsers that support CDP automation.
    pub fn preferred() -> Option<BrowserInstallation> {
        Self::detect_brave()
            .or_else(Self::detect_chrome)
            .or_else(Self::detect_chromium)
            .or_else(Self::detect_edge)
            .or_else(Self::detect_opera)
            .or_else(Self::detect_vivaldi)
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
        println!("Detected {} browsers:", browsers.len());
        for browser in &browsers {
            println!(
                "  - {} ({}) at {:?} (valid: {}, CDP: {})",
                browser.browser_type,
                browser.browser_type.engine(),
                browser.executable_path,
                browser.is_valid(),
                browser.browser_type.supports_cdp()
            );
        }
    }

    #[test]
    fn test_detect_cdp_capable() {
        let cdp_browsers = BrowserDetector::detect_cdp_capable();
        println!("CDP-capable browsers: {}", cdp_browsers.len());
        for browser in &cdp_browsers {
            assert!(browser.browser_type.supports_cdp());
        }
    }

    #[test]
    fn test_browser_type_from_str() {
        assert_eq!("brave".parse::<BrowserType>().unwrap(), BrowserType::Brave);
        assert_eq!(
            "chrome".parse::<BrowserType>().unwrap(),
            BrowserType::Chrome
        );
        assert_eq!(
            "google-chrome".parse::<BrowserType>().unwrap(),
            BrowserType::Chrome
        );
        assert_eq!(
            "firefox".parse::<BrowserType>().unwrap(),
            BrowserType::Firefox
        );
        assert_eq!(
            "safari".parse::<BrowserType>().unwrap(),
            BrowserType::Safari
        );
        assert_eq!("opera".parse::<BrowserType>().unwrap(), BrowserType::Opera);
        assert_eq!(
            "vivaldi".parse::<BrowserType>().unwrap(),
            BrowserType::Vivaldi
        );
        assert_eq!("edge".parse::<BrowserType>().unwrap(), BrowserType::Edge);
        assert_eq!("msedge".parse::<BrowserType>().unwrap(), BrowserType::Edge);
    }

    #[test]
    fn test_browser_type_cdp_support() {
        // Chromium-based should support CDP
        assert!(BrowserType::Brave.supports_cdp());
        assert!(BrowserType::Chrome.supports_cdp());
        assert!(BrowserType::Chromium.supports_cdp());
        assert!(BrowserType::Edge.supports_cdp());
        assert!(BrowserType::Opera.supports_cdp());
        assert!(BrowserType::Vivaldi.supports_cdp());

        // Non-Chromium should not support CDP
        assert!(!BrowserType::Firefox.supports_cdp());
        assert!(!BrowserType::Safari.supports_cdp());
    }

    #[test]
    fn test_browser_type_engine() {
        assert_eq!(BrowserType::Chrome.engine(), "Chromium/Blink");
        assert_eq!(BrowserType::Firefox.engine(), "Gecko");
        assert_eq!(BrowserType::Safari.engine(), "WebKit");
    }

    #[test]
    fn test_all_browser_types() {
        let all = BrowserType::all();
        assert_eq!(all.len(), 8);

        let cdp = BrowserType::cdp_supported();
        assert_eq!(cdp.len(), 6);
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

    #[test]
    fn test_launch_config_cdp_validation() {
        let firefox = BrowserInstallation {
            browser_type: BrowserType::Firefox,
            executable_path: PathBuf::from("/usr/bin/firefox"),
            user_data_dir: PathBuf::from("/home/user/.mozilla/firefox"),
            version: None,
        };

        // Firefox doesn't support CDP - config should still work but caller should check
        assert!(!firefox.browser_type.supports_cdp());
    }
}
