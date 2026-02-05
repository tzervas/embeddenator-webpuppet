//! Display mode management for browser visibility.
//!
//! Defines the three display modes for webpuppet browser sessions:
//! - **Headless**: No visible UI. The browser runs in headless mode, suitable for
//!   automation and CI/CD. Output is via terminal/logs only.
//! - **HeadsUp**: An interactive browser window pops up so users can see exactly
//!   what is being done and intervene as needed (for security or any other reason).
//! - **Dashboard**: Full monitoring dashboard with dual browsers -- a headless
//!   automation browser and a visible monitoring browser showing DevTools, real-time
//!   screenshots, and security screening status.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Display mode for browser sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DisplayMode {
    /// Headless mode: no visible browser UI.
    ///
    /// The browser runs entirely in the background. All output flows through
    /// the terminal/logs. This is the mode for unattended automation.
    #[default]
    Headless,

    /// Heads-up mode: interactive popup browser window.
    ///
    /// A visible browser window opens, allowing the user to see exactly what
    /// the automation is doing in real time. Users can intervene directly in
    /// the browser window (e.g., solving CAPTCHAs, approving actions, or
    /// stopping operations they consider unsafe).
    HeadsUp,

    /// Dashboard mode: full monitoring with dual-head browsers.
    ///
    /// Runs a headless automation browser alongside a visible monitoring
    /// browser. The monitoring window mirrors the automation state, showing
    /// navigation, DevTools, and security screening status. Intended for
    /// security review, debugging, and auditing workflows.
    Dashboard,
}

impl DisplayMode {
    /// Whether the primary browser runs in headless mode.
    pub fn is_headless(&self) -> bool {
        matches!(self, DisplayMode::Headless | DisplayMode::Dashboard)
    }

    /// Whether a visible browser window should be launched.
    pub fn has_visible_window(&self) -> bool {
        matches!(self, DisplayMode::HeadsUp | DisplayMode::Dashboard)
    }

    /// Whether dual-head mode (monitoring window) is enabled.
    pub fn is_dual_head(&self) -> bool {
        matches!(self, DisplayMode::Dashboard)
    }

    /// Whether the user can directly interact with the browser.
    pub fn is_interactive(&self) -> bool {
        matches!(self, DisplayMode::HeadsUp)
    }
}

impl fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisplayMode::Headless => write!(f, "headless"),
            DisplayMode::HeadsUp => write!(f, "heads-up"),
            DisplayMode::Dashboard => write!(f, "dashboard"),
        }
    }
}

impl std::str::FromStr for DisplayMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "headless" => Ok(DisplayMode::Headless),
            "heads-up" | "headsup" | "heads_up" | "visible" | "headed" => Ok(DisplayMode::HeadsUp),
            "dashboard" | "dual-head" | "dual_head" | "dualhead" | "monitor" => {
                Ok(DisplayMode::Dashboard)
            }
            _ => Err(format!(
                "Unknown display mode '{}'. Expected: headless, heads-up, dashboard",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_headless() {
        assert_eq!(DisplayMode::default(), DisplayMode::Headless);
    }

    #[test]
    fn test_headless_properties() {
        let mode = DisplayMode::Headless;
        assert!(mode.is_headless());
        assert!(!mode.has_visible_window());
        assert!(!mode.is_dual_head());
        assert!(!mode.is_interactive());
    }

    #[test]
    fn test_headsup_properties() {
        let mode = DisplayMode::HeadsUp;
        assert!(!mode.is_headless());
        assert!(mode.has_visible_window());
        assert!(!mode.is_dual_head());
        assert!(mode.is_interactive());
    }

    #[test]
    fn test_dashboard_properties() {
        let mode = DisplayMode::Dashboard;
        assert!(mode.is_headless());
        assert!(mode.has_visible_window());
        assert!(mode.is_dual_head());
        assert!(!mode.is_interactive());
    }

    #[test]
    fn test_parse_display_mode() {
        assert_eq!(
            "headless".parse::<DisplayMode>().unwrap(),
            DisplayMode::Headless
        );
        assert_eq!(
            "heads-up".parse::<DisplayMode>().unwrap(),
            DisplayMode::HeadsUp
        );
        assert_eq!(
            "visible".parse::<DisplayMode>().unwrap(),
            DisplayMode::HeadsUp
        );
        assert_eq!(
            "dashboard".parse::<DisplayMode>().unwrap(),
            DisplayMode::Dashboard
        );
        assert_eq!(
            "dual-head".parse::<DisplayMode>().unwrap(),
            DisplayMode::Dashboard
        );
        assert!("invalid".parse::<DisplayMode>().is_err());
    }
}
