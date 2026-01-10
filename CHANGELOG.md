# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING**: Renamed crate from `embeddenator-webpuppet` to `webpuppet`
- Simplified all internal references from embeddenator naming
- Previous version (embeddenator-webpuppet v0.1.0-alpha.3) has been yanked from crates.io

## [0.1.0-alpha.3] - 2025-01-19

### Added
- Multi-browser support: Extended from 4 to 8 browser types (Brave, Chrome, Chromium, Edge, Opera, Vivaldi, Firefox, Safari)
- Cross-platform browser detection for Linux, macOS, and Windows
- Support for Flatpak and Snap package formats on Linux
- CDP capability detection via `supports_cdp()` and `detect_cdp_capable()`
- Browser engine identification via `engine()` method (Chromium, Gecko, WebKit)
- `FromStr` implementation for flexible browser name parsing
- `is_chromium_based()` helper method

### Changed
- CI: Bumped softprops/action-gh-release from 1 to 2
- CI: Bumped actions/checkout from 4 to 6
- CI: Added OpenSSL installation for Firefox feature support
- CI: Removed ARM64 self-hosted build job
- Session auto-detection now uses `detect_cdp_capable()` for automation-ready browsers only
- Updated browser priority ordering to include new browser types

## [0.1.0-alpha.2] - 2024-12-20

### Added
- Comprehensive security hardening and MCP server preparation
- Modern platform focus (Linux, macOS, Windows 10+)
- Standardized GitHub workflows and configs
- Security audit configuration

### Security
- Implemented maximum security hardening measures
- Added security auditing with cargo-deny

## [0.1.0-alpha.1] - 2024-12-19

### Added
- Initial alpha release
- Core browser automation functionality
- Support for multiple AI providers (ChatGPT, Claude, Gemini, Grok, Kaggle, NotebookLM, Perplexity)
- Session management and credential handling
- Rate limiting and intervention detection
- Permission and security controls
- Configuration management

[Unreleased]: https://github.com/tzervas/webpuppet-rs/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/tzervas/webpuppet-rs/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/tzervas/webpuppet-rs/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/tzervas/webpuppet-rs/releases/tag/v0.1.0-alpha.1
