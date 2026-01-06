# Contributing to embeddenator-webpuppet

Thank you for your interest in contributing to embeddenator-webpuppet! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites
- Rust 1.75+ (latest stable recommended)
- Chrome 120+, Chromium 120+, or Brave 1.60+ for testing
- Modern operating system (Linux, macOS 13+, Windows 11 22H2+)
- Git for version control

### Setup
1. Fork and clone the repository
2. Install dependencies: `cargo build`
3. Run tests: `cargo test`
4. Run security checks: `cargo audit && cargo deny check`

## Platform Support

This project focuses on modern platforms and environments:

**Operating Systems (Minimum Versions):**
- Linux: Ubuntu 22.04 LTS, Fedora 38, RHEL 9, Debian 12, or equivalent
- macOS: 13.0 Ventura or later
- Windows: 11 22H2 or later

**Browser Requirements:**
- Chrome/Chromium: 120+
- Brave: 1.60+
- Edge: 120+ (Windows/macOS)

**Development Environment:**
- Rust: 1.75+ (uses latest stable features)
- Node.js: 20+ (if using JavaScript tooling)

We intentionally do not support legacy platforms to focus development resources on modern, secure environments.

## Code Standards

### Commit Messages
We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes  
- `docs`: Documentation changes
- `style`: Code formatting (no logic changes)
- `refactor`: Code restructuring (no feature changes)
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `security`: Security-related changes

**Examples:**
```
feat(providers): add Claude file upload support
fix(session): resolve authentication timeout issues
docs: update installation instructions
security(deps): update vulnerable dependencies
```

### Branch Naming
Follow this pattern: `type/description-in-kebab-case`

**Examples:**
- `feat/add-conversation-branching`
- `fix/session-recovery-bug`
- `docs/api-documentation-update`
- `refactor/provider-trait-simplification`

### Code Style
- Use `rustfmt` for formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy`
- Write documentation for all public APIs
- Include examples in documentation where helpful
- Follow Rust naming conventions

## Pull Request Process

### Before Submitting
1. Ensure all tests pass: `cargo test`
2. Run security checks: `cargo audit && cargo deny check`
3. Format code: `cargo fmt`
4. Check for lint issues: `cargo clippy`
5. Update documentation if needed
6. Add tests for new functionality

### PR Guidelines
- Use a clear, descriptive title
- Reference related issues: `Closes #123`
- Provide a detailed description of changes
- Include testing instructions if applicable
- Keep changes focused and atomic

### Review Process
- All PRs require review before merging
- Address all review feedback
- Maintain a clean commit history
- Ensure CI checks pass

## Security

### Reporting Security Issues
- **Do not** create public issues for security vulnerabilities
- Email security reports to: [security contact needed]
- Include detailed reproduction steps
- Allow time for response before public disclosure

### Security Guidelines
- All user input must be validated and sanitized
- Credentials must never be logged or stored in plaintext
- Follow secure coding practices
- Regular dependency updates and audits
- Implement appropriate rate limiting

## Testing

### Test Categories
- **Unit tests**: Test individual components
- **Integration tests**: Test component interactions  
- **End-to-end tests**: Test complete user workflows
- **Security tests**: Test security controls and validation

### Test Requirements
- New features must include tests
- Bug fixes should include regression tests
- Tests must be reliable and deterministic
- Use descriptive test names and assertions

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test category
cargo test --test integration

# Run with output
cargo test -- --nocapture
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
