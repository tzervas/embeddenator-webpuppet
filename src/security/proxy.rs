//! MCP security proxy for enforced tool call routing.
//!
//! Provides a stateful connection model for downstream MCP servers.
//! All tool calls and results are routed through the security pipeline
//! before being forwarded, ensuring mandatory screening.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::detectors::{Direction, Verdict};
use super::pipeline::{PipelineConfig, PipelineResult, SecurityPipeline};

/// Configuration for an upstream MCP server connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Unique identifier for this server.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Transport type.
    pub transport: McpTransport,
    /// Whether this server's traffic requires screening.
    pub screening_enabled: bool,
    /// Override pipeline config for this specific server.
    pub pipeline_override: Option<PipelineConfigOverride>,
}

/// Transport configuration for connecting to an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpTransport {
    /// Stdio transport (command + args).
    Stdio {
        /// Command to execute.
        command: String,
        /// Command arguments.
        args: Vec<String>,
    },
    /// HTTP/SSE transport.
    Http {
        /// Server URL.
        url: String,
    },
}

/// Per-server pipeline configuration overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfigOverride {
    /// Override injection detection.
    pub enable_injection: Option<bool>,
    /// Override PII detection.
    pub enable_pii: Option<bool>,
    /// Override secrets detection.
    pub enable_secrets: Option<bool>,
    /// Override auto-redaction.
    pub auto_redact: Option<bool>,
    /// Override risk threshold.
    pub risk_threshold: Option<f32>,
}

/// Represents the state of a connected MCP server.
#[derive(Debug, Clone)]
pub struct McpServerState {
    /// Server configuration.
    pub config: McpServerConfig,
    /// Connection status.
    pub status: ConnectionStatus,
    /// Tools registered by this server.
    pub tools: Vec<McpToolInfo>,
    /// Screening statistics.
    pub stats: ScreeningStats,
}

/// Connection status for an MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Not yet connected.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection failed.
    Failed,
}

/// Information about a tool registered by a downstream MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolInfo {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Server ID that provides this tool.
    pub server_id: String,
}

/// Statistics for security screening on an MCP connection.
#[derive(Debug, Clone, Default)]
pub struct ScreeningStats {
    /// Total tool calls screened.
    pub calls_screened: u64,
    /// Total tool results screened.
    pub results_screened: u64,
    /// Total findings detected.
    pub findings_total: u64,
    /// Total calls blocked.
    pub calls_blocked: u64,
    /// Total content redacted.
    pub content_redacted: u64,
}

/// Result of screening an MCP tool call.
#[derive(Debug, Clone)]
pub struct McpScreeningResult {
    /// The pipeline result for the tool call arguments.
    pub call_result: PipelineResult,
    /// Whether the call should proceed.
    pub allow: bool,
    /// The (potentially redacted) arguments to forward.
    pub screened_arguments: String,
}

/// Result of screening an MCP tool response.
#[derive(Debug, Clone)]
pub struct McpResponseScreeningResult {
    /// The pipeline result for the tool response.
    pub response_result: PipelineResult,
    /// Whether the response should be returned to the caller.
    pub allow: bool,
    /// The (potentially redacted) response to return.
    pub screened_response: String,
}

/// The MCP security proxy.
///
/// Manages connections to downstream MCP servers and enforces security
/// screening on all tool calls and responses. This is the enforcement
/// point that ensures no MCP traffic bypasses security screening.
pub struct McpSecurityProxy {
    pipeline: Arc<SecurityPipeline>,
    servers: Arc<RwLock<HashMap<String, McpServerState>>>,
    stats: Arc<RwLock<ScreeningStats>>,
}

impl McpSecurityProxy {
    /// Create a new MCP security proxy with the given pipeline.
    pub fn new(pipeline: Arc<SecurityPipeline>) -> Self {
        Self {
            pipeline,
            servers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ScreeningStats::default())),
        }
    }

    /// Create with custom pipeline configuration.
    pub fn with_config(config: PipelineConfig) -> Self {
        Self::new(Arc::new(SecurityPipeline::with_config(config)))
    }

    /// Register an MCP server for proxied connections.
    pub async fn register_server(&self, config: McpServerConfig) {
        let id = config.id.clone();
        let state = McpServerState {
            config,
            status: ConnectionStatus::Disconnected,
            tools: Vec::new(),
            stats: ScreeningStats::default(),
        };

        let mut servers = self.servers.write().await;
        servers.insert(id.clone(), state);
        tracing::info!(server_id = %id, "MCP server registered with security proxy");
    }

    /// Unregister an MCP server.
    pub async fn unregister_server(&self, server_id: &str) {
        let mut servers = self.servers.write().await;
        servers.remove(server_id);
        tracing::info!(server_id = %server_id, "MCP server unregistered from security proxy");
    }

    /// Register tools for a server (called after connection/initialization).
    pub async fn register_tools(&self, server_id: &str, tools: Vec<McpToolInfo>) {
        let mut servers = self.servers.write().await;
        if let Some(state) = servers.get_mut(server_id) {
            state.tools = tools;
            state.status = ConnectionStatus::Connected;
        }
    }

    /// Get all registered tools across all servers.
    pub async fn all_tools(&self) -> Vec<McpToolInfo> {
        let servers = self.servers.read().await;
        servers
            .values()
            .filter(|s| s.status == ConnectionStatus::Connected)
            .flat_map(|s| s.tools.clone())
            .collect()
    }

    /// Screen an MCP tool call before forwarding to the downstream server.
    ///
    /// This is the mandatory screening point for all outgoing tool calls.
    /// It screens the tool name and arguments for injection attacks and
    /// other security threats.
    pub async fn screen_tool_call(
        &self,
        server_id: &str,
        tool_name: &str,
        arguments: &str,
    ) -> McpScreeningResult {
        // Build the content to screen: tool name + arguments
        let content = format!("tool:{}\n{}", tool_name, arguments);

        let result = self.pipeline.screen(&content, Direction::McpToolCall);

        let allow = result.is_allowed();
        let screened_arguments = if let Some(ref redacted) = result.redacted_content {
            // Extract just the arguments part (skip the tool: line)
            redacted
                .split_once('\n')
                .map(|x| x.1)
                .unwrap_or(redacted)
                .to_string()
        } else {
            arguments.to_string()
        };

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.calls_screened += 1;
            stats.findings_total += result.findings.len() as u64;
            if !allow {
                stats.calls_blocked += 1;
            }
            if result.redacted_content.is_some() {
                stats.content_redacted += 1;
            }
        }

        // Update per-server stats
        {
            let mut servers = self.servers.write().await;
            if let Some(state) = servers.get_mut(server_id) {
                state.stats.calls_screened += 1;
                state.stats.findings_total += result.findings.len() as u64;
                if !allow {
                    state.stats.calls_blocked += 1;
                }
            }
        }

        if !allow {
            tracing::warn!(
                server_id = %server_id,
                tool = %tool_name,
                verdict = %result.verdict,
                findings = result.findings.len(),
                "MCP tool call BLOCKED by security proxy"
            );
        }

        McpScreeningResult {
            call_result: result,
            allow,
            screened_arguments,
        }
    }

    /// Screen an MCP tool response before returning to the caller.
    ///
    /// This is the mandatory screening point for all incoming tool results.
    /// It screens for PII, secrets, and content manipulation.
    pub async fn screen_tool_response(
        &self,
        server_id: &str,
        tool_name: &str,
        response: &str,
    ) -> McpResponseScreeningResult {
        let result = self.pipeline.screen(response, Direction::McpToolResult);

        let allow = result.is_allowed();
        let screened_response = result
            .redacted_content
            .clone()
            .unwrap_or_else(|| response.to_string());

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.results_screened += 1;
            stats.findings_total += result.findings.len() as u64;
            if !allow {
                stats.calls_blocked += 1;
            }
            if result.redacted_content.is_some() {
                stats.content_redacted += 1;
            }
        }

        // Update per-server stats
        {
            let mut servers = self.servers.write().await;
            if let Some(state) = servers.get_mut(server_id) {
                state.stats.results_screened += 1;
                state.stats.findings_total += result.findings.len() as u64;
            }
        }

        if !allow {
            tracing::warn!(
                server_id = %server_id,
                tool = %tool_name,
                verdict = %result.verdict,
                findings = result.findings.len(),
                "MCP tool response BLOCKED by security proxy"
            );
        }

        McpResponseScreeningResult {
            response_result: result,
            allow,
            screened_response,
        }
    }

    /// Get aggregate screening statistics.
    pub async fn stats(&self) -> ScreeningStats {
        self.stats.read().await.clone()
    }

    /// Get per-server states.
    pub async fn server_states(&self) -> Vec<McpServerState> {
        let servers = self.servers.read().await;
        servers.values().cloned().collect()
    }

    /// Get the underlying security pipeline.
    pub fn pipeline(&self) -> &SecurityPipeline {
        &self.pipeline
    }

    /// Check if a server is registered and connected.
    pub async fn is_server_connected(&self, server_id: &str) -> bool {
        let servers = self.servers.read().await;
        servers
            .get(server_id)
            .map(|s| s.status == ConnectionStatus::Connected)
            .unwrap_or(false)
    }

    /// Find which server provides a given tool.
    pub async fn find_tool_server(&self, tool_name: &str) -> Option<String> {
        let servers = self.servers.read().await;
        for state in servers.values() {
            if state.tools.iter().any(|t| t.name == tool_name) {
                return Some(state.config.id.clone());
            }
        }
        None
    }

    /// Produce a screening report for a given verdict.
    pub fn format_blocked_message(verdict: &Verdict, findings_count: usize) -> String {
        match verdict {
            Verdict::Blocked => format!(
                "Content blocked by security policy ({} finding(s) detected)",
                findings_count
            ),
            Verdict::Redacted => format!(
                "Content redacted ({} sensitive item(s) masked)",
                findings_count
            ),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_registration() {
        let proxy = McpSecurityProxy::with_config(PipelineConfig::default());

        proxy
            .register_server(McpServerConfig {
                id: "test-server".into(),
                name: "Test Server".into(),
                transport: McpTransport::Stdio {
                    command: "test-mcp".into(),
                    args: vec![],
                },
                screening_enabled: true,
                pipeline_override: None,
            })
            .await;

        proxy
            .register_tools(
                "test-server",
                vec![McpToolInfo {
                    name: "test_tool".into(),
                    description: "A test tool".into(),
                    server_id: "test-server".into(),
                }],
            )
            .await;

        let tools = proxy.all_tools().await;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "test_tool");
    }

    #[tokio::test]
    async fn test_proxy_screens_tool_call() {
        let proxy = McpSecurityProxy::with_config(PipelineConfig::default());

        proxy
            .register_server(McpServerConfig {
                id: "test".into(),
                name: "Test".into(),
                transport: McpTransport::Stdio {
                    command: "test".into(),
                    args: vec![],
                },
                screening_enabled: true,
                pipeline_override: None,
            })
            .await;

        // Clean call should pass
        let result = proxy
            .screen_tool_call("test", "read_file", r#"{"path": "/tmp/test.txt"}"#)
            .await;
        assert!(result.allow);

        // Call with injection should be flagged
        let result = proxy
            .screen_tool_call("test", "read_file", r#"{"path": "../../etc/passwd"}"#)
            .await;
        assert!(!result.call_result.findings.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_screens_response() {
        let proxy = McpSecurityProxy::with_config(PipelineConfig {
            block_on_high: false, // Don't block, just redact
            ..Default::default()
        });

        proxy
            .register_server(McpServerConfig {
                id: "test".into(),
                name: "Test".into(),
                transport: McpTransport::Stdio {
                    command: "test".into(),
                    args: vec![],
                },
                screening_enabled: true,
                pipeline_override: None,
            })
            .await;

        let result = proxy
            .screen_tool_response(
                "test",
                "read_file",
                "The user's email is user@example.com",
            )
            .await;
        assert!(!result.response_result.findings.is_empty());
    }
}
