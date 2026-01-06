//! Containerized WebPuppet executor for secure isolation.
//!
//! This module provides secure containerized execution of webpuppet operations
//! to prevent malicious code execution, data exfiltration, and other security risks.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::providers::Provider;
use crate::puppet::{PromptRequest, PromptResponse};
use crate::sanitization::{SanitizationConfig, Sanitizer};

/// Configuration for containerized execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerizedConfig {
    /// Docker image to use for execution.
    pub image: String,
    /// CPU limit per container.
    pub cpu_limit: String,
    /// Memory limit per container.
    pub memory_limit: String,
    /// Network mode (recommend "none" for security).
    pub network_mode: String,
    /// Execution timeout in seconds.
    pub timeout_seconds: u32,
    /// Maximum concurrent containers.
    pub max_concurrent: usize,
    /// Working directory for temporary files.
    pub work_dir: PathBuf,
    /// Enable container logging.
    pub enable_logging: bool,
    /// Security policies.
    pub security: ContainerSecurityPolicy,
}

/// Security policies for container execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityPolicy {
    /// Disable network access.
    pub no_network: bool,
    /// Read-only filesystem.
    pub readonly_root: bool,
    /// Drop all capabilities.
    pub drop_capabilities: bool,
    /// Run as non-root user.
    pub non_root_user: String,
    /// Ulimits for resource constraints.
    pub ulimits: HashMap<String, String>,
    /// Environment variable allowlist.
    pub allowed_env_vars: Vec<String>,
}

impl Default for ContainerizedConfig {
    fn default() -> Self {
        let mut ulimits = HashMap::new();
        ulimits.insert("nproc".into(), "32".into());      // Max processes
        ulimits.insert("fsize".into(), "100000000".into()); // Max file size: 100MB
        ulimits.insert("nofile".into(), "1024".into());    // Max open files

        Self {
            image: "embeddenator-webpuppet:secure".into(),
            cpu_limit: "1.0".into(),
            memory_limit: "1g".into(),
            network_mode: "none".into(),
            timeout_seconds: 60,
            max_concurrent: 4,
            work_dir: std::env::temp_dir().join("webpuppet-containers"),
            enable_logging: true,
            security: ContainerSecurityPolicy {
                no_network: true,
                readonly_root: true,
                drop_capabilities: true,
                non_root_user: "webpuppet".into(),
                ulimits,
                allowed_env_vars: vec!["RUST_LOG".into()],
            },
        }
    }
}

/// Result of containerized execution.
#[derive(Debug, Clone)]
pub struct ContainerExecutionResult {
    /// Exit code from container.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Execution time.
    pub duration: Duration,
    /// Container ID used.
    pub container_id: String,
    /// Resource usage statistics.
    pub resource_stats: ResourceStats,
}

/// Resource usage statistics.
#[derive(Debug, Clone, Default)]
pub struct ResourceStats {
    /// Maximum memory used in bytes.
    pub max_memory_usage: u64,
    /// CPU time used in milliseconds.
    pub cpu_time_ms: u64,
    /// Network bytes (should be 0 for isolated containers).
    pub network_bytes: u64,
    /// Disk I/O bytes.
    pub disk_io_bytes: u64,
}

/// Containerized WebPuppet executor.
pub struct ContainerizedExecutor {
    config: ContainerizedConfig,
    sanitizer: Sanitizer,
    /// Currently running containers for cleanup.
    running_containers: parking_lot::RwLock<HashMap<String, std::process::Child>>,
}

impl ContainerizedExecutor {
    /// Create a new containerized executor.
    pub fn new(config: ContainerizedConfig, sanitizer: Sanitizer) -> Result<Self> {
        // Ensure work directory exists
        std::fs::create_dir_all(&config.work_dir)
            .map_err(|e| Error::Config(format!("Failed to create work directory: {}", e)))?;

        Ok(Self {
            config,
            sanitizer,
            running_containers: parking_lot::RwLock::new(HashMap::new()),
        })
    }

    /// Execute a websearch query in a secure container.
    pub async fn execute_websearch(
        &self,
        provider: Provider,
        request: &PromptRequest,
    ) -> Result<PromptResponse> {
        // First, sanitize the input
        let sanitized_input = self.sanitizer.sanitize_input(&request.message)
            .map_err(|e| Error::Security(format!("Input sanitization failed: {}", e)))?;

        if sanitized_input.blocked {
            return Err(Error::Security(format!(
                "Query blocked due to security issues: {:?}",
                sanitized_input.issues
            )));
        }

        // Create execution context
        let execution_id = Uuid::new_v4().to_string();
        let work_path = self.config.work_dir.join(&execution_id);
        std::fs::create_dir_all(&work_path)
            .map_err(|e| Error::Config(format!("Failed to create execution directory: {}", e)))?;

        // Prepare input files
        let input_file = work_path.join("input.json");
        let output_file = work_path.join("output.json");
        let config_file = work_path.join("config.json");

        let container_request = ContainerRequest {
            provider,
            message: sanitized_input.sanitized.clone(),
            context: request.context.clone(),
            conversation_id: request.conversation_id.clone(),
            attachments: request.attachments.clone(),
            metadata: request.metadata.clone(),
        };

        // Write input files
        self.write_container_input(&input_file, &container_request)?;
        self.write_container_config(&config_file)?;

        // Execute in container
        let execution_result = self.run_container(&execution_id, &input_file, &output_file, &config_file).await?;

        // Read and validate results
        let mut response = self.read_container_output(&output_file)?;

        // Sanitize output
        let sanitized_output = self.sanitizer.sanitize_output(&response.text)
            .map_err(|e| Error::Security(format!("Output sanitization failed: {}", e)))?;

        if sanitized_output.blocked {
            return Err(Error::Security(format!(
                "Response blocked due to security issues: {:?}",
                sanitized_output.issues
            )));
        }

        response.text = sanitized_output.sanitized;

        // Cleanup
        let _ = std::fs::remove_dir_all(work_path);

        // Log security events if issues were found
        if !sanitized_input.issues.is_empty() || !sanitized_output.issues.is_empty() {
            tracing::warn!(
                "Security issues detected in containerized execution {}: Input: {:?}, Output: {:?}",
                execution_id,
                sanitized_input.issues,
                sanitized_output.issues
            );
        }

        Ok(response)
    }

    /// Write input data for container execution.
    fn write_container_input(&self, path: &Path, request: &ContainerRequest) -> Result<()> {
        let json = serde_json::to_string_pretty(request)
            .map_err(|e| Error::Config(format!("Failed to serialize request: {}", e)))?;

        std::fs::write(path, json)
            .map_err(|e| Error::Config(format!("Failed to write input file: {}", e)))?;

        Ok(())
    }

    /// Write container configuration.
    fn write_container_config(&self, path: &Path) -> Result<()> {
        let config = ContainerExecutionConfig {
            timeout_seconds: self.config.timeout_seconds,
            enable_logging: self.config.enable_logging,
            max_memory_mb: self.parse_memory_limit()?,
            max_cpu_cores: self.parse_cpu_limit()?,
        };

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, json)
            .map_err(|e| Error::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Execute the container with security restrictions.
    async fn run_container(
        &self,
        execution_id: &str,
        input_file: &Path,
        output_file: &Path,
        config_file: &Path,
    ) -> Result<ContainerExecutionResult> {
        let container_name = format!("webpuppet-{}", execution_id);
        
        let start_time = std::time::Instant::now();

        // Build docker command with security restrictions
        let mut cmd = Command::new("docker");
        
        cmd.args(&["run", "--rm"]);
        cmd.args(&["--name", &container_name]);
        
        // Resource limits
        cmd.args(&["--cpus", &self.config.cpu_limit]);
        cmd.args(&["--memory", &self.config.memory_limit]);
        
        // Security restrictions
        if self.config.security.no_network {
            cmd.args(&["--network", "none"]);
        } else {
            cmd.args(&["--network", &self.config.network_mode]);
        }
        
        if self.config.security.readonly_root {
            cmd.arg("--read-only");
        }
        
        if self.config.security.drop_capabilities {
            cmd.args(&["--cap-drop", "ALL"]);
        }
        
        // Run as non-root user
        cmd.args(&["--user", &self.config.security.non_root_user]);
        
        // Add ulimits
        for (limit, value) in &self.config.security.ulimits {
            cmd.args(&["--ulimit", &format!("{}={}", limit, value)]);
        }
        
        // Mount input files (read-only)
        cmd.args(&["--volume", &format!("{}:/tmp/input.json:ro", input_file.display())]);
        cmd.args(&["--volume", &format!("{}:/tmp/config.json:ro", config_file.display())]);
        cmd.args(&["--volume", &format!("{}:/tmp/output.json:rw", output_file.display())]);
        
        // Set allowed environment variables
        for env_var in &self.config.security.allowed_env_vars {
            if let Ok(value) = std::env::var(env_var) {
                cmd.args(&["--env", &format!("{}={}", env_var, value)]);
            }
        }
        
        // Working directory (writable tmpfs)
        cmd.args(&["--tmpfs", "/tmp/work:exec,size=100m"]);
        cmd.args(&["--workdir", "/tmp/work"]);
        
        // Timeout using docker itself
        cmd.args(&["--stop-timeout", &self.config.timeout_seconds.to_string()]);
        
        // Image and command
        cmd.arg(&self.config.image);
        cmd.args(&["webpuppet-execute", "/tmp/input.json", "/tmp/output.json", "/tmp/config.json"]);

        // Execute with timeout
        let timeout = Duration::from_secs(self.config.timeout_seconds as u64 + 10); // Extra buffer
        let output = tokio::time::timeout(timeout, cmd.output()).await
            .map_err(|_| Error::Timeout(self.config.timeout_seconds as u64 * 1000))?
            .map_err(|e| Error::Browser(format!("Container execution failed: {}", e)))?;

        let duration = start_time.elapsed();

        // Get resource statistics (if available)
        let resource_stats = self.get_container_stats(&container_name).await.unwrap_or_default();

        Ok(ContainerExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration,
            container_id: container_name,
            resource_stats,
        })
    }

    /// Read output from container execution.
    fn read_container_output(&self, path: &Path) -> Result<PromptResponse> {
        if !path.exists() {
            return Err(Error::Browser("Container did not produce output file".into()));
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read output file: {}", e)))?;

        let response: PromptResponse = serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse output: {}", e)))?;

        Ok(response)
    }

    /// Get container resource statistics.
    async fn get_container_stats(&self, container_name: &str) -> Result<ResourceStats> {
        let output = Command::new("docker")
            .args(&["stats", "--no-stream", "--format", "table {{.MemUsage}},{{.CPUPerc}},{{.NetIO}},{{.BlockIO}}", container_name])
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let stats_str = String::from_utf8_lossy(&output.stdout);
                // Parse stats (simplified - would need proper parsing for production)
                Ok(ResourceStats::default())
            }
            _ => Ok(ResourceStats::default()),
        }
    }

    /// Parse memory limit to MB.
    fn parse_memory_limit(&self) -> Result<u32> {
        let limit = &self.config.memory_limit;
        if let Some(stripped) = limit.strip_suffix('g').or(limit.strip_suffix('G')) {
            stripped.parse::<u32>().map(|g| g * 1024).map_err(|_| Error::Config("Invalid memory limit".into()))
        } else if let Some(stripped) = limit.strip_suffix('m').or(limit.strip_suffix('M')) {
            stripped.parse::<u32>().map_err(|_| Error::Config("Invalid memory limit".into()))
        } else {
            Err(Error::Config("Memory limit must end with 'g', 'G', 'm', or 'M'".into()))
        }
    }

    /// Parse CPU limit.
    fn parse_cpu_limit(&self) -> Result<f32> {
        self.config.cpu_limit.parse::<f32>()
            .map_err(|_| Error::Config("Invalid CPU limit".into()))
    }

    /// Cleanup all running containers.
    pub async fn cleanup(&self) -> Result<()> {
        let container_names: Vec<String> = {
            let guard = self.running_containers.read();
            guard.keys().cloned().collect()
        };
        
        for container_name in container_names {
            let _ = Command::new("docker")
                .args(&["stop", &container_name])
                .output()
                .await;
                
            let _ = Command::new("docker")
                .args(&["rm", "-f", &container_name])
                .output()
                .await;
        }
        
        self.running_containers.write().clear();
        
        Ok(())
    }
}

impl Drop for ContainerizedExecutor {
    fn drop(&mut self) {
        // Best effort cleanup on drop
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(rt) = rt {
            let _ = rt.block_on(self.cleanup());
        }
    }
}

/// Request structure for container execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContainerRequest {
    provider: Provider,
    message: String,
    context: Option<String>,
    conversation_id: Option<String>,
    attachments: Vec<crate::puppet::Attachment>,
    metadata: HashMap<String, String>,
}

/// Configuration for container execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContainerExecutionConfig {
    timeout_seconds: u32,
    enable_logging: bool,
    max_memory_mb: u32,
    max_cpu_cores: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitization::SanitizationConfig;

    #[tokio::test]
    async fn test_containerized_config() {
        let config = ContainerizedConfig::default();
        assert_eq!(config.network_mode, "none");
        assert!(config.security.no_network);
        assert!(config.security.drop_capabilities);
    }

    #[tokio::test]
    async fn test_memory_parsing() {
        let config = ContainerizedConfig {
            memory_limit: "2g".into(),
            ..Default::default()
        };
        
        let sanitizer = Sanitizer::new().unwrap();
        let executor = ContainerizedExecutor::new(config, sanitizer).unwrap();
        
        assert_eq!(executor.parse_memory_limit().unwrap(), 2048);
    }

    #[test]
    fn test_security_policy() {
        let policy = ContainerSecurityPolicy {
            no_network: true,
            readonly_root: true,
            drop_capabilities: true,
            non_root_user: "webpuppet".into(),
            ulimits: std::collections::HashMap::new(),
            allowed_env_vars: vec!["RUST_LOG".into()],
        };
        
        assert!(policy.no_network);
        assert_eq!(policy.non_root_user, "webpuppet");
    }
}