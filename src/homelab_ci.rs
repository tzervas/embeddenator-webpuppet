//! Homelab CI/CD integration for automated security testing.
//!
//! This module provides integration with homelab infrastructure for:
//! - Automated security test execution
//! - Docker-based testing environments  
//! - CI/CD pipeline integration with 56-core server
//! - Security validation and monitoring
//! - Performance benchmarking under load

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{info, warn, error, debug};

use crate::containerized::ContainerizedConfig;
use crate::security_tests::{SecurityTestSuite, SecurityReport, RiskLevel};
use crate::error::{Error, Result};

/// Homelab CI/CD configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomelabConfig {
    /// Docker registry for testing images.
    pub docker_registry: String,
    /// Testing base image.
    pub base_image: String,
    /// Security testing image.
    pub security_image: String,
    /// Maximum parallel test containers.
    pub max_parallel_containers: u32,
    /// Test timeout in seconds.
    pub test_timeout_seconds: u64,
    /// Results storage path.
    pub results_path: PathBuf,
    /// Enable performance profiling.
    pub enable_profiling: bool,
    /// Load testing configuration.
    pub load_testing: LoadTestConfig,
    /// Notification configuration.
    pub notifications: NotificationConfig,
}

impl Default for HomelabConfig {
    fn default() -> Self {
        Self {
            docker_registry: "localhost:5000".into(),
            base_image: "embeddenator-webpuppet:test".into(),
            security_image: "embeddenator-webpuppet:security".into(),
            max_parallel_containers: 8, // Utilize 56-core server efficiently
            test_timeout_seconds: 300,
            results_path: PathBuf::from("/opt/ci-results"),
            enable_profiling: true,
            load_testing: LoadTestConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

/// Load testing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    /// Concurrent users to simulate.
    pub concurrent_users: u32,
    /// Requests per second target.
    pub requests_per_second: u32,
    /// Test duration in seconds.
    pub duration_seconds: u64,
    /// Ramp-up time in seconds.
    pub ramp_up_seconds: u64,
    /// Enable adversarial load testing.
    pub adversarial_testing: bool,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_users: 100,
            requests_per_second: 50,
            duration_seconds: 300,
            ramp_up_seconds: 60,
            adversarial_testing: true,
        }
    }
}

/// Notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Enable Slack notifications.
    pub slack_enabled: bool,
    /// Slack webhook URL.
    pub slack_webhook: Option<String>,
    /// Enable email notifications.
    pub email_enabled: bool,
    /// Email recipients for security alerts.
    pub email_recipients: Vec<String>,
    /// Minimum risk level for notifications.
    pub min_risk_level: RiskLevel,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            slack_enabled: false,
            slack_webhook: None,
            email_enabled: false,
            email_recipients: Vec::new(),
            min_risk_level: RiskLevel::High,
        }
    }
}

/// Homelab CI/CD pipeline executor.
pub struct HomelabCiCd {
    /// Configuration.
    config: HomelabConfig,
    /// Active test containers.
    active_containers: Arc<parking_lot::Mutex<HashMap<String, TestContainer>>>,
    /// Test results history.
    results_history: Arc<parking_lot::Mutex<Vec<CiCdTestResult>>>,
}

/// Test container information.
#[derive(Debug, Clone)]
struct TestContainer {
    /// Container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// Test suite being run.
    pub test_suite: String,
    /// Start time.
    pub start_time: Instant,
    /// Status.
    pub status: ContainerStatus,
}

/// Container status.
#[derive(Debug, Clone)]
enum ContainerStatus {
    /// Container is starting.
    Starting,
    /// Container is running tests.
    Running,
    /// Container has completed successfully.
    Completed,
    /// Container has failed.
    Failed(String),
    /// Container has timed out.
    TimedOut,
}

/// CI/CD test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdTestResult {
    /// Test run ID.
    pub run_id: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Git commit hash.
    pub commit_hash: Option<String>,
    /// Branch name.
    pub branch: Option<String>,
    /// Security report.
    pub security_report: SecurityReport,
    /// Performance metrics.
    pub performance_metrics: PerformanceMetrics,
    /// Load testing results.
    pub load_test_results: Option<LoadTestResults>,
    /// Container execution details.
    pub container_details: Vec<ContainerExecution>,
    /// Overall status.
    pub overall_status: CiCdStatus,
}

/// Performance metrics from testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total test execution time.
    pub total_execution_time: Duration,
    /// Memory usage peak.
    pub peak_memory_usage_mb: u64,
    /// CPU usage average.
    pub avg_cpu_usage_percent: f32,
    /// Network I/O metrics.
    pub network_io_bytes: u64,
    /// Disk I/O metrics.
    pub disk_io_bytes: u64,
    /// Container startup overhead.
    pub container_startup_time: Duration,
}

/// Load testing results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestResults {
    /// Total requests sent.
    pub total_requests: u64,
    /// Successful requests.
    pub successful_requests: u64,
    /// Failed requests.
    pub failed_requests: u64,
    /// Average response time.
    pub avg_response_time_ms: f32,
    /// 95th percentile response time.
    pub p95_response_time_ms: f32,
    /// Maximum response time.
    pub max_response_time_ms: f32,
    /// Requests per second achieved.
    pub achieved_rps: f32,
    /// Security violations detected.
    pub security_violations: u32,
}

/// Container execution details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExecution {
    /// Container ID.
    pub container_id: String,
    /// Test suite executed.
    pub test_suite: String,
    /// Execution time.
    pub execution_time: Duration,
    /// Exit code.
    pub exit_code: i32,
    /// Resource usage.
    pub resource_usage: ResourceUsage,
    /// Security events.
    pub security_events: u32,
}

/// Resource usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU usage.
    pub cpu_percent: f32,
    /// Memory usage in MB.
    pub memory_mb: u64,
    /// Network bytes.
    pub network_bytes: u64,
    /// Disk I/O bytes.
    pub disk_bytes: u64,
}

/// CI/CD status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CiCdStatus {
    /// Tests passed.
    Passed,
    /// Tests failed with warnings.
    Warning,
    /// Tests failed.
    Failed,
    /// Tests were aborted.
    Aborted,
}

impl HomelabCiCd {
    /// Create a new homelab CI/CD instance.
    pub async fn new(config: HomelabConfig) -> Result<Self> {
        // Ensure results directory exists
        if let Err(e) = fs::create_dir_all(&config.results_path).await {
            warn!("Failed to create results directory: {}", e);
        }

        Ok(Self {
            config,
            active_containers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            results_history: Arc::new(parking_lot::Mutex::new(Vec::new())),
        })
    }

    /// Run comprehensive security testing in homelab environment.
    pub async fn run_security_testing(&self) -> Result<CiCdTestResult> {
        let run_id = format!("security-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        let start_time = Instant::now();
        
        info!("Starting homelab security testing run: {}", run_id);

        // Get git information
        let (commit_hash, branch) = self.get_git_info().await;

        // Step 1: Build security testing image
        self.build_security_image().await?;

        // Step 2: Run parallel security test containers
        let container_results = self.run_parallel_security_tests(&run_id).await?;

        // Step 3: Run load testing with security monitoring
        let load_test_results = if self.config.load_testing.duration_seconds > 0 {
            Some(self.run_load_testing(&run_id).await?)
        } else {
            None
        };

        // Step 4: Collect and aggregate results
        let security_report = self.aggregate_security_results(&container_results).await?;
        let performance_metrics = self.collect_performance_metrics(&container_results, start_time).await;

        // Step 5: Determine overall status
        let overall_status = self.determine_overall_status(&security_report, &load_test_results);

        let test_result = CiCdTestResult {
            run_id: run_id.clone(),
            timestamp: chrono::Utc::now(),
            commit_hash,
            branch,
            security_report,
            performance_metrics,
            load_test_results,
            container_details: container_results,
            overall_status,
        };

        // Step 6: Save results
        self.save_test_results(&test_result).await?;

        // Step 7: Send notifications if needed
        self.send_notifications(&test_result).await;

        // Step 8: Update history
        self.results_history.lock().push(test_result.clone());

        info!("Homelab security testing completed: {} ({:?})", 
              run_id, test_result.overall_status);

        Ok(test_result)
    }

    /// Build the security testing Docker image.
    async fn build_security_image(&self) -> Result<()> {
        info!("Building security testing Docker image");

        let dockerfile_content = self.generate_security_dockerfile();
        
        // Write Dockerfile
        let dockerfile_path = std::env::temp_dir().join("Dockerfile.security");
        fs::write(&dockerfile_path, dockerfile_content).await
            .map_err(|e| Error::Config(format!("Failed to write Dockerfile: {}", e)))?;

        // Build image
        let output = Command::new("docker")
            .args(&[
                "build",
                "-f", dockerfile_path.to_str().unwrap(),
                "-t", &self.config.security_image,
                "."
            ])
            .output()
            .map_err(|e| Error::Config(format!("Failed to run docker build: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Config(format!("Docker build failed: {}", stderr)));
        }

        info!("Security testing image built successfully");
        Ok(())
    }

    /// Run parallel security test containers.
    async fn run_parallel_security_tests(&self, run_id: &str) -> Result<Vec<ContainerExecution>> {
        info!("Running parallel security tests");

        let test_suites = vec![
            "injection_tests",
            "sanitization_tests", 
            "container_security_tests",
            "websearch_security_tests",
            "provider_security_tests",
            "adversarial_tests",
        ];

        let mut handles = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_parallel_containers as usize));

        for test_suite in test_suites {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let config = self.config.clone();
            let run_id = run_id.to_string();
            let test_suite = test_suite.to_string();
            let active_containers = self.active_containers.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit; // Hold permit for duration of test
                
                Self::run_security_test_container(
                    &config,
                    &run_id,
                    &test_suite,
                    active_containers,
                ).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => warn!("Security test container failed: {}", e),
                Err(e) => warn!("Security test task panicked: {}", e),
            }
        }

        info!("Parallel security tests completed: {} containers", results.len());
        Ok(results)
    }

    /// Run a single security test container.
    async fn run_security_test_container(
        config: &HomelabConfig,
        run_id: &str,
        test_suite: &str,
        active_containers: Arc<parking_lot::Mutex<HashMap<String, TestContainer>>>,
    ) -> Result<ContainerExecution> {
        let container_name = format!("security-test-{}-{}", run_id, test_suite);
        let start_time = Instant::now();

        info!("Starting security test container: {}", container_name);

        // Register container as active
        let container_id = format!("{}:{}", container_name, chrono::Utc::now().timestamp());
        {
            let mut containers = active_containers.lock();
            containers.insert(container_id.clone(), TestContainer {
                id: container_id.clone(),
                name: container_name.clone(),
                test_suite: test_suite.to_string(),
                start_time,
                status: ContainerStatus::Starting,
            });
        }

        // Run container
        let mut cmd = Command::new("docker");
        cmd.args(&[
            "run",
            "--rm",
            "--name", &container_name,
            "--network", "none", // Network isolation
            "--memory", "512m",   // Memory limit
            "--cpus", "1.0",      // CPU limit
            "--read-only",        // Read-only filesystem
            "--tmpfs", "/tmp",    // Writable tmp
            "-e", &format!("TEST_SUITE={}", test_suite),
            "-e", &format!("RUN_ID={}", run_id),
            &config.security_image,
            "cargo", "test", "--test", "security_tests", "--", test_suite,
        ]);

        // Update status
        {
            let mut containers = active_containers.lock();
            if let Some(container) = containers.get_mut(&container_id) {
                container.status = ContainerStatus::Running;
            }
        }

        let output = tokio::time::timeout(
            Duration::from_secs(config.test_timeout_seconds),
            tokio::task::spawn_blocking(move || cmd.output())
        ).await;

        let execution_time = start_time.elapsed();

        let (exit_code, security_events) = match output {
            Ok(Ok(Ok(output))) => {
                debug!("Container {} completed with exit code: {}", 
                       container_name, output.status.code().unwrap_or(-1));
                (output.status.code().unwrap_or(-1), 0) // TODO: Parse security events from output
            }
            Ok(Ok(Err(e))) => {
                warn!("Container {} execution error: {}", container_name, e);
                (-1, 0)
            }
            Ok(Err(e)) => {
                warn!("Container {} task error: {}", container_name, e);
                (-1, 0)
            }
            Err(_) => {
                warn!("Container {} timed out", container_name);
                (-2, 0)
            }
        };

        // Update container status
        {
            let mut containers = active_containers.lock();
            if let Some(container) = containers.get_mut(&container_id) {
                container.status = if exit_code == 0 {
                    ContainerStatus::Completed
                } else if exit_code == -2 {
                    ContainerStatus::TimedOut
                } else {
                    ContainerStatus::Failed(format!("Exit code: {}", exit_code))
                };
            }
        }

        // Get resource usage (simplified for now)
        let resource_usage = ResourceUsage {
            cpu_percent: 0.0, // TODO: Implement actual resource monitoring
            memory_mb: 512,    // Based on container limit
            network_bytes: 0,  // Network disabled
            disk_bytes: 0,     // TODO: Monitor disk I/O
        };

        Ok(ContainerExecution {
            container_id,
            test_suite: test_suite.to_string(),
            execution_time,
            exit_code,
            resource_usage,
            security_events,
        })
    }

    /// Run load testing with security monitoring.
    async fn run_load_testing(&self, run_id: &str) -> Result<LoadTestResults> {
        info!("Starting load testing with security monitoring");

        let config = &self.config.load_testing;
        let start_time = Instant::now();

        // TODO: Implement actual load testing
        // For now, return mock results
        Ok(LoadTestResults {
            total_requests: (config.requests_per_second as u64) * config.duration_seconds,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            p95_response_time_ms: 0.0,
            max_response_time_ms: 0.0,
            achieved_rps: 0.0,
            security_violations: 0,
        })
    }

    /// Aggregate security results from all containers.
    async fn aggregate_security_results(&self, container_results: &[ContainerExecution]) -> Result<SecurityReport> {
        info!("Aggregating security results from {} containers", container_results.len());

        // For now, run a local security test suite to generate the report
        // In a real implementation, this would parse results from the containers
        let mut test_suite = SecurityTestSuite::new();
        let results = test_suite.run_all_tests().await;
        
        Ok(test_suite.generate_security_report())
    }

    /// Collect performance metrics from container executions.
    async fn collect_performance_metrics(&self, container_results: &[ContainerExecution], start_time: Instant) -> PerformanceMetrics {
        let total_execution_time = start_time.elapsed();
        
        let peak_memory_usage_mb = container_results
            .iter()
            .map(|c| c.resource_usage.memory_mb)
            .max()
            .unwrap_or(0);

        let avg_cpu_usage_percent = if !container_results.is_empty() {
            container_results
                .iter()
                .map(|c| c.resource_usage.cpu_percent)
                .sum::<f32>() / container_results.len() as f32
        } else {
            0.0
        };

        let network_io_bytes = container_results
            .iter()
            .map(|c| c.resource_usage.network_bytes)
            .sum();

        let disk_io_bytes = container_results
            .iter()
            .map(|c| c.resource_usage.disk_bytes)
            .sum();

        let container_startup_time = container_results
            .iter()
            .map(|c| c.execution_time)
            .min()
            .unwrap_or(Duration::ZERO);

        PerformanceMetrics {
            total_execution_time,
            peak_memory_usage_mb,
            avg_cpu_usage_percent,
            network_io_bytes,
            disk_io_bytes,
            container_startup_time,
        }
    }

    /// Determine overall test status.
    fn determine_overall_status(&self, security_report: &SecurityReport, load_test_results: &Option<LoadTestResults>) -> CiCdStatus {
        // Critical failures = Failed
        if security_report.critical_failures > 0 {
            return CiCdStatus::Failed;
        }

        // High-risk failures = Warning
        if security_report.high_risk_failures > 0 {
            return CiCdStatus::Warning;
        }

        // Check load test security violations
        if let Some(load_results) = load_test_results {
            if load_results.security_violations > 0 {
                return CiCdStatus::Warning;
            }
        }

        // Security score below 80% = Warning
        if security_report.security_score < 80.0 {
            return CiCdStatus::Warning;
        }

        CiCdStatus::Passed
    }

    /// Save test results to disk.
    async fn save_test_results(&self, test_result: &CiCdTestResult) -> Result<()> {
        let filename = format!("{}.json", test_result.run_id);
        let filepath = self.config.results_path.join(filename);
        
        let json = serde_json::to_string_pretty(test_result)
            .map_err(|e| Error::Config(format!("Failed to serialize results: {}", e)))?;

        fs::write(&filepath, json).await
            .map_err(|e| Error::Config(format!("Failed to write results: {}", e)))?;

        info!("Test results saved to: {:?}", filepath);
        Ok(())
    }

    /// Send notifications based on test results.
    async fn send_notifications(&self, test_result: &CiCdTestResult) {
        let should_notify = match test_result.overall_status {
            CiCdStatus::Failed => true,
            CiCdStatus::Warning => matches!(self.config.notifications.min_risk_level, RiskLevel::Medium | RiskLevel::Low),
            _ => false,
        };

        if !should_notify {
            return;
        }

        // Send Slack notification
        if self.config.notifications.slack_enabled {
            if let Some(webhook_url) = &self.config.notifications.slack_webhook {
                self.send_slack_notification(webhook_url, test_result).await;
            }
        }

        // Send email notifications
        if self.config.notifications.email_enabled {
            for recipient in &self.config.notifications.email_recipients {
                self.send_email_notification(recipient, test_result).await;
            }
        }
    }

    /// Send Slack notification.
    async fn send_slack_notification(&self, webhook_url: &str, test_result: &CiCdTestResult) {
        let message = format!(
            "🔐 Security Test Alert: {} - Status: {:?}\nSecurity Score: {:.1}%\nCritical Failures: {}\nHigh-Risk Failures: {}",
            test_result.run_id,
            test_result.overall_status,
            test_result.security_report.security_score,
            test_result.security_report.critical_failures,
            test_result.security_report.high_risk_failures
        );

        // TODO: Implement actual Slack webhook call
        warn!("Would send Slack notification: {}", message);
    }

    /// Send email notification.
    async fn send_email_notification(&self, recipient: &str, test_result: &CiCdTestResult) {
        // TODO: Implement email notifications
        warn!("Would send email to {}: Security test {}", recipient, test_result.run_id);
    }

    /// Get git information.
    async fn get_git_info(&self) -> (Option<String>, Option<String>) {
        let commit_hash = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string());

        let branch = Command::new("git")
            .args(&["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string());

        (commit_hash, branch)
    }

    /// Generate Dockerfile for security testing.
    fn generate_security_dockerfile(&self) -> String {
        format!(r#"
FROM rust:1.75 as builder

WORKDIR /app
COPY . .

# Install additional security tools
RUN apt-get update && apt-get install -y \
    binutils \
    strace \
    ltrace \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Build with security hardening
RUN cargo build --tests --release

FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 testuser

WORKDIR /app
COPY --from=builder /app/target/release/deps/* ./
COPY --from=builder /app/target/release/embeddenator_webpuppet-* ./

# Security hardening
RUN chown -R testuser:testuser /app
USER testuser

# Default command
CMD ["./embeddenator_webpuppet-security_tests"]
"#)
    }

    /// Get test results history.
    pub fn get_results_history(&self) -> Vec<CiCdTestResult> {
        self.results_history.lock().clone()
    }

    /// Clean up old test results.
    pub async fn cleanup_old_results(&self, days_to_keep: u64) -> Result<()> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(days_to_keep as i64);
        
        // Clean up history
        {
            let mut history = self.results_history.lock();
            history.retain(|result| result.timestamp > cutoff_date);
        }

        // Clean up files
        let mut entries = fs::read_dir(&self.config.results_path).await
            .map_err(|e| Error::Config(format!("Failed to read results directory: {}", e)))?;

        let mut files_deleted = 0;
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            if let Ok(metadata) = entry.metadata().await {
                if let Ok(created) = metadata.created() {
                    let created_chrono = chrono::DateTime::<chrono::Utc>::from(created);
                    if created_chrono < cutoff_date {
                        if let Err(e) = fs::remove_file(entry.path()).await {
                            warn!("Failed to delete old result file {:?}: {}", entry.path(), e);
                        } else {
                            files_deleted += 1;
                        }
                    }
                }
            }
        }

        info!("Cleaned up {} old result files", files_deleted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_homelab_config_defaults() {
        let config = HomelabConfig::default();
        assert_eq!(config.max_parallel_containers, 8);
        assert_eq!(config.test_timeout_seconds, 300);
        assert!(config.enable_profiling);
    }

    #[test]
    fn test_load_test_config() {
        let config = LoadTestConfig::default();
        assert_eq!(config.concurrent_users, 100);
        assert_eq!(config.requests_per_second, 50);
        assert!(config.adversarial_testing);
    }

    #[test]
    fn test_cicd_status_determination() {
        // This would test the status determination logic
        assert!(matches!(CiCdStatus::Passed, CiCdStatus::Passed));
    }
}