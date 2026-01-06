#!/bin/bash

# Homelab CI/CD Security Testing Pipeline
# Comprehensive security validation for embeddenator-webpuppet

set -euo pipefail

# Configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
PROJECT_NAME="embeddenator-webpuppet" 
BUILD_ID="${BUILD_ID:-$(date +%Y%m%d-%H%M%S)}"
MAX_PARALLEL_CONTAINERS="${MAX_PARALLEL_CONTAINERS:-8}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"

# Logging setup
LOG_DIR="/opt/ci-logs/${PROJECT_NAME}"
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_DIR}/security-pipeline-${BUILD_ID}.log")
exec 2>&1

echo "=== EMBEDDENATOR WEBPUPPET SECURITY PIPELINE ==="
echo "Build ID: ${BUILD_ID}"
echo "Registry: ${DOCKER_REGISTRY}"
echo "Max Containers: ${MAX_PARALLEL_CONTAINERS}"
echo "Test Timeout: ${TEST_TIMEOUT}s"
echo "=============================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Function to handle cleanup
cleanup() {
    log "Cleaning up containers and resources..."
    
    # Stop any running security test containers
    docker ps --filter "name=security-test-${BUILD_ID}" --format "{{.ID}}" | xargs -r docker stop || true
    
    # Remove test containers
    docker ps -a --filter "name=security-test-${BUILD_ID}" --format "{{.ID}}" | xargs -r docker rm || true
    
    # Clean up test networks if created
    docker network ls --filter "name=security-test-${BUILD_ID}" --format "{{.ID}}" | xargs -r docker network rm || true
    
    # Clean up temporary volumes
    docker volume ls --filter "name=security-test-${BUILD_ID}" --format "{{.Name}}" | xargs -r docker volume rm || true
    
    log "Cleanup completed"
}

trap cleanup EXIT

# Build security testing image
build_security_image() {
    log "Building security testing image..."
    
    # Create comprehensive Dockerfile for security testing
    cat > Dockerfile.security << 'EOF'
FROM rust:1.75-slim as builder

# Install security testing tools
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    binutils \
    strace \
    ltrace \
    valgrind \
    gdb \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build with security hardening flags
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-s"
RUN cargo build --tests --release

# Create minimal runtime image  
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1001 -g 1001 testuser

WORKDIR /app

# Copy test binaries
COPY --from=builder /app/target/release/deps/ ./deps/
COPY --from=builder /app/target/release/embeddenator_webpuppet-* ./

# Copy test data and configurations
COPY tests/ ./tests/
COPY .ci/ ./.ci/

# Security hardening
RUN chown -R testuser:testuser /app && \
    chmod -R 750 /app

USER testuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD echo "Security test container healthy"

# Default test command
CMD ["./embeddenator_webpuppet-security_tests"]
EOF

    # Build the image with security context
    docker build \
        -f Dockerfile.security \
        -t "${DOCKER_REGISTRY}/${PROJECT_NAME}:security-${BUILD_ID}" \
        -t "${DOCKER_REGISTRY}/${PROJECT_NAME}:security-latest" \
        --build-arg BUILD_ID="${BUILD_ID}" \
        --build-arg RUST_LOG=debug \
        .

    log "Security image built successfully"
}

# Run parallel security test suites
run_security_tests() {
    log "Running parallel security test suites..."
    
    local test_suites=(
        "injection_prevention"
        "output_sanitization" 
        "container_isolation"
        "websearch_security"
        "provider_security"
        "adversarial_payloads"
        "performance_security"
        "memory_safety"
    )
    
    local pids=()
    local results_dir="/tmp/security-results-${BUILD_ID}"
    mkdir -p "${results_dir}"
    
    # Run test suites in parallel
    for suite in "${test_suites[@]}"; do
        # Limit concurrent containers
        while [ ${#pids[@]} -ge ${MAX_PARALLEL_CONTAINERS} ]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    unset "pids[$i]"
                fi
            done
            pids=("${pids[@]}")  # Re-index array
            sleep 1
        done
        
        # Start container for this test suite
        run_test_container "${suite}" "${results_dir}" &
        pids+=($!)
        
        log "Started test suite: ${suite} (PID: $!)"
        sleep 2  # Stagger container startup
    done
    
    # Wait for all containers to complete
    log "Waiting for all security tests to complete..."
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # Collect and analyze results
    analyze_security_results "${results_dir}"
}

# Run individual test container
run_test_container() {
    local suite="$1"
    local results_dir="$2"
    local container_name="security-test-${BUILD_ID}-${suite}"
    
    log "Running security test container: ${container_name}"
    
    # Run container with security constraints
    timeout "${TEST_TIMEOUT}" docker run \
        --name "${container_name}" \
        --rm \
        --network none \
        --memory 512m \
        --cpus 1.0 \
        --read-only \
        --tmpfs /tmp:rw,noexec,size=100m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --user 1001:1001 \
        -e "TEST_SUITE=${suite}" \
        -e "BUILD_ID=${BUILD_ID}" \
        -e "RUST_LOG=debug" \
        -v "${results_dir}:/results:rw" \
        "${DOCKER_REGISTRY}/${PROJECT_NAME}:security-${BUILD_ID}" \
        bash -c "
            set -e
            cd /app
            echo 'Starting security test: ${suite}'
            
            # Run specific test suite
            case '${suite}' in
                'injection_prevention')
                    ./deps/embeddenator_webpuppet-* --test prompt_injection_prevention
                    ./deps/embeddenator_webpuppet-* --test code_injection_prevention  
                    ./deps/embeddenator_webpuppet-* --test sql_injection_prevention
                    ;;
                'output_sanitization')
                    ./deps/embeddenator_webpuppet-* --test pii_redaction
                    ./deps/embeddenator_webpuppet-* --test api_key_redaction
                    ./deps/embeddenator_webpuppet-* --test proprietary_info_protection
                    ;;
                'container_isolation')
                    ./deps/embeddenator_webpuppet-* --test container_isolation
                    ./deps/embeddenator_webpuppet-* --test container_escape_prevention
                    ./deps/embeddenator_webpuppet-* --test container_resource_limits
                    ;;
                'websearch_security')
                    ./deps/embeddenator_webpuppet-* --test websearch_security
                    ./deps/embeddenator_webpuppet-* --test malicious_url_blocking
                    ;;
                'provider_security')
                    ./deps/embeddenator_webpuppet-* --test provider_isolation
                    ./deps/embeddenator_webpuppet-* --test rate_limiting
                    ;;
                'adversarial_payloads')
                    ./deps/embeddenator_webpuppet-* --test encoded_payloads
                    ./deps/embeddenator_webpuppet-* --test unicode_attacks
                    ./deps/embeddenator_webpuppet-* --test polyglot_payloads
                    ;;
                'performance_security')
                    ./deps/embeddenator_webpuppet-* --test memory_exhaustion_prevention
                    ./deps/embeddenator_webpuppet-* --test timing_attacks
                    ;;
                'memory_safety')
                    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
                        ./deps/embeddenator_webpuppet-* --test memory_safety 2>&1 | tee /tmp/valgrind.log
                    ;;
                *)
                    echo 'Unknown test suite: ${suite}'
                    exit 1
                    ;;
            esac
            
            # Save results
            echo '{\"suite\":\"${suite}\",\"status\":\"completed\",\"timestamp\":\"$(date -Iseconds)\"}' > /results/${suite}.json
            echo 'Test suite completed: ${suite}'
        " || {
            echo "{\"suite\":\"${suite}\",\"status\":\"failed\",\"timestamp\":\"$(date -Iseconds)\"}" > "${results_dir}/${suite}.json"
            log "Test suite failed: ${suite}"
            return 1
        }
    
    log "Test suite completed: ${suite}"
}

# Analyze security test results
analyze_security_results() {
    local results_dir="$1"
    local report_file="${LOG_DIR}/security-report-${BUILD_ID}.json"
    
    log "Analyzing security test results..."
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local critical_failures=0
    
    # Count results
    for result_file in "${results_dir}"/*.json; do
        if [[ -f "$result_file" ]]; then
            total_tests=$((total_tests + 1))
            
            if grep -q '"status":"completed"' "$result_file"; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
                
                # Check for critical failures
                local suite_name
                suite_name=$(basename "$result_file" .json)
                if [[ "$suite_name" =~ ^(injection_prevention|container_isolation|websearch_security)$ ]]; then
                    critical_failures=$((critical_failures + 1))
                fi
            fi
        fi
    done
    
    # Calculate security score
    local security_score=0
    if [[ $total_tests -gt 0 ]]; then
        security_score=$(( (passed_tests * 100) / total_tests ))
    fi
    
    # Generate comprehensive report
    cat > "$report_file" << EOF
{
  "build_id": "${BUILD_ID}",
  "timestamp": "$(date -Iseconds)",
  "total_tests": ${total_tests},
  "passed_tests": ${passed_tests}, 
  "failed_tests": ${failed_tests},
  "critical_failures": ${critical_failures},
  "security_score": ${security_score},
  "status": "$(determine_overall_status $security_score $critical_failures)",
  "results": [
$(for result_file in "${results_dir}"/*.json; do
    if [[ -f "$result_file" ]]; then
        cat "$result_file"
        echo ","
    fi
done | sed '$s/,$//')
  ]
}
EOF

    log "Security analysis completed"
    log "Results: ${passed_tests}/${total_tests} passed (${security_score}% security score)"
    
    # Display summary
    echo
    echo "=== SECURITY TEST SUMMARY ==="
    echo "Build ID: ${BUILD_ID}"
    echo "Total Tests: ${total_tests}"
    echo "Passed: ${passed_tests}"
    echo "Failed: ${failed_tests}"
    echo "Critical Failures: ${critical_failures}"
    echo "Security Score: ${security_score}%"
    echo "Status: $(determine_overall_status $security_score $critical_failures)"
    echo "============================"
    echo
    
    # Send notifications if needed
    send_notifications "$security_score" "$critical_failures" "$report_file"
    
    # Return appropriate exit code
    if [[ $critical_failures -gt 0 ]]; then
        return 2  # Critical failure
    elif [[ $failed_tests -gt 0 ]]; then
        return 1  # Some failures
    else
        return 0  # All passed
    fi
}

# Determine overall status
determine_overall_status() {
    local security_score=$1
    local critical_failures=$2
    
    if [[ $critical_failures -gt 0 ]]; then
        echo "FAILED"
    elif [[ $security_score -lt 80 ]]; then
        echo "WARNING"  
    else
        echo "PASSED"
    fi
}

# Send notifications
send_notifications() {
    local security_score=$1
    local critical_failures=$2
    local report_file=$3
    
    local status
    status=$(determine_overall_status "$security_score" "$critical_failures")
    
    # Only notify on failures or warnings
    if [[ "$status" != "PASSED" ]]; then
        log "Sending security alert notifications..."
        
        # Slack notification (if configured)
        if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
            local message="🔐 Security Test Alert: ${PROJECT_NAME} Build ${BUILD_ID}
Status: ${status}
Security Score: ${security_score}%
Critical Failures: ${critical_failures}
Report: Available in ${report_file}"
            
            curl -X POST -H 'Content-type: application/json' \
                --data "{\"text\":\"${message}\"}" \
                "${SLACK_WEBHOOK}" || log "Failed to send Slack notification"
        fi
        
        # Email notification (if configured)
        if [[ -n "${EMAIL_RECIPIENTS:-}" ]]; then
            local subject="Security Test Alert: ${PROJECT_NAME} ${status}"
            local body="Security test results for ${PROJECT_NAME} build ${BUILD_ID}:

Status: ${status}
Security Score: ${security_score}%
Total Tests: $(jq -r '.total_tests' "$report_file")
Passed Tests: $(jq -r '.passed_tests' "$report_file")  
Failed Tests: $(jq -r '.failed_tests' "$report_file")
Critical Failures: ${critical_failures}

Full report available at: ${report_file}"
            
            echo "$body" | mail -s "$subject" "${EMAIL_RECIPIENTS}" || log "Failed to send email notification"
        fi
    fi
}

# Performance and load testing
run_load_testing() {
    log "Running load testing with security monitoring..."
    
    # This would run comprehensive load tests while monitoring for security issues
    # For now, just a placeholder
    log "Load testing completed (placeholder)"
}

# Cleanup old results and artifacts
cleanup_old_results() {
    log "Cleaning up old test results..."
    
    # Keep last 30 days of results
    find "${LOG_DIR}" -name "*.log" -mtime +30 -delete || true
    find "${LOG_DIR}" -name "*.json" -mtime +30 -delete || true
    
    # Clean up old Docker images
    docker image prune -f --filter "until=720h" || true  # 30 days
    
    log "Cleanup completed"
}

# Main pipeline execution
main() {
    log "Starting security testing pipeline..."
    
    # Step 1: Build security testing environment
    build_security_image
    
    # Step 2: Run comprehensive security tests
    run_security_tests
    local security_exit_code=$?
    
    # Step 3: Run load testing (optional)
    if [[ "${RUN_LOAD_TESTS:-false}" == "true" ]]; then
        run_load_testing
    fi
    
    # Step 4: Cleanup old results
    cleanup_old_results
    
    log "Security testing pipeline completed with exit code: ${security_exit_code}"
    
    exit $security_exit_code
}

# Execute main function
main "$@"