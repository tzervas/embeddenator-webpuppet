//! Rate limiting for provider requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::RateLimitConfig;
use crate::providers::Provider;

/// Rate limiter for controlling request frequency.
pub struct RateLimiter {
    config: RateLimitConfig,
    state: Arc<Mutex<HashMap<Provider, RateLimitState>>>,
}

struct RateLimitState {
    /// Timestamps of recent requests.
    requests: Vec<Instant>,
    /// Last request time.
    last_request: Option<Instant>,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            last_request: None,
        }
    }

    fn cleanup_old_requests(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.requests.retain(|t| *t > cutoff);
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            config: config.clone(),
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Wait until a request is allowed for the given provider.
    pub async fn wait(&self, provider: Provider) {
        let delay = self.calculate_delay(provider);

        if delay > Duration::ZERO {
            tracing::debug!(
                "Rate limiting: waiting {:?} before request to {}",
                delay,
                provider
            );
            tokio::time::sleep(delay).await;
        }

        // Record the request
        self.record_request(provider);
    }

    /// Calculate the delay needed before the next request.
    fn calculate_delay(&self, provider: Provider) -> Duration {
        let mut state = self.state.lock();
        let provider_state = state.entry(provider).or_insert_with(RateLimitState::new);

        // Cleanup old requests
        provider_state.cleanup_old_requests(Duration::from_secs(60));

        let now = Instant::now();

        // Check requests per minute
        if provider_state.requests.len() >= self.config.requests_per_minute as usize {
            // Need to wait for oldest request to fall out of window
            if let Some(oldest) = provider_state.requests.first() {
                let window_end = *oldest + Duration::from_secs(60);
                if window_end > now {
                    return window_end - now;
                }
            }
        }

        // Check minimum delay between requests
        if let Some(last) = provider_state.last_request {
            let min_delay = self.calculate_humanized_delay();
            let next_allowed = last + min_delay;
            if next_allowed > now {
                return next_allowed - now;
            }
        }

        Duration::ZERO
    }

    /// Calculate delay with optional humanization.
    fn calculate_humanized_delay(&self) -> Duration {
        let base_delay = self.config.min_delay;

        if !self.config.humanize {
            return base_delay;
        }

        // Add jitter
        let jitter_range = (self.config.max_delay - self.config.min_delay).as_millis() as u64;
        let jitter_max = jitter_range * self.config.jitter_percent as u64 / 100;

        if jitter_max > 0 {
            let jitter = fastrand::u64(0..jitter_max);
            base_delay + Duration::from_millis(jitter)
        } else {
            base_delay
        }
    }

    /// Record a request for rate limiting purposes.
    fn record_request(&self, provider: Provider) {
        let mut state = self.state.lock();
        let provider_state = state.entry(provider).or_insert_with(RateLimitState::new);

        let now = Instant::now();
        provider_state.requests.push(now);
        provider_state.last_request = Some(now);
    }

    /// Check if a request is currently allowed without waiting.
    pub fn is_allowed(&self, provider: Provider) -> bool {
        self.calculate_delay(provider) == Duration::ZERO
    }

    /// Get the current request count for a provider (in the last minute).
    pub fn request_count(&self, provider: Provider) -> usize {
        let mut state = self.state.lock();
        let provider_state = state.entry(provider).or_insert_with(RateLimitState::new);
        provider_state.cleanup_old_requests(Duration::from_secs(60));
        provider_state.requests.len()
    }

    /// Reset rate limit state for a provider.
    pub fn reset(&self, provider: Provider) {
        let mut state = self.state.lock();
        state.remove(&provider);
    }

    /// Reset all rate limit state.
    pub fn reset_all(&self) {
        let mut state = self.state.lock();
        state.clear();
    }
}

/// Leaky bucket rate limiter for more sophisticated rate limiting.
pub struct LeakyBucket {
    capacity: f64,
    rate: f64, // tokens per second
    tokens: Arc<Mutex<f64>>,
    last_update: Arc<Mutex<Instant>>,
}

impl LeakyBucket {
    /// Create a new leaky bucket.
    pub fn new(capacity: f64, rate: f64) -> Self {
        Self {
            capacity,
            rate,
            tokens: Arc::new(Mutex::new(capacity)),
            last_update: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Wait for a token to be available.
    pub async fn acquire(&self) {
        loop {
            if self.try_acquire() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Try to acquire a token without waiting.
    pub fn try_acquire(&self) -> bool {
        let mut tokens = self.tokens.lock();
        let mut last_update = self.last_update.lock();

        // Add tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(*last_update).as_secs_f64();
        *tokens = (*tokens + elapsed * self.rate).min(self.capacity);
        *last_update = now;

        // Try to take a token
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current token count.
    pub fn tokens(&self) -> f64 {
        *self.tokens.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig {
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(200),
            requests_per_minute: 60,
            humanize: false,
            jitter_percent: 0,
        };

        let limiter = RateLimiter::new(&config);

        // First request should be allowed immediately
        assert!(limiter.is_allowed(Provider::Claude));
        limiter.record_request(Provider::Claude);

        // Second request should need to wait
        assert!(!limiter.is_allowed(Provider::Claude));
    }

    #[test]
    fn test_leaky_bucket() {
        let bucket = LeakyBucket::new(5.0, 1.0);

        // Should be able to acquire 5 tokens immediately
        for _ in 0..5 {
            assert!(bucket.try_acquire());
        }

        // 6th should fail
        assert!(!bucket.try_acquire());
    }
}
