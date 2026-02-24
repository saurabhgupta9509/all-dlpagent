// src/utils/timing_config.rs
use std::time::Duration;
use once_cell::sync::Lazy;

// Global configuration for timing - available everywhere
pub static TIMING_CONFIG: Lazy<GlobalTimingConfig> = Lazy::new(|| GlobalTimingConfig {
    agent_poll_interval: Duration::from_secs(30),  // Changed from 2 to 30 seconds
    ocr_interval: Duration::from_secs(5),
    security_monitor_maintenance: Duration::from_secs(60),
    policy_check_interval: Duration::from_secs(30),  // Check policies every 30s
    token_refresh_interval: Duration::from_secs(300), // Refresh token every 5 minutes
});

#[derive(Debug, Clone)]
pub struct GlobalTimingConfig {
    pub agent_poll_interval: Duration,
    pub ocr_interval: Duration,
    pub security_monitor_maintenance: Duration,
    pub policy_check_interval: Duration,
    pub token_refresh_interval: Duration,
}

// Convenience methods
impl GlobalTimingConfig {
    pub fn get_agent_poll_interval(&self) -> Duration {
        self.agent_poll_interval
    }
    
    pub fn get_ocr_interval(&self) -> Duration {
        self.ocr_interval
    }
    
    pub fn get_policy_check_interval(&self) -> Duration {
        self.policy_check_interval
    }
    
    pub fn get_token_refresh_interval(&self) -> Duration {
        self.token_refresh_interval
    }
}