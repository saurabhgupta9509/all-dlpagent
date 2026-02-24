// src/utils/mod.rs
pub mod timing_config;
pub mod output_lock;
// Re-export for easy access
pub use timing_config::{TIMING_CONFIG, GlobalTimingConfig};