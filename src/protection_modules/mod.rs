// src/protection_modules/mod.rs
pub mod ca_manager;
pub mod dto;
pub mod mitm_proxy;
pub mod network_protection;
pub mod usb_protection;
pub mod web_filter_phase2;
pub mod web_filter_phase3;
pub mod web_filter_protection;
pub mod web_proxy;
pub mod file_protection;
pub mod file_browser;
pub mod security_monitor;
pub mod app_tracker;
pub mod browser_monitor;
pub mod partial_access_manager;

pub use file_protection::FileProtectionModule;
pub use app_tracker::AppTrackerModule;
pub use browser_monitor::BrowserMonitorModule;
pub use partial_access_manager::PartialAccessModule;
// use async_trait::async_trait;
use crate::communication::ServerCommunicator;
use crate::policy_engine::PolicyEngine;
pub use security_monitor::SecurityMonitorProtection;    
use std::any::Any;
use std::error::Error;
pub use crate::policy_constants::*;
/// Protection module trait used by the agent.
/// Note the error type includes Send + Sync to match async contexts.
#[async_trait::async_trait]

pub trait ProtectionModule: Send + Sync {
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Get the name of this protection module
    fn get_name(&self) -> &str;

      fn as_any(&self) -> &dyn Any;

      
}
