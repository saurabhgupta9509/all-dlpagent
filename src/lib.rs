// --- MODS AND USE STATEMENTS ---
pub mod agent_core;
pub mod capabilities;
pub mod communication;
pub mod config;
pub mod gui;
pub mod policy_constants;
pub mod policy_engine;
pub mod protection_modules;
pub mod utils;

// --- Re-export main types ---
pub use agent_core::AgentCore;
pub use communication::ServerCommunicator;
pub use gui::AgentGUI;
pub use policy_engine::{Policy, PolicyEngine};
pub use utils::timing_config::{TIMING_CONFIG, GlobalTimingConfig};
