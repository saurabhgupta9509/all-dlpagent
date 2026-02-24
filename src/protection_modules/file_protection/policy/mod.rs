//! Policy Engine (STEP 4)
//! Core Principle: Bridge Admin intent → kernel enforcement securely
//! 🔐 SECURITY BOUNDARY: Only here are IDs resolved to NT paths
// src/policy/mod.rs
mod policy_intent;
mod path_resolver;
mod kernel_policy;
mod kernel_adapter;
pub mod policy_store;
mod policy_engine;
pub mod policy_preview;
mod policy_guard;
mod policy_dry_run;

pub use policy_intent::{PolicyIntent, ProtectionScope, ProtectionAction, ProtectionOperations};
pub use path_resolver::PathResolver;
pub use kernel_policy::{KernelPolicy, PathMatchType, KernelOperations, PolicyNormalizer};
pub use kernel_adapter::{KernelAdapter, FilePolicy};
pub use policy_store::{PolicyStore, ActivePolicy, PolicyStoreStats};
pub use policy_engine::{PolicyEngine, PolicyEngineStats};
pub use policy_preview::{PolicyPreviewService, PolicyPreview};
pub use policy_store::HealthStatus;

use crate::protection_modules::file_protection::{fs_index::FilesystemIndex, kernel::KernelEvent};
/// Initialize STEP 4 Policy Engine
pub fn init_step4(
    index: std::sync::Arc<FilesystemIndex>,
    kernel_event_sender: Option<tokio::sync::mpsc::Sender<KernelEvent>>) 
    -> Result<std::sync::Arc<PolicyEngine>, String> 
{
    println!("🔐 Initializing STEP 4: Policy Engine");
    println!("   • Admin intent → kernel enforcement");
    println!("   • ID → NT path resolution (Agent-only)");
    println!("   • Security boundary: NT paths never exposed");
    
    PolicyEngine::new(index , kernel_event_sender)
}