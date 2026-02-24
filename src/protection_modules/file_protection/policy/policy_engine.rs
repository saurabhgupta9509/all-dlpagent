//! Policy Engine (STEP 4)
//! Core Principle: Bridge Admin intent → kernel enforcement securely
// src/policy/policy_engine.rs
use std::sync::Arc;
use crate::protection_modules::file_protection::{fs_index::FilesystemIndex, kernel::KernelEvent, policy::{HealthStatus, KernelAdapter, PathResolver, PolicyNormalizer, PolicyPreview, PolicyPreviewService, PolicyStore, policy_dry_run::{DryRunEvaluation, DryRunEvaluator}, policy_guard::{PolicyGuard, SafetyValidation}, policy_store::EnforcementStats}};

use super::policy_intent::{PolicyIntent, ProtectionScope, ProtectionAction, ProtectionOperations};

/// Main policy engine
pub struct PolicyEngine {
    path_resolver: Arc<PathResolver>,
    kernel_adapter: Arc<parking_lot::RwLock<Option<KernelAdapter>>>,
    policy_store: Arc<PolicyStore>,
}

impl PolicyEngine {
    /// Create new policy engine
    pub fn new(
        // index: Arc<crate::fs_index::FilesystemIndex>,
        index: Arc<FilesystemIndex>,
        event_sender: Option<tokio::sync::mpsc::Sender<KernelEvent>>,
    ) -> Result<Arc<Self>, String> {
        println!("🚀 PolicyEngine: Initializing...");
        
        // Create path resolver
        let path_resolver = Arc::new(PathResolver::new(index));
        
        // Create kernel adapter (might fail if kernel not running)
        let kernel_adapter = match KernelAdapter::new(event_sender) {
            Ok(adapter) => {
                println!("✅ KernelAdapter: Connected");
                Arc::new(parking_lot::RwLock::new(Some(adapter)))
            }
            Err(e) => {
                println!("⚠️  KernelAdapter: Not connected - running in simulation mode");
                println!("   Error: {}", e);
                Arc::new(parking_lot::RwLock::new(None))
            }
        };
        
        // Create policy store
        let policy_store = PolicyStore::new();
        
        let engine = Arc::new(PolicyEngine {
            path_resolver,
            kernel_adapter,
            policy_store,
        });
        
        println!("✅ PolicyEngine: Ready");
        Ok(engine)
    }

     pub fn attach_kernel_event_sender(&self, event_sender: tokio::sync::mpsc::Sender<KernelEvent>) {
        let mut adapter = self.kernel_adapter.write();
        if let Some(adapter) = adapter.as_mut() {
            // This method needs to be added to KernelAdapter
            adapter.set_event_sender(event_sender);
            println!("✅ PolicyEngine: Kernel event sender attached");
        } else {
            println!("⚠️  PolicyEngine: No kernel adapter to attach event sender");
        }
    }
    
      /// Get policy by ID (internal or kernel ID)
    pub fn get_policy_by_id(&self, policy_id: u64) -> Option<super::policy_store::ActivePolicy> {
        self.policy_store.get_policy_by_id(policy_id)
    }
    
    /// Get node ID by kernel policy ID
    pub fn get_node_id_by_kernel_id(&self, kernel_policy_id: u64) -> Option<u64> {
        self.policy_store.get_node_id_by_kernel_id(kernel_policy_id)
    }
    
    pub fn new_simulated() -> Self {
        println!("🔄 Creating simulated PolicyEngine for demo");
        
        // Create a minimal index for simulation
        let index = FilesystemIndex::new();
        
        PolicyEngine {
            path_resolver: Arc::new(PathResolver::new(Arc::new(index))),
            kernel_adapter: Arc::new(parking_lot::RwLock::new(None)),
            policy_store: PolicyStore::new(),
        }
    }
        
    /// Apply protection policy
    pub fn apply_protection(&self, intent: PolicyIntent) -> Result<u64, String> {
        println!("🛡️ PolicyEngine: Applying protection...");
        println!("   {}", intent.describe());
        
        // 1. Validate intent
        intent.validate()?;
        
        // 2. Validate node exists and is accessible
        self.path_resolver.validate_node(intent.node_id)?;
        
        // 3. Resolve node ID → NT path(s)
        let nt_paths = self.path_resolver.resolve_policy_intent(&intent)?;
        
        // 4. Get policy ID
        let policy_id = {
            let mut adapter = self.kernel_adapter.write();
            if let Some(adapter) = adapter.as_mut() {
                adapter.get_next_policy_id()
            } else {
                // Simulation mode - generate fake ID
                99990000 + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u64
            }
        };
        
        // 5. Normalize to kernel policies
        let kernel_policies = PolicyNormalizer::normalize(&intent, nt_paths, policy_id);
        
        // Validate each kernel policy
        for policy in &kernel_policies {
            PolicyNormalizer::validate(policy)?;
        }
        
        // 6. Send to kernel (if connected)
        let mut kernel_policy_ids = Vec::new();
        let mut adapter = self.kernel_adapter.write();
        
        if let Some(adapter) = adapter.as_mut() {
            for policy in &kernel_policies {
                match adapter.send_policy(policy) {
                    Ok(id) => kernel_policy_ids.push(id),
                    Err(e) => {
                        println!("❌ Failed to send policy to kernel: {}", e);
                        // Continue with other policies? For now, fail fast
                        return Err(e);
                    }
                }
            }
        } else {
            println!("⚠️  Running in simulation mode - not sending to kernel");
            // Generate fake kernel IDs for simulation
            for (i, _) in kernel_policies.iter().enumerate() {
                kernel_policy_ids.push(policy_id + i as u64);
            }
        }
        
        // 7. Store in policy store
        self.policy_store.add_policy(
            policy_id,
            intent,
            kernel_policies,
            kernel_policy_ids,
        );
        
        println!("✅ PolicyEngine: Protection applied successfully (Policy ID: {})", policy_id);
        Ok(policy_id)
    }
    
    /// Remove protection policy
    pub fn remove_protection(&self, policy_id: u64) -> Result<(), String> {
        println!("🗑️ PolicyEngine: Removing protection (Policy ID: {})", policy_id);
        
        // 1. Get policy from store
        let policy = match self.policy_store.get_policy(policy_id) {
            Some(policy) => policy,
            None => return Err(format!("Policy ID {} not found", policy_id)),
        };
        
        // 2. Remove from kernel (if connected)
        let mut adapter = self.kernel_adapter.write();
        
        if let Some(adapter) = adapter.as_mut() {
            for kernel_policy in &policy.kernel_policies {
                if let Err(e) = adapter.remove_policy(policy_id, &kernel_policy.nt_path) {
                    println!("⚠️  Failed to remove from kernel: {}", e);
                    // Continue trying other paths
                }
            }
        } else {
            println!("⚠️  Running in simulation mode - not removing from kernel");
        }
        
        // 3. Remove from store
        self.policy_store.remove_policy(policy_id);
        
        println!("✅ PolicyEngine: Protection removed successfully");
        Ok(())
    }
    
    /// Get all active policies
    pub fn get_active_policies(&self) -> Vec<super::policy_store::ActivePolicy> {
        self.policy_store.get_all_policies()
    }
    
    /// Get policies for a specific node
    pub fn get_policies_for_node(&self, node_id: u64) -> Vec<super::policy_store::ActivePolicy> {
        self.policy_store.get_policies_for_node(node_id)
    }
    
    /// Get policy engine statistics
    pub fn get_stats(&self) -> PolicyEngineStats {
        let store_stats = self.policy_store.get_stats();
        
        let kernel_connected = {
            let adapter = self.kernel_adapter.read();
            adapter.is_some()
        };
        
        PolicyEngineStats {
            total_policies: store_stats.total_policies,
            active_policies: store_stats.active_policies,
            protected_nodes: store_stats.protected_nodes,
            kernel_connected,
        }
    }
    
    /// Get path resolver (for internal use)
    pub fn path_resolver(&self) -> &Arc<PathResolver> {
        &self.path_resolver
    }
    
    /// Get policy store (for internal use)
    pub fn policy_store(&self) -> &Arc<PolicyStore> {
        &self.policy_store
    }

    /// Get policy preview (STEP 7.1)
    pub fn preview_policy(&self, intent: &PolicyIntent) -> Result<PolicyPreview, String> {
        println!("🔍 PolicyEngine: Generating policy preview");
        
        // Validate intent first
        intent.validate()?;
        
        // Generate preview
        let preview = PolicyPreviewService::preview(intent);
        
        Ok(preview)
    }

    /// Dry-run policy evaluation (STEP 7.2)
    pub fn dry_run_policy(&self, intent: &PolicyIntent) -> Result<DryRunEvaluation, String> {
        println!("🧪 PolicyEngine: Running dry-run evaluation");
        
        // Create dry-run evaluator
        let evaluator = DryRunEvaluator::new(self.path_resolver.index().clone());
        
        // Run evaluation
        evaluator.evaluate(intent)
    }

     /// Validate policy safety (STEP 7.4)
    pub fn validate_policy_safety(&self, intent: &PolicyIntent) -> SafetyValidation {
        let kernel_connected = self.is_kernel_connected();
        PolicyGuard::validate(intent, kernel_connected)
    }
    
    /// Check if kernel is connected
    pub fn is_kernel_connected(&self) -> bool {
        let adapter = self.kernel_adapter.read();
        adapter.is_some()
    }

      /// Apply protection with assurance checks (enhanced version)
    pub fn apply_protection_with_assurance(&self, intent: PolicyIntent, confirmed: bool) -> Result<u64, String> {
        println!("🛡️ PolicyEngine: Applying protection with assurance checks");
        
        // Step 1: Basic validation
        intent.validate()?;
        
        // Step 2: Safety validation
        let safety = self.validate_policy_safety(&intent);
        
        if !safety.is_valid {
            return Err(format!("Policy failed safety validation: {:?}", safety.errors));
        }
        
        // Step 3: Check if confirmation required
        if safety.requires_confirmation && !confirmed {
            return Err("Policy requires confirmation before applying".to_string());
        }
        
        // Step 4: Show warnings
        if !safety.warnings.is_empty() {
            println!("⚠️  Safety warnings:");
            for warning in &safety.warnings {
                println!("   • {}", warning);
            }
        }
        
        // Step 5: Apply protection (original method)
        self.apply_protection(intent)
    }

      /// Get enforcement statistics
      /// Get enforcement statistics
    pub fn get_enforcement_stats(&self) -> EnforcementStats {
        let stats = self.policy_store.get_stats();
        
        EnforcementStats {
            total_policies: stats.total_policies,
            real_enforcement: if self.is_kernel_connected() { stats.active_policies } else { 0 },
            simulated: if !self.is_kernel_connected() { stats.active_policies } else { 0 },
            healthy: stats.active_policies, // Simplified for now
            warning: 0,
            failed: 0,
        }
    }
    
     pub fn get_policy_health(&self, policy_id: u64) -> Option<(HealthStatus, String)> {
        // Check if policy exists
        match self.policy_store.get_policy_by_id(policy_id) {
            Some(policy) => {
                let kernel_connected = self.is_kernel_connected();
                let is_active = policy.is_active;
                
                if !is_active {
                    Some((HealthStatus::Failed, "Policy is inactive".to_string()))
                } else if !kernel_connected {
                    Some((HealthStatus::Warning, "Running in simulation mode".to_string()))
                } else {
                    // In a real implementation, you would verify with kernel
                    // For now, assume healthy if kernel is connected and policy is active
                    Some((HealthStatus::Healthy, "Policy is active and healthy".to_string()))
                }
            }
            None => None,
        }
    }

}

/// Policy engine statistics
#[derive(Debug, Clone)]
pub struct PolicyEngineStats {
    pub total_policies: usize,
    pub active_policies: usize,
    pub protected_nodes: usize,
    pub kernel_connected: bool,
}