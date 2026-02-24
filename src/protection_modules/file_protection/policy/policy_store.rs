//! Policy Store (STEP 4)
//! Core Principle: Track active policies, survive UI refresh
// src/policy/policy_store.rs
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use super::policy_intent::PolicyIntent;
use super::kernel_policy::KernelPolicy;

/// Active policy entry
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub intent: PolicyIntent,          // Admin's original intent
    pub kernel_policies: Vec<KernelPolicy>, // Kernel-ready policies
    pub kernel_policy_ids: Vec<u64>,   // IDs returned by kernel
    pub is_active: bool,               // Is currently enforced?
    pub created_at: u64,               // When created
    pub last_updated: u64,             // When last updated
}

// Add to existing PolicyStore struct
#[derive(Debug, Clone)]
pub struct PolicyStatus {
    pub policy_id: u64,
    pub enforcement_mode: EnforcementMode,
    pub kernel_applied: bool,
    pub verified_at: u64,
    pub last_checked: u64,
    pub health_status: HealthStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    Real,       // Actually enforced by kernel
    Simulated,  // Running in simulation mode
    Testing,    // In test/dry-run mode
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,        // Policy is active and verified
    Warning,        // Some issues detected
    Degraded,       // Policy partially applied
    Failed,         // Policy failed to apply
    Unknown,        // Status unknown
}

/// Policy store - manages active policies
pub struct PolicyStore {
    policies: RwLock<HashMap<u64, ActivePolicy>>, // policy_id -> ActivePolicy
    node_to_policies: RwLock<HashMap<u64, Vec<u64>>>, // node_id -> policy_ids
}

impl PolicyStore {
    /// Create new policy store
    pub fn new() -> Arc<Self> {
        Arc::new(PolicyStore {
            policies: RwLock::new(HashMap::new()),
            node_to_policies: RwLock::new(HashMap::new()),
        })
    }

     /// Get policy by kernel policy ID
    pub fn get_policy_by_kernel_id(&self, kernel_policy_id: u64) -> Option<ActivePolicy> {
        let policies = self.policies.read();
        
        // Search through all policies for matching kernel policy ID
        for policy in policies.values() {
            if policy.kernel_policy_ids.contains(&kernel_policy_id) {
                return Some(policy.clone());
            }
        }
        
        None
    }
    
    /// Get policy by any policy ID (could be kernel ID or our internal ID)
    pub fn get_policy_by_id(&self, policy_id: u64) -> Option<ActivePolicy> {
        // First try exact match (could be our internal policy ID)
        if let Some(policy) = self.get_policy(policy_id) {
            return Some(policy);
        }
        
        // Try as kernel policy ID
        self.get_policy_by_kernel_id(policy_id)
    }
    
    /// Get node ID by kernel policy ID
    pub fn get_node_id_by_kernel_id(&self, kernel_policy_id: u64) -> Option<u64> {
        self.get_policy_by_kernel_id(kernel_policy_id)
            .map(|policy| policy.intent.node_id)
    }
    
    /// Add a new policy
    pub fn add_policy(
        &self,
        policy_id: u64,
        intent: PolicyIntent,
        kernel_policies: Vec<KernelPolicy>,
        kernel_policy_ids: Vec<u64>,
    ) {
        println!("💾 PolicyStore: Adding policy ID {}", policy_id);
        
        // Store node_id before moving intent
        let node_id = intent.node_id;
        
        let active_policy = ActivePolicy {
            intent,
            kernel_policies,
            kernel_policy_ids,
            is_active: true,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Store in policies map
        {
            let mut policies = self.policies.write();
            policies.insert(policy_id, active_policy);
        }
        
        // Update node-to-policies mapping using stored node_id
        {
            let mut node_map = self.node_to_policies.write();
            node_map.entry(node_id)
                .or_insert_with(Vec::new)
                .push(policy_id);
        }
        
        println!("   ✅ Policy stored successfully");
    }
    
    /// Get policy by ID
    pub fn get_policy(&self, policy_id: u64) -> Option<ActivePolicy> {
        let policies = self.policies.read();
        policies.get(&policy_id).cloned()
    }
    
    /// Get all policies for a node
    pub fn get_policies_for_node(&self, node_id: u64) -> Vec<ActivePolicy> {
        let node_map = self.node_to_policies.read();
        let policy_ids = node_map.get(&node_id).cloned().unwrap_or_default();
        
        let policies = self.policies.read();
        policy_ids.into_iter()
            .filter_map(|id| policies.get(&id).cloned())
            .collect()
    }
    
    /// Get all active policies
    pub fn get_all_policies(&self) -> Vec<ActivePolicy> {
        let policies = self.policies.read();
        policies.values().cloned().collect()
    }
    
    /// Remove policy
    pub fn remove_policy(&self, policy_id: u64) -> Option<ActivePolicy> {
        println!("🗑️ PolicyStore: Removing policy ID {}", policy_id);
        
        let removed_policy = {
            let mut policies = self.policies.write();
            policies.remove(&policy_id)
        };
        
        if let Some(policy) = &removed_policy {
            // Remove from node-to-policies mapping
            let mut node_map = self.node_to_policies.write();
            if let Some(policy_ids) = node_map.get_mut(&policy.intent.node_id) {
                policy_ids.retain(|&id| id != policy_id);
                if policy_ids.is_empty() {
                    node_map.remove(&policy.intent.node_id);
                }
            }
            
            println!("   ✅ Policy removed from store");
        }
        
        removed_policy
    }
    
    /// Update policy status
    pub fn update_policy_status(&self, policy_id: u64, is_active: bool) -> bool {
        let mut policies = self.policies.write();
        
        if let Some(policy) = policies.get_mut(&policy_id) {
            policy.is_active = is_active;
            policy.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            println!("📝 PolicyStore: Updated policy ID {} status to active={}", policy_id, is_active);
            true
        } else {
            println!("❌ PolicyStore: Policy ID {} not found", policy_id);
            false
        }
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> PolicyStoreStats {
        let policies = self.policies.read();
        let node_map = self.node_to_policies.read();
        
        let total_policies = policies.len();
        let active_policies = policies.values().filter(|p| p.is_active).count();
        
        PolicyStoreStats {
            total_policies,
            active_policies,
            protected_nodes: node_map.len(),
        }
    }
    
    /// Clear all policies (for testing/reset)
    pub fn clear(&self) {
        println!("🧹 PolicyStore: Clearing all policies");
        
        let mut policies = self.policies.write();
        let mut node_map = self.node_to_policies.write();
        
        policies.clear();
        node_map.clear();
    }
}

/// Policy store statistics
#[derive(Debug, Clone)]
pub struct PolicyStoreStats {
    pub total_policies: usize,
    pub active_policies: usize,
    pub protected_nodes: usize,
}

#[derive(Debug, Clone)]
pub struct EnforcementStats {
    pub total_policies: usize,
    pub real_enforcement: usize,
    pub simulated: usize,
    pub healthy: usize,
    pub warning: usize,
    pub failed: usize,
}