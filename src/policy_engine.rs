use std::collections::HashMap;

// src/policy_engine.rs

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::{Arc, Mutex};

use crate::policy_constants::POLICY_NETWORK_DNS_BLOCK;

/// Represents a policy received from the backend.
/// This struct MUST match the Java PolicyCapabilityDTO.
#[derive(Debug, Clone , Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub code: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub is_active: bool,
    #[serde(default)]
    pub policy_data: String,
}

/// Main engine that manages policies and provides checking methods.
pub struct PolicyEngine {
    policies: Vec<Policy>,
    /// NEW: Stores the *data* for file policies, fetched from /api/agent/file-policies
    file_policies: Arc<Mutex<HashMap<String, Vec<String>>>>,
}


impl PolicyEngine {
    /// Create a new PolicyEngine.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            file_policies: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Updates the engine with a new set of policies from the backend.
    pub fn update_policies(&mut self, policies: Vec<Policy>) {
        self.policies = policies;
        debug!(
            "🔄 Updated PolicyEngine with {} policies",
            self.policies.len()
        );
    }

    /// NEW: Updates the specific map of file policies
    pub fn update_file_policies(&self, file_policies: HashMap<String, Vec<String>>) {
        let mut lock = self.file_policies.lock().unwrap();
        *lock = file_policies;
        debug!(
            "🔄 Updated File Policy Map with {} rule categories",
            lock.len()
        );
    }

    /// NEW: Provides a clone of the file policies for a module to use
    pub fn get_file_policies(&self) -> HashMap<String, Vec<String>> {
        self.file_policies.lock().unwrap().clone()
    }

    /// Gets and parses the JSON string from a policy's `policy_data` field.
    /// Returns a default `T` if the policy is not active or parsing fails.
    pub fn get_policy_json_data<T: for<'de> serde::Deserialize<'de> + Default>(
        &self,
        policy_code: &str,
    ) -> T {
        if let Some(policy) = self
            .policies
            .iter()
            .find(|p| p.code == policy_code && p.is_active)
        {
            // First, check if the data string is empty. If it is, return a default
            // value (e.g., an empty list) without trying to parse it.
            if policy.policy_data.is_empty() {
                return T::default();
            }

            // Only try to parse if the string is NOT empty.
            serde_json::from_str(&policy.policy_data).unwrap_or_else(|e| {
                warn!(
                    "Failed to parse policy data for {}: {}. Data was: '{}'",
                    policy_code, e, policy.policy_data
                );
                T::default() // Return default if parsing fails.
            })
        } else {
            // If policy isn't active, return default.
            T::default()
        }
    }

    /// Checks if a specific policy code is active.
    pub fn is_policy_active(&self, policy_code: &str) -> bool {
        self.policies
            .iter()
            .any(|p| p.code == policy_code && p.is_active)
    }

    // ===== CATEGORY CHECKS (For the AgentCore) =====

    /// Checks if any USB protection policy is active.
    pub fn is_usb_protection_enabled(&self) -> bool {
        self.policies
            .iter()
            .any(|p| p.category == "USB" && p.is_active)
    }

    /// Checks if any Network protection policy is active.
    pub fn is_network_protection_enabled(&self) -> bool {
        self.is_policy_active(POLICY_NETWORK_DNS_BLOCK)
    }

    // / Checks if any web protection policy is active.
    pub fn is_web_protection_enabled(&self) -> bool {
        self.policies
            .iter()
            .any(|p| p.category == "WEB" && p.is_active)
            // || self.is_policy_active(POLICY_WEB_MONITOR_HISTORY)
            // || self.is_policy_active(POLICY_WEB_UPLOAD_BLOCK)
            // || self.is_policy_active(POLICY_WEB_DOWNLOAD_BLOCK)
            // || self.is_policy_active(POLICY_WEB_URL_BLOCK)
    }   

    /// NEW: Checks if any file protection policy is active.
    pub fn is_file_protection_enabled(&self) -> bool {
            self.is_policy_active(crate::policy_constants::FILE_PROTECTION_ENABLED)
    }

  
    /// Returns a list of all currently active policies.
    pub fn get_active_policies(&self) -> Vec<&Policy> {
        self.policies.iter().filter(|p| p.is_active).collect()
    }

      /// Helper method to get explicit block list for web policies
    pub fn get_explicit_block_list(&self, policy_code: &str) -> Vec<String> {
        self.get_policy_json_data(policy_code)
    }

    
    /// Returns the total number of policies (active and inactive).
    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }

}

// Default implementation
impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}