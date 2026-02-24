//! Policy Dry-Run Evaluator (STEP 7.2)
//! Purpose: Simulate policy impact without touching kernel
// src/policy/policy_dry_Run.rs
use std::sync::Arc;
use crate::protection_modules::file_protection::fs_index::FilesystemIndex;

use super::policy_intent::{PolicyIntent, ProtectionAction};
use super::policy_preview::PolicyPreviewService;
use super::kernel_policy::{KernelPolicy, PolicyNormalizer};

/// Dry-run result for a single operation
#[derive(Debug, Clone)]
pub struct DryRunResult {
    pub operation: String,
    pub will_block: bool,
    pub reason: String,
}

/// Dry-run evaluation for a policy
#[derive(Debug, Clone)]
pub struct DryRunEvaluation {
    pub node_id: u64,
    pub policy_preview: String,
    pub results: Vec<DryRunResult>,
    pub summary: String,
}

/// Dry-Run Evaluator
pub struct DryRunEvaluator {
    index: Arc<FilesystemIndex>,
}

impl DryRunEvaluator {
    pub fn new(index: Arc<FilesystemIndex>) -> Self {
        DryRunEvaluator { index }
    }
    
    /// Evaluate policy impact without applying
    pub fn evaluate(&self, intent: &PolicyIntent) -> Result<DryRunEvaluation, String> {
        println!("🧪 DryRunEvaluator: Simulating policy impact");
        println!("   Node ID: {}, Action: {:?}", intent.node_id, intent.action);
        
        // Validate node exists
        self.validate_node(intent.node_id)?;
        
        // Get policy preview
        let preview = PolicyPreviewService::preview(intent);
        
        // Generate dry-run results
        let results = Self::simulate_operations(intent);
        
        // Create summary
        let summary = Self::generate_summary(&results, intent);
        
        Ok(DryRunEvaluation {
            node_id: intent.node_id,
            policy_preview: preview.human_readable,
            results,
            summary,
        })
    }
    
    /// Validate node exists (without resolving NT paths)
    fn validate_node(&self, node_id: u64) -> Result<(), String> {
        // In a real implementation, this would check the filesystem index
        // For now, just check it's not zero
        if node_id == 0 {
            return Err("Invalid node ID (0)".to_string());
        }
        Ok(())
    }
    
    /// Simulate common user operations
    fn simulate_operations(intent: &PolicyIntent) -> Vec<DryRunResult> {
        let mut results = Vec::new();
        
        // Simulate READ operation
        let (read_will_block, read_reason) = if intent.operations.read {
            (true, "READ selected → BLOCK ALL".to_string())
        } else {
            (false, "READ not blocked".to_string())
        };
        
        results.push(DryRunResult {
            operation: "Open/Read file".to_string(),
            will_block: read_will_block,
            reason: read_reason,
        });
        
        // Simulate other operations
        let operations = vec![
            ("Copy file", "copy"),
            ("Delete file", "delete"),
            ("Rename file", "rename"),
            ("Modify/Write file", "write"),
            ("Execute file", "execute"),
            ("Create new file", "create"),
        ];
        
        for (display_name, op_name) in operations {
            let will_block = match op_name {
                "read" => intent.operations.read,
                "write" => intent.operations.write,
                "delete" => intent.operations.delete,
                "rename" => intent.operations.rename,
                "create" => intent.operations.create,
                _ => false,
            };
            
            // Apply READ = BLOCK ALL rule
            let (final_block, reason) = if intent.operations.read && intent.action == ProtectionAction::Block {
                (true, "READ selected → BLOCK ALL".to_string())
            } else {
                (will_block, if will_block { "Blocked by policy".to_string() } else { "Allowed".to_string() })
            };
            
            results.push(DryRunResult {
                operation: display_name.to_string(),
                will_block: final_block,
                reason,
            });
        }
        
        results
    }
    
    /// Generate summary from results
    fn generate_summary(results: &[DryRunResult], intent: &PolicyIntent) -> String {
        let blocked_count = results.iter().filter(|r| r.will_block).count();
        let total_count = results.len();
        
        let mut summary = format!("Dry Run Summary - Node ID: {}\n", intent.node_id);
        summary.push_str(&format!("Total operations simulated: {}\n", total_count));
        summary.push_str(&format!("Will be blocked: {}\n", blocked_count));
        summary.push_str(&format!("Will be allowed: {}\n", total_count - blocked_count));
        
        if intent.operations.read && intent.action == ProtectionAction::Block {
            summary.push_str("\n⚠️  CRITICAL: READ selected → ALL operations blocked\n");
            summary.push_str("This is the Enterprise DLP standard for read protection");
        }
        
        summary
    }
    
    /// Quick dry-run (just returns blocking status for common operations)
    pub fn quick_dry_run(intent: &PolicyIntent) -> Vec<(String, bool)> {
        let mut checks = Vec::new();
        
        // Common operations users care about
        let operations = vec![
            ("Open file", intent.operations.read),
            ("Save changes", intent.operations.write),
            ("Delete", intent.operations.delete),
            ("Rename", intent.operations.rename),
            ("Create new file", intent.operations.create),
        ];
        
        for (name, selected) in operations {
            // Apply READ = BLOCK ALL rule
            let will_block = if intent.operations.read && intent.action == ProtectionAction::Block {
                true
            } else {
                selected
            };
            
            checks.push((name.to_string(), will_block));
        }
        
        checks
    }
}