//! Policy Preview Engine (STEP 7.1)
//! Purpose: Show admin what will REALLY happen before applying
//! Especially important for READ = BLOCK ALL expansion
// src/policy/policy_preview.rs
use super::policy_intent::{PolicyIntent, ProtectionAction, ProtectionOperations};
use super::kernel_policy::KernelOperations;

/// Preview of what a policy will actually do
#[derive(Debug, Clone)]
pub struct PolicyPreview {
    pub intent: PolicyIntent,
    pub effective_operations: KernelOperations,
    pub is_block_all: bool,
    pub human_readable: String,
}

/// Policy Preview Service
pub struct PolicyPreviewService;

impl PolicyPreviewService {    
    /// Create policy preview from intent
    pub fn preview(intent: &PolicyIntent) -> PolicyPreview {
        println!("🔍 PolicyPreviewService: Generating preview for intent");
        println!("   Original: {}", intent.describe());
        
        // Expand READ if present
        let expanded_ops = intent.operations.expand_for_kernel();
        
        // Convert to kernel operations
        let effective_ops = match intent.action {
            ProtectionAction::Block => {
                KernelOperations::from_protection_operations(&expanded_ops, intent.action)
            }
            ProtectionAction::Allow => {
                // For Allow, show what will be blocked (inverse logic)
                KernelOperations::from_protection_operations(&expanded_ops, intent.action)
            }
            ProtectionAction::Audit => {
                // For Audit, show what will be logged
                KernelOperations::from_protection_operations(&expanded_ops, intent.action)
            }
        };
        
        // let is_block_all = effective_ops.is_block_all();
        let is_block_all =
        intent.action == ProtectionAction::Block &&
        intent.operations.read;
        let human_readable = Self::generate_human_readable(intent, &effective_ops, is_block_all);
        
        PolicyPreview {
            intent: intent.clone(),
            effective_operations: effective_ops,
            is_block_all,
            human_readable,
        }
    }
    
    /// Generate human-readable preview
    pub fn generate_human_readable(
        intent: &PolicyIntent,
        effective_ops: &KernelOperations,
        is_block_all: bool,
    ) -> String {
        let mut lines = Vec::new();
        
        lines.push("=".repeat(50));
        lines.push("POLICY PREVIEW".to_string());
        lines.push("=".repeat(50));
        
        // Basic info
        lines.push(format!("Action      : {:?}", intent.action));
        lines.push(format!("Scope       : {:?}", intent.scope));
        
        // Show what admin selected
        let selected_ops: Vec<&str> = {
            let mut ops = Vec::new();
            if intent.operations.read { ops.push("READ"); }
            if intent.operations.write { ops.push("WRITE"); }
            if intent.operations.delete { ops.push("DELETE"); }
            if intent.operations.rename { ops.push("RENAME"); }
            if intent.operations.create { ops.push("CREATE"); }
            ops
        };
        
        lines.push(format!("Selected    : {}", 
            if selected_ops.is_empty() { "None".to_string() } 
            else { selected_ops.join(", ") }
        ));
        
        lines.push("-".repeat(50));
        lines.push("EFFECTIVE BEHAVIOR:".to_string());
        
        if is_block_all {
            lines.push("⚠️  READ selected → BLOCK ALL ACCESS".to_string());
            lines.push("All operations will be blocked:".to_string());
            lines.push("  ✓ Block Write".to_string());
            lines.push("  ✓ Block Delete".to_string());
            lines.push("  ✓ Block Rename".to_string());
            lines.push("  ✓ Block Create".to_string());
            lines.push("  ✓ Block Copy".to_string());
            lines.push("  ✓ Block Execute".to_string());
            
            if intent.action == ProtectionAction::Block {
                lines.push("\n💡 Enterprise DLP Rule:".to_string());
                lines.push("Blocking READ means blocking ALL access".to_string());
                lines.push("This prevents copying, previewing, or metadata access".to_string());
            }
        } else {
            // Show individual operations
            if intent.action == ProtectionAction::Block {
                lines.push("Blocked operations:".to_string());
                if effective_ops.write { lines.push("  ✓ Block Write".to_string()); }
                if effective_ops.delete { lines.push("  ✓ Block Delete".to_string()); }
                if effective_ops.rename { lines.push("  ✓ Block Rename".to_string()); }
                if effective_ops.create { lines.push("  ✓ Block Create".to_string()); }
            } else if intent.action == ProtectionAction::Allow {
                lines.push("Allowed operations:".to_string());
                if !effective_ops.write { lines.push("  ✓ Allow Write".to_string()); }
                if !effective_ops.delete { lines.push("  ✓ Allow Delete".to_string()); }
                if !effective_ops.rename { lines.push("  ✓ Allow Rename".to_string()); }
                if !effective_ops.create { lines.push("  ✓ Allow Create".to_string()); }
            }
        }
        
        lines.push("=".repeat(50));
        lines.join("\n")
    }
    
    /// Get quick summary of policy impact
    pub fn get_quick_summary(intent: &PolicyIntent) -> String {
         if intent.action == ProtectionAction::Block && intent.operations.read {
                return "BLOCK ALL ACCESS (READ selected)".to_string();
            }
        let expanded_ops = intent.operations.expand_for_kernel();
        let effective_ops = KernelOperations::from_protection_operations(&expanded_ops, intent.action);
        
        let blocked_count = [
            effective_ops.write,
            effective_ops.delete,
            effective_ops.rename,
            effective_ops.create,
        ].iter().filter(|&&b| b).count();
        
        match intent.action {
            ProtectionAction::Block => format!("Block {} operations", blocked_count),
            ProtectionAction::Allow => format!("Allow {} operations", 6 - blocked_count),
            ProtectionAction::Audit => "Audit mode".to_string(),
        }
    }


}