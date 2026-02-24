//! Policy Guard - Safety Rules (STEP 7.4)
//! Purpose: Prevent dangerous policies, require confirmations
// src/policy/policy_guard.rs
use super::policy_intent::{PolicyIntent, ProtectionAction, ProtectionScope};

/// Safety validation result
#[derive(Debug, Clone)]
pub struct SafetyValidation {
    pub is_valid: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub requires_confirmation: bool,
    pub confirmation_message: Option<String>,
}

/// Policy Guard - Enforces safety rules
pub struct PolicyGuard;

impl PolicyGuard {
    /// Validate policy intent for safety
    pub fn validate(intent: &PolicyIntent, kernel_connected: bool) -> SafetyValidation {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        let mut requires_confirmation = false;
        let mut confirmation_message = None;
        
        println!("🛡️  PolicyGuard: Validating policy safety");
        
        // Rule 1: Allow + Read is invalid
        if intent.action == ProtectionAction::Allow && intent.operations.read {
            errors.push("READ cannot be used with Allow action".to_string());
            errors.push("Use Block action for read protection".to_string());
        }
        
        // Rule 2: READ = BLOCK ALL warning
        if intent.operations.read && intent.action == ProtectionAction::Block {
            warnings.push("READ selected → BLOCK ALL ACCESS".to_string());
            warnings.push("This will block ALL operations (write, delete, rename, create, copy, execute)".to_string());
            requires_confirmation = true;
            confirmation_message = Some(
                "You are about to block ALL access to this file/folder.\n\n\
                This means:\n\
                • Users cannot open/read the file\n\
                • Users cannot copy/duplicate it\n\
                • Users cannot delete/rename it\n\
                • Users cannot modify it\n\n\
                This is the Enterprise DLP standard for read protection.\n\
                Are you sure you want to continue?".to_string()
            );
        }
        
        // Rule 3: Recursive + Block All requires confirmation
        if matches!(intent.scope, ProtectionScope::FolderRecursive) 
            && intent.operations.read 
            && intent.action == ProtectionAction::Block {
            warnings.push("Recursive folder with BLOCK ALL access".to_string());
            warnings.push("This will block ALL access to ALL files in this folder and subfolders".to_string());
            requires_confirmation = true;
            confirmation_message = Some(
                "⚠️  DANGER: Recursive BLOCK ALL\n\n\
                You are about to block ALL access to:\n\
                • This folder\n\
                • ALL subfolders\n\
                • ALL files within\n\n\
                This will affect potentially thousands of files.\n\
                Are you absolutely sure?".to_string()
            );
        }
        
        // Rule 4: Kernel disconnected warning
        if !kernel_connected {
            warnings.push("Kernel driver not connected".to_string());
            warnings.push("Policy will run in SIMULATION MODE only".to_string());
            warnings.push("No actual blocking will occur".to_string());
        }
        
        // Determine if valid
        let is_valid = errors.is_empty();
        
        SafetyValidation {
            is_valid,
            warnings,
            errors,
            requires_confirmation,
            confirmation_message,
        }
    }
    
    /// Generate safety report
    pub fn generate_safety_report(intent: &PolicyIntent, kernel_connected: bool) -> String {
        let validation = Self::validate(intent, kernel_connected);
        
        let mut report = String::new();
        report.push_str(&"=".repeat(60));
        report.push_str("\nPOLICY SAFETY REPORT\n");
        report.push_str(&"=".repeat(60));
        
        report.push_str("\n\n📋 POLICY DETAILS:\n");
        report.push_str(&format!("Action: {:?}\n", intent.action));
        report.push_str(&format!("Scope: {:?}\n", intent.scope));
        report.push_str(&format!("Node ID: {}\n", intent.node_id));
        
        report.push_str("\n🔒 SAFETY CHECKS:\n");
        report.push_str(&format!("Kernel Connected: {}\n", 
            if kernel_connected { "✅ Yes" } else { "❌ No (Simulation Mode)" }
        ));
        
        if !validation.errors.is_empty() {
            report.push_str("\n❌ ERRORS (Must fix):\n");
            for error in &validation.errors {
                report.push_str(&format!("  • {}\n", error));
            }
        }
        
        if !validation.warnings.is_empty() {
            report.push_str("\n⚠️  WARNINGS:\n");
            for warning in &validation.warnings {
                report.push_str(&format!("  • {}\n", warning));
            }
        }
        
        if validation.requires_confirmation {
            report.push_str("\n🔐 CONFIRMATION REQUIRED:\n");
            if let Some(msg) = &validation.confirmation_message {
                report.push_str(&format!("{}\n", msg));
            }
        }
        
        report.push_str(&format!("\nOverall Status: {}\n", 
            if validation.is_valid { "✅ PASSED" } else { "❌ FAILED" }
        ));
        report.push_str(&"=".repeat(60));
        
        report
    }
    
    /// Check if policy requires special confirmation
    pub fn requires_confirmation(intent: &PolicyIntent) -> bool {
        // High-risk policies that need extra confirmation
        (intent.operations.read && intent.action == ProtectionAction::Block) ||
        (matches!(intent.scope, ProtectionScope::FolderRecursive) && intent.operations.read)
    }
    
    /// Get confirmation message for high-risk policies
    pub fn get_confirmation_message(intent: &PolicyIntent) -> Option<String> {
        if !Self::requires_confirmation(intent) {
            return None;
        }
        
        if intent.operations.read && intent.action == ProtectionAction::Block {
            if matches!(intent.scope, ProtectionScope::FolderRecursive) {
                Some(
                    "⚠️  CRITICAL: Recursive BLOCK ALL\n\n\
                    You are blocking ALL access to this folder and ALL subfolders.\n\
                    This will affect every file within.\n\n\
                    Type 'CONFIRM_RECURSIVE_BLOCK_ALL' to proceed.".to_string()
                )
            } else {
                Some(
                    "⚠️  WARNING: BLOCK ALL ACCESS\n\n\
                    You are blocking ALL access to this file/folder.\n\
                    Users will not be able to read, copy, modify, or delete.\n\n\
                    Type 'CONFIRM_BLOCK_ALL' to proceed.".to_string()
                )
            }
        } else {
            None
        }
    }
}