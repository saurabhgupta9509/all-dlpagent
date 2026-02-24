//! Policy Intent Model (STEP 4.1)
//! Core Principle: Admin expresses intent, Agent implements it securely
// src/policy/policy_intent.rs
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Scope of protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum ProtectionScope {
    File,           // Single file only
    Folder,         // Folder only (non-recursive)
    FolderRecursive, // Folder and all subfolders/files
}

/// Protection action

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum ProtectionAction {
    Block,          // Prevent operation
    Allow,          // Allow operation (whitelist)
    Audit,          // Allow but log (monitor)
}

/// Operations to protect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionOperations {
    pub read: bool,          // ⚠️ READ = BLOCK ALL (Enterprise rule)
    pub write: bool,         // Block/Allow/Audit write
    pub delete: bool,        // Block/Allow/Audit delete
    pub rename: bool,        // Block/Allow/Audit rename
    pub create: bool,        // Block/Allow/Audit create (folders only)
}

impl Default for ProtectionOperations {
    fn default() -> Self {
        ProtectionOperations {
            read: false,
            write: true,     // Default: protect against modifications
            delete: true,
            rename: true,
            create: true,
        }
    }
}

impl ProtectionOperations {
    /// Create read-only protection (READ = true means block everything)
    pub fn read_only() -> Self {
        ProtectionOperations {
            read: true,     // Allow read
            write: true,     // Block write
            delete: true,    // Block delete
            rename: true,    // Block rename
            create: true,    // Block create
        }
    }
    
    /// Create full protection (block everything except read)
    pub fn full_protection() -> Self {
        ProtectionOperations {
            read: true,     // Allow read
            write: true,     // Block write
            delete: true,    // Block delete
            rename: true,    // Block rename
            create: true,    // Block create
        }
    }
    
    /// Create audit-only (monitor everything)
    pub fn audit_only() -> Self {
        ProtectionOperations {
            read: false,      // Audit read
            write: false,     // Audit write
            delete: false,    // Audit delete
            rename: false,    // Audit rename
            create: false,    // Audit create
        }
    }

     /// Check if this is a "block all" policy (READ = true)
    pub fn is_block_all(&self) -> bool {
        self.read
    }
    
    /// Expand READ flag to all operations for kernel
    /// READ = true → set all other flags to true
    pub fn expand_for_kernel(&self) -> Self {
        if self.read {
            // READ is master switch: block everything
            ProtectionOperations {
                read: false,      // Kernel doesn't use READ flag
                write: true,      // All operations blocked
                delete: true,
                rename: true,
                create: true,
            }
        } else {
            // Normal case: pass through individual flags
            *self
        }
    }
}

/// Admin's protection intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIntent {
    pub node_id: u64,                    // ID from STEP 3 selection
    pub scope: ProtectionScope,          // File, Folder, or Recursive
    pub action: ProtectionAction,        // Block, Allow, or Audit
    pub operations: ProtectionOperations, // What to protect
    pub created_by: String,              // Admin username/ID
    pub timestamp: u64,                  // Unix timestamp
    pub comment: Option<String>,         // Optional admin comment
}

impl PolicyIntent {
    /// Create new policy intent
    pub fn new(
        node_id: u64,
        scope: ProtectionScope,
        action: ProtectionAction,
        operations: ProtectionOperations,
        created_by: &str,
        comment: Option<&str>,
    ) -> Self {
        PolicyIntent {
            node_id,
            scope,
            action,
            operations,
            created_by: created_by.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            comment: comment.map(|s| s.to_string()),
        }
    }

    
    pub fn validate(&self) -> Result<(), String> {

        println!("📥 Received PolicyIntent: {:?}", self);
        
    // Node ID must be non-zero
        if self.node_id == 0 {
            return Err("Invalid node ID (0)".to_string());
        }

        // ❌ CREATE is not valid for File scope
        if self.scope == ProtectionScope::File && self.operations.create {
            return Err("CREATE operation is not allowed for File scope".to_string());
        }

        // // ❌ Folder cannot have execute unless READ is true
        // if matches!(self.scope, ProtectionScope::Folder | ProtectionScope::FolderRecursive)
        //     && !self.operations.read
        // {
        //     return Err("Folders cannot have execute protection".to_string());
        // }

        // Created by cannot be empty
        if self.created_by.trim().is_empty() {
            return Err("Creator name cannot be empty".to_string());
        }

        // ❌ Allow + Read is illegal
        if self.action == ProtectionAction::Allow && self.operations.read {
            return Err("READ cannot be used with Allow action".to_string());
        }

        // READ = BLOCK ALL (log only)
        if self.operations.read {
            println!("⚠️ READ selected: Applying BLOCK ALL semantics");
        }

        Ok(())
    }

    /// Get a human-readable description
    pub fn describe(&self) -> String {
        let scope_str = match self.scope {
            ProtectionScope::File => "file",
            ProtectionScope::Folder => "folder",
            ProtectionScope::FolderRecursive => "folder (recursive)",
        };
        
        let action_str = match self.action {
            ProtectionAction::Block => "Block",
            ProtectionAction::Allow => "Allow",
            ProtectionAction::Audit => "Audit",
        };
        
         if self.operations.read {
            // READ = block everything
            format!("{} ALL operations on {} (ID: {}) - READ selected", 
                action_str, scope_str, self.node_id)
        } else {
        let operations: Vec<&str> = {
            let mut ops = Vec::new();
            if self.operations.read { ops.push("read"); }
            if self.operations.write { ops.push("write"); }
            if self.operations.delete { ops.push("delete"); }
            if self.operations.rename { ops.push("rename"); }
            if self.operations.create { ops.push("create"); }
            ops
        };  
        
        let ops_str = if operations.is_empty() {
            "nothing".to_string()
        } else {
            operations.join(", ")
        };
        
        format!("{} {} on {} (ID: {})", action_str, ops_str, scope_str, self.node_id)
    }
}
}