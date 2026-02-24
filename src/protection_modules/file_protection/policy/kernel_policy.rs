//! Kernel Policy Model (STEP 4.3)
//! Core Principle: Convert Admin intent to kernel-understandable rules
//! IMPORTANT: Implements READ = BLOCK ALL enterprise DLP rule

use crate::protection_modules::file_protection::policy::{PolicyIntent, ProtectionAction, ProtectionOperations, ProtectionScope};
// src/policy/kernel_policy.rs
/// How kernel should match the path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMatchType {
    Exact, // Exact NT path match (files)
    Prefix, // NT path prefix match (folders - recursive)
}

/// Kernel-ready policy
#[derive(Debug, Clone)]
pub struct KernelPolicy {
    pub policy_id: u64, // Unique policy ID
    pub nt_path: String, // NT path from PathResolver (INTERNAL ONLY)
    pub match_type: PathMatchType, // How to match the path
    // pub is_recursive: bool, // For folders: apply to subfolders
    pub blocked_ops: KernelOperations, // Operations to block
    // pub audit_ops: KernelOperations, // Operations to audit (monitor)

    pub block_all: bool, // Whether this policy blocks all operations (from READ)
    pub created_by: String, // Admin who created it
    pub timestamp: u64, // When created
    // pub comment: Option<String>, // Optional comment
}

/// Kernel operations (binary flags for kernel)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelOperations {
    pub write: bool,
    pub delete: bool,
    pub rename: bool,
    pub create: bool,
}

impl Default for KernelOperations {
    fn default() -> Self {
        KernelOperations {
            write: false,
            delete: false,
            rename: false,
            create: false,
        }
    }
}

impl KernelOperations {
    /// Check if any operation is set
    pub fn is_empty(&self) -> bool {
        // ✅ REMOVED: !self.read &&
        !self.write && !self.delete && !self.rename && !self.create
    }

    /// Convert to binary flags (for kernel communication)
    pub fn to_flags(&self) -> (u8, u8, u8, u8) {
        ( self.write as u8, self.delete as u8, self.rename as u8, self.create as u8)
    }

    /// Convert from ProtectionOperations (Admin intent) to KernelOperations
    /// IMPORTANT: READ flag from admin intent expands to all operations
    pub fn from_protection_operations(
        ops: &ProtectionOperations,
        _action: ProtectionAction
    ) -> Self {
        // First, expand READ if it's present
        let expanded = ops.expand_for_kernel();

        KernelOperations {
            // read: false,
            write: expanded.write,
            delete: expanded.delete,
            rename: expanded.rename,
            create: expanded.create,
        }
    }

    /// Create a "block all" operations set
    pub fn block_all() -> Self {
        KernelOperations {
            // read: false, // Kernel doesn't need this
            write: true,
            delete: true,
            rename: true,
            create: true,
        }
    }
}

/// Policy normalizer - converts Admin intent to kernel policy
pub struct PolicyNormalizer;

impl PolicyNormalizer {
    /// Normalize NT path based on scope
    // fn normalize_nt_path(nt_path: String, scope:ProtectionScope) -> String {
    //     let mut path = nt_path;

    //     match scope {
    //         crate::policy::policy_intent::ProtectionScope::File => {
    //             // Files: keep as-is
    //             path
    //         }
    //         crate::policy::policy_intent::ProtectionScope::Folder |
    //         crate::policy::policy_intent::ProtectionScope::FolderRecursive => {
    //             // Folders: ensure trailing backslash for prefix matching
    //             // if !path.ends_with('\\') {
    //             //     path.push('\\');
    //             // }
    //               while path.ends_with("\\\\") {
    //                 path.pop();
    //             }

    //             match scope {
    //                 ProtectionScope::File => {
    //                     while path.ends_with('\\') {
    //                         path.pop();
    //                     }
    //                 }
    //                 ProtectionScope::Folder | ProtectionScope::FolderRecursive => {
    //                     if !path.ends_with('\\') {
    //                         path.push('\\');
    //                     }
    //                 }
    //              }
    //             path
    //         }
    //     }
    // }

    // fn normalize_nt_path(path: &str, is_folder: bool) -> String {
    //     let mut p = path.trim().replace('/', "\\");

    //     if is_folder && !p.ends_with('\\') {
    //         p.push('\\');
    //     }

    //     p
    // }

    /// Normalize policy intent into kernel policy(ies)
    pub fn normalize(
        intent: &PolicyIntent,
        nt_paths: Vec<String>,
        policy_id: u64
    ) -> Vec<KernelPolicy> {
        println!("🔄 PolicyNormalizer: Converting intent to kernel policy");
        println!("   Intent: {}", intent.describe());

        // Log READ semantics warning if applicable
        if intent.operations.read && matches!(intent.action, ProtectionAction::Block) {
            println!("   ⚠️  READ flag detected in intent - expanding to BLOCK ALL");
            println!("   ℹ️  Kernel will receive ALL operations blocked");
        }
        // let is_block_all = intent.action == ProtectionAction::Block && intent.operations.read;
        let is_block_all = intent.action == ProtectionAction::Block && intent.operations.read;
        
        nt_paths
            .into_iter()
            .map(|nt_path| {
                // let normalized_path = Self::normalize_nt_path(nt_path, intent.scope);
                let normalized_path = nt_path;
                let (match_type, is_recursive) = match intent.scope {
                    ProtectionScope::File => {
                        (PathMatchType::Exact, false)
                    }
                    ProtectionScope::Folder => {
                        (PathMatchType::Prefix, false)
                    }
                    ProtectionScope::FolderRecursive => {
                        (PathMatchType::Prefix, true)
                    }
                };

                // Convert protection operations to kernel operations
                let (blocked_ops, audit_ops) = match intent.action {
                    // ProtectionAction::Block => {
                    //     // Block operations - convert from ProtectionOperations
                    //     let blocked = KernelOperations::from_protection_operations(
                    //         &intent.operations,
                    //         intent.action
                    //     );

                    //     (blocked, KernelOperations::default())
                    // }
                    ProtectionAction::Block => {
                        let blocked = if is_block_all {
                            KernelOperations::block_all()
                        } else {
                            KernelOperations::from_protection_operations(
                                &intent.operations,
                                intent.action
                            )
                        };

                        (blocked, KernelOperations::default())
                    }
                    ProtectionAction::Allow => {
                        // Allow mode: block everything EXCEPT these operations
                        // This is inverse logic for allow-lists
                        let allowed = if intent.operations.read {
                            // If READ is allowed, block everything else
                            // But READ with Allow is invalid (should be caught in validation)
                            KernelOperations::default() // Fallback
                        } else {
                            // For Allow mode, we block what's NOT in the allow list
                            let expanded_ops = intent.operations.expand_for_kernel();
                            KernelOperations {
                                // read: !expanded_ops.read, // Not in kernel ops
                                write: !expanded_ops.write,
                                delete: !expanded_ops.delete,
                                rename: !expanded_ops.rename,
                                create: !expanded_ops.create,
                            }
                        };

                        (allowed, KernelOperations::default())
                    }
                    ProtectionAction::Audit => {
                        // Audit mode: allow but log (don't block)
                        let audit = KernelOperations::from_protection_operations(
                            &intent.operations,
                            intent.action
                        );

                        (KernelOperations::default(), audit)
                    }
                };

                let policy = KernelPolicy {
                    policy_id,
                    nt_path: normalized_path,
                    match_type,
                    // is_recursive,
                    blocked_ops,
                    // audit_ops,
                    block_all: is_block_all,
                    created_by: intent.created_by.clone(),
                    timestamp: intent.timestamp,
                    // comment: intent.comment.clone(),
                };

                println!("   ✅ Created kernel policy ID {} for path", policy_id);
                println!("      Match: {:?}, Recursive: {}", match_type, is_recursive);

                // Print operations based on action type
                match intent.action {
                    ProtectionAction::Block => {
                        if intent.operations.read {
                            println!("      🔒 READ = BLOCK ALL: All operations blocked");
                        } else {
                            println!(
                                "      Blocked ops: W{} D{} RN{} C{}",
                                // ✅ REMOVED: blocked_ops.read as u8,
                                blocked_ops.write as u8,
                                blocked_ops.delete as u8,
                                blocked_ops.rename as u8,
                                blocked_ops.create as u8
                            );
                        }
                    }
                    ProtectionAction::Allow => {
                        // For Allow, show what's allowed (not blocked)
                        println!(
                            "      Allowed ops: R{} W{} D{} RN{} C{}",
                            !intent.operations.read as u8, // Show READ from intent
                            !blocked_ops.write as u8, // Inverse for display
                            !blocked_ops.delete as u8,
                            !blocked_ops.rename as u8,
                            !blocked_ops.create as u8
                        );
                    }
                    ProtectionAction::Audit => {
                        println!(
                            "      Audit ops: W{} D{} RN{} C{}",
                            // ✅ REMOVED: audit_ops.read as u8,
                            audit_ops.write as u8,
                            audit_ops.delete as u8,
                            audit_ops.rename as u8,
                            audit_ops.create as u8
                        );
                    }
                }

                policy
            })
            .collect()
    }

    /// Validate kernel policy before sending to kernel
    pub fn validate(policy: &KernelPolicy) -> Result<(), String> {
        // Validate NT path format
        if !policy.nt_path.starts_with("\\Device\\") {
            return Err(format!("Invalid NT path format: {}", policy.nt_path));
        }

        // Validate path ending for prefix matches
        if policy.match_type == PathMatchType::Prefix && !policy.nt_path.ends_with('\\') {
            return Err("Prefix match paths must end with backslash".to_string());
        }

        // Validate that we're not blocking everything (which would be useless)
        if !policy.block_all && policy.blocked_ops.is_empty() {
            return Err("Kernel policy must block or audit at least one operation".to_string());
        }

        Ok(())
    }
}

impl KernelPolicy {
    /// Check if operation should be blocked
    pub fn should_block_operation(&self, operation: &str) -> bool {
        if self.block_all {
            return true;
        }

        match operation {
            "read" => false,
            "write" => self.blocked_ops.write,
            "delete" => self.blocked_ops.delete,
            "rename" => self.blocked_ops.rename,
            "create" => self.blocked_ops.create,
            _ => false,
        }
    }

    // Get a description of what this kernel policy does
    // pub fn describe(&self) -> String {
    //     if self.is_block_all() {
    //         format!("BLOCK ALL operations on {} (Policy ID: {})",
    //             self.nt_path, self.policy_id)
    //     } else {
    //         let blocked_ops: Vec<&str> = {
    //             let mut ops = Vec::new();
    //             if self.blocked_ops.write { ops.push("write"); }
    //             if self.blocked_ops.delete { ops.push("delete"); }
    //             if self.blocked_ops.rename { ops.push("rename"); }
    //             if self.blocked_ops.create { ops.push("create"); }
    //             ops
    //         };

    //         let audit_ops: Vec<&str> = {
    //             let mut ops = Vec::new();
    //             // ✅ REMOVED: read auditing for now
    //             if self.audit_ops.write { ops.push("write"); }
    //             if self.audit_ops.delete { ops.push("delete"); }
    //             if self.audit_ops.rename { ops.push("rename"); }
    //             if self.audit_ops.create { ops.push("create"); }
    //             ops
    //         };

    //         let mut description = format!("Policy ID {} on {}: ", self.policy_id, self.nt_path);

    //         if !blocked_ops.is_empty() {
    //             description.push_str(&format!("Block [{}]", blocked_ops.join(", ")));
    //         }

    //         if !audit_ops.is_empty() {
    //             if !blocked_ops.is_empty() {
    //                 description.push_str(", ");
    //             }
    //             description.push_str(&format!("Audit [{}]", audit_ops.join(", ")));
    //         }

    //         if self.is_recursive {
    //             description.push_str(" (Recursive)");
    //         }

    //         description
    //     }
    // }
}
