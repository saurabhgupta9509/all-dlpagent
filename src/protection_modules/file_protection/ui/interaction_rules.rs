//! Explorer Interaction Rules (STEP 3.2)
//! Core Principle: Define how clicks behave, enforce STEP 2 API usage
// src/ui/intreaction_rules.rs
use crate::protection_modules::file_protection::{comms::{AdminRequest, AgentResponse, QueryApiServer}, ui::{ExplorerState, PendingProtection, SelectionInfo}};
use std::sync::Arc;

/// Interaction Rules Engine
pub struct InteractionEngine {
    api_server: Arc<QueryApiServer>,
    ui_state: Arc<ExplorerState>,
}

impl InteractionEngine {
    /// Create new interaction engine
    pub fn new(api_server: Arc<QueryApiServer>, ui_state: Arc<ExplorerState>) -> Self {
        InteractionEngine { api_server, ui_state }
    }
    
    /// ========================================
    /// Single Click Interaction (STEP 3.2)
    /// ========================================
    
    /// Handle single click on a folder
    /// Rule: Selects the folder, does NOT expand
    pub async fn handle_folder_click(&self, node_id: u64, node_name: &str, is_accessible: bool, has_children: bool) {
        println!("🖱️ UI: Folder clicked - ID: {}, Name: '{}'", node_id, node_name);
        
        let selection = SelectionInfo {
            node_id,
            node_type: "folder".to_string(),
            name: node_name.to_string(),
            is_accessible,
            has_children,
        };
        
        self.ui_state.select_node(selection);
        self.ui_state.clear_error();
        
        println!("   → Selected (not expanded)");
    }
    
    /// Handle single click on a file
    /// Rule: Selects file, shows metadata panel
    pub async fn handle_file_click(&self, node_id: u64, node_name: &str, is_accessible: bool) {
        println!("🖱️ UI: File clicked - ID: {}, Name: '{}'", node_id, node_name);
        
        let selection = SelectionInfo {
            node_id,
            node_type: "file".to_string(),
            name: node_name.to_string(),
            is_accessible,
            has_children: false,
        };
        
        self.ui_state.select_node(selection);
        self.ui_state.clear_error();
        
        println!("   → Selected (showing metadata)");
    }
    
    /// Handle single click on a drive
    /// Rule: Selects drive, does NOT expand
    pub async fn handle_drive_click(&self, node_id: u64, drive_name: &str, drive_letter: &str, has_children: bool) {
        println!("🖱️ UI: Drive clicked - ID: {}, {} ({})", node_id, drive_name, drive_letter);
        
        let selection = SelectionInfo {
            node_id,
            node_type: "drive".to_string(),
            name: format!("{} ({})", drive_name, drive_letter),
            is_accessible: true,
            has_children,
        };
        
        self.ui_state.select_node(selection);
        self.ui_state.clear_error();
        
        println!("   → Selected (not expanded)");
    }
    
    /// ========================================
    /// Expand/Collapse Interactions (STEP 3.2)
    /// ========================================
    
    /// Handle expand arrow click on folder/drive
    /// Rule: UI shows spinner, calls ExpandNode API, waits for response
    pub async fn handle_expand_click(&self, node_id: u64, node_name: &str) -> Result<(), String> {
        println!("📂 UI: Expand clicked - ID: {}, Name: '{}'", node_id, node_name);
        
        // Check if already expanded
        if self.ui_state.is_expanded(node_id) {
            println!("   ⚠️ Already expanded, ignoring");
            return Ok(());
        }
        
        // Check if already expanding
        if self.ui_state.is_expanding(node_id) {
            println!("   ⚠️ Already expanding, ignoring");
            return Ok(());
        }
        
        // Mark as expanding (show spinner)
        self.ui_state.mark_expanding(node_id);
        self.ui_state.clear_error();
        
        println!("   → Sending ExpandNode request to Agent...");
        
        // Call STEP 2 API (async)
        match self.api_server.handle_request(AdminRequest::ExpandNode { node_id }).await {
            AgentResponse::Expanded { node_id: expanded_id, node_name, children, total_children } => {
                println!("   ✅ Agent: Expanded '{}' (ID: {})", node_name, expanded_id);
                println!("      • Children loaded: {}", children.len());
                println!("      • Total children: {}", total_children);
                
                // Mark as expanded
                self.ui_state.mark_expanded(node_id);
                Ok(())
            }
            
            AgentResponse::Error { code, message, details } => {
                println!("   ❌ Agent: Expansion failed - {}: {}", code, message);
                
                // Mark as collapsed (failed)
                self.ui_state.mark_collapsed(node_id);
                self.ui_state.set_error(Some(format!("{}: {}", code, message)));
                
                Err(format!("{}: {}", code, message))
            }
            
            _ => {
                println!("   ❌ UI: Unexpected response from Agent");
                self.ui_state.mark_collapsed(node_id);
                self.ui_state.set_error(Some("Unexpected response".to_string()));
                Err("Unexpected response".to_string())
            }
        }
    }
    
    /// Handle collapse arrow click
    /// Rule: UI removes children from view, calls CollapseNode API
    pub async fn handle_collapse_click(&self, node_id: u64, node_name: &str) -> Result<(), String> {
        println!("📁 UI: Collapse clicked - ID: {}, Name: '{}'", node_id, node_name);
        
        // Check if already collapsed
        if !self.ui_state.is_expanded(node_id) {
            println!("   ⚠️ Already collapsed, ignoring");
            return Ok(());
        }
        
        println!("   → Sending CollapseNode request to Agent...");
        
        // Call STEP 2 API (async)
        match self.api_server.handle_request(AdminRequest::CollapseNode { node_id }).await {
            AgentResponse::Collapsed { node_id: collapsed_id, node_name, removed_children } => {
                println!("   ✅ Agent: Collapsed '{}' (ID: {})", node_name, collapsed_id);
                println!("      • Removed children: {}", removed_children);
                
                // Mark as collapsed
                self.ui_state.mark_collapsed(node_id);
                Ok(())
            }
            
            AgentResponse::Error { code, message, details } => {
                println!("   ❌ Agent: Collapse failed - {}: {}", code, message);
                self.ui_state.set_error(Some(format!("{}: {}", code, message)));
                Err(format!("{}: {}", code, message))
            }
            
            _ => {
                println!("   ❌ UI: Unexpected response from Agent");
                self.ui_state.set_error(Some("Unexpected response".to_string()));
                Err("Unexpected response".to_string())
            }
        }
    }
    
    /// ========================================
    /// Search Interaction (STEP 3.2)
    /// ========================================
    
    /// Handle search box input
    /// Rule: Search is LOCAL ONLY within expanded folders
    pub async fn handle_search(&self, parent_id: u64, query: &str, limit: Option<usize>) -> Result<Vec<u64>, String> {
        println!("🔍 UI: Searching within expanded nodes - Parent ID: {}, Query: '{}'", parent_id, query);
        
        if query.trim().is_empty() {
            println!("   ⚠️ Empty query, clearing search");
            self.ui_state.set_search_query(None);
            return Ok(vec![]);
        }
        
        // Show search scope warning
        println!("   ℹ️  Searching LOCAL ONLY (expanded nodes)");
        println!("   ℹ️  To search globally, expand more folders first");
        
        self.ui_state.set_search_query(Some(query.to_string()));
        self.ui_state.clear_error();
        
        // Call STEP 2 API (async)
        match self.api_server.handle_request(
            AdminRequest::SearchLocal { parent_id, query: query.to_string(), limit }
        ).await {
            AgentResponse::SearchLocalResults { parent_id, query, results, total_matches, scope } => {
                println!("   ✅ Agent: Found {} matches (Scope: {})", total_matches, scope);
                
                let result_ids: Vec<u64> = results.iter().map(|node| node.id).collect();
                Ok(result_ids)
            }
            
            AgentResponse::Error { code, message, details } => {
                println!("   ❌ Agent: Search failed - {}: {}", code, message);
                self.ui_state.set_error(Some(format!("{}: {}", code, message)));
                Err(format!("{}: {}", code, message))
            }
            
            _ => {
                println!("   ❌ UI: Unexpected response from Agent");
                self.ui_state.set_error(Some("Unexpected response".to_string()));
                Err("Unexpected response".to_string())
            }
        }
    }
    
    /// Clear search
    pub fn clear_search(&self) {
        println!("🗑️ UI: Clearing search");
        self.ui_state.set_search_query(None);
    }
    
    /// ========================================
    /// Protection Flow (STEP 3.3)
    /// ========================================
    
    /// Handle "Mark for Protection" button click
    /// Rule: Stores selection for STEP 4, NO kernel calls
    pub async fn handle_mark_for_protection(
        &self,
        node_id: u64,
        node_type: &str,
        node_name: &str,
        size: Option<u64>,
        modified_time: u64,
    ) -> Result<(), String> {
        println!("🛡️ UI: Mark for Protection clicked - ID: {}, Name: '{}'", node_id, node_name);
        
        // Check if node is accessible
        if let Some(selection) = self.ui_state.get_selection() {
            if !selection.is_accessible {
                let error = "Cannot protect inaccessible node".to_string();
                println!("   ❌ {}", error);
                self.ui_state.set_error(Some(error.clone()));
                return Err(error);
            }
        }
        
        // Create pending protection
        let protection = PendingProtection {
            node_id,
            node_type: node_type.to_string(),
            name: node_name.to_string(),
            size,
            modified_time,
        };
        
        // Store for STEP 4
        self.ui_state.set_pending_protection(protection);
        
        // Show confirmation message
        println!("   ✅ Marked for protection (STEP 4 will handle)");
        println!("   ⚠️  IMPORTANT: No kernel calls yet");
        println!("   ⚠️  NT paths not resolved yet");
        
        Ok(())
    }
    
    /// Handle "Clear Protection" button click
    pub fn handle_clear_protection(&self) {
        println!("🗑️ UI: Clearing pending protection");
        self.ui_state.clear_pending_protection();
    }
    
    /// ========================================
    /// Utility Methods
    /// ========================================
    
    /// Get the API server reference
    pub fn api_server(&self) -> &Arc<QueryApiServer> {
        &self.api_server
    }
    
    /// Get the UI state reference
    pub fn ui_state(&self) -> &Arc<ExplorerState> {
        &self.ui_state
    }
    
    /// Reset all interactions
    pub fn reset(&self) {
        println!("🔄 UI: Resetting all interactions");
        self.ui_state.reset();
    }
}