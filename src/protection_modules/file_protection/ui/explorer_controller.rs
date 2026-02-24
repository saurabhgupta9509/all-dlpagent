//! Explorer Controller (STEP 3)
//! Core Principle: Coordinate UI state, interactions, and API calls
// src/ui/explorer_controller.rs
use crate::protection_modules::file_protection::comms::{AdminRequest, AgentResponse, QueryApiServer};
use super::explorer_state::{ExplorerState, SelectionInfo};
use super::interaction_rules::InteractionEngine;
use std::sync::Arc;

/// Main Explorer Controller
pub struct ExplorerController {
    interaction_engine: Arc<InteractionEngine>,
}

impl ExplorerController {
    /// Create new explorer controller
    pub fn new(api_server: Arc<QueryApiServer>) -> Arc<Self> {
        let ui_state = ExplorerState::new();
        let interaction_engine = InteractionEngine::new(api_server.clone(), ui_state.clone());
        
        Arc::new(ExplorerController {
            interaction_engine: Arc::new(interaction_engine),
        })
    }
    
    /// ========================================
    /// Initialization
    /// ========================================
    
    /// Initialize explorer by loading drives
    pub async fn initialize(&self) -> Result<Vec<u64>, String> {
        println!("🚀 UI: Initializing Explorer...");
        
        // Load drives from Agent (async)
        match self.interaction_engine.api_server().handle_request(AdminRequest::GetDrives).await {
            AgentResponse::Drives { drives } => {
                println!("✅ UI: Loaded {} drives", drives.len());
                
                let drive_ids: Vec<u64> = drives.iter().map(|drive| drive.id).collect();
                
                for drive in drives {
                    println!("   • {} (ID: {})", drive.name, drive.id);
                }
                
                Ok(drive_ids)
            }
            
            AgentResponse::Error { code, message, details } => {
                let error = format!("Failed to load drives: {}: {}", code, message);
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
            
            _ => {
                let error = "Unexpected response when loading drives".to_string();
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
        }
    }
    
    /// ========================================
    /// Public API for UI Components
    /// ========================================
    
    /// Get interaction engine
    pub fn interaction_engine(&self) -> &Arc<InteractionEngine> {
        &self.interaction_engine
    }
    
    /// Get UI state
    pub fn ui_state(&self) -> &Arc<ExplorerState> {
        self.interaction_engine.ui_state()
    }
    
    /// ========================================
    /// Tree Navigation
    /// ========================================
    
    /// Load children of a node (called when node is expanded)
    pub async fn load_children(&self, parent_id: u64) -> Result<Vec<SelectionInfo>, String> {
        println!("📂 UI: Loading children of node {}", parent_id);
        
        match self.interaction_engine.api_server().handle_request(AdminRequest::ListChildren { node_id: parent_id }).await {
            AgentResponse::Children { parent_id, parent_name, children, total_children } => {
                println!("✅ UI: Loaded {} children for '{}'", total_children, parent_name);
                
                let selection_infos: Vec<SelectionInfo> = children.into_iter().map(|node| {
                    SelectionInfo {
                        node_id: node.id,
                        node_type: node.node_type,
                        name: node.name,
                        is_accessible: node.is_accessible,
                        has_children: node.has_children,
                    }
                }).collect();
                
                Ok(selection_infos)
            }
            
            AgentResponse::Error { code, message, details } => {
                let error = format!("Failed to load children: {}: {}", code, message);
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
            
            _ => {
                let error = "Unexpected response when loading children".to_string();
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
        }
    }
    
    /// Get node info for metadata panel
    pub async fn get_node_info(&self, node_id: u64) -> Result<SelectionInfo, String> {
        println!("📋 UI: Getting info for node {}", node_id);
        
        match self.interaction_engine.api_server().handle_request(AdminRequest::GetNode { node_id }).await {
            AgentResponse::Node { node } => {
                println!("✅ UI: Got info for '{}'", node.name);
                
                Ok(SelectionInfo {
                    node_id: node.id,
                    node_type: node.node_type,
                    name: node.name,
                    is_accessible: node.is_accessible,
                    has_children: node.has_children,
                })
            }
            
            AgentResponse::Error { code, message, details } => {
                let error = format!("Failed to get node info: {}: {}", code, message);
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
            
            _ => {
                let error = "Unexpected response when getting node info".to_string();
                println!("❌ UI: {}", error);
                self.interaction_engine.ui_state().set_error(Some(error.clone()));
                Err(error)
            }
        }
    }
    
    /// ========================================
    /// UI Lifecycle
    /// ========================================
    
    /// Show UI summary
    pub fn show_summary(&self) {
        println!("\n📊 UI EXPLORER SUMMARY:");
        println!("======================");
        
        let stats = self.ui_state().get_stats();
        println!("Tracked Nodes: {}", stats.total_tracked_nodes);
        println!("Expanded Nodes: {}", stats.expanded_nodes);
        println!("Expanding Nodes: {}", stats.expanding_nodes);
        println!("Has Selection: {}", stats.has_selection);
        println!("Has Pending Protection: {}", stats.has_pending_protection);
        println!("Has Search: {}", stats.has_search);
        
        if let Some(error) = self.ui_state().get_error() {
            println!("Last Error: {}", error);
        }
        
        if let Some(selection) = self.ui_state().get_selection() {
            println!("\nCurrent Selection:");
            println!("  ID: {}", selection.node_id);
            println!("  Name: {}", selection.name);
            println!("  Type: {}", selection.node_type);
            println!("  Accessible: {}", selection.is_accessible);
            println!("  Has Children: {}", selection.has_children);
        }
        
        if let Some(protection) = self.ui_state().get_pending_protection() {
            println!("\nPending Protection (for STEP 4):");
            println!("  ID: {}", protection.node_id);
            println!("  Name: {}", protection.name);
            println!("  Type: {}", protection.node_type);
            println!("  Size: {:?}", protection.size);
        }
        
        println!("======================\n");
    }
    
    /// Reset UI
    pub fn reset(&self) {
        println!("🔄 UI: Resetting explorer");
        self.interaction_engine.reset();
    }
}