//! Explorer UI State Model (STEP 3.1)
//! Core Principle: UI remembers expand/collapse/selection states, Agent owns filesystem truth
// src/ui/explorer_state.rs
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// UI state for a single node
#[derive(Debug, Clone, PartialEq)]
pub enum NodeUIState {
    Collapsed,     // Not expanded
    Expanding,     // Loading children (spinner visible)
    Expanded,      // Children loaded and visible
}

/// Selection information
#[derive(Debug, Clone)]
pub struct SelectionInfo {
    pub node_id: u64,
    pub node_type: String,     // "file", "folder", "drive"
    pub name: String,
    pub is_accessible: bool,
    pub has_children: bool,
}

/// Pending protection request (for STEP 4)
#[derive(Debug, Clone)]
pub struct PendingProtection {
    pub node_id: u64,
    pub node_type: String,
    pub name: String,
    pub size: Option<u64>,
    pub modified_time: u64,
}

/// Main Explorer UI State
#[derive(Debug)]
pub struct ExplorerState {
    /// Node ID -> UI State
    node_states: RwLock<HashMap<u64, NodeUIState>>,
    
    /// Current selection
    selection: RwLock<Option<SelectionInfo>>,
    
    /// Pending protection (STEP 4 preparation)
    pending_protection: RwLock<Option<PendingProtection>>,
    
    /// Search query (if any)
    current_search: RwLock<Option<String>>,
    
    /// Is UI in loading state?
    is_loading: RwLock<bool>,
    
    /// Last error message (if any)
    last_error: RwLock<Option<String>>,
}

impl ExplorerState {
    /// Create new empty explorer state
    pub fn new() -> Arc<Self> {
        Arc::new(ExplorerState {
            node_states: RwLock::new(HashMap::new()),
            selection: RwLock::new(None),
            pending_protection: RwLock::new(None),
            current_search: RwLock::new(None),
            is_loading: RwLock::new(false),
            last_error: RwLock::new(None),
        })
    }
    
    /// ========================================
    /// Tree State Management (STEP 3.1)
    /// ========================================
    
    /// Get UI state for a node
    pub fn get_node_state(&self, node_id: u64) -> NodeUIState {
        let node_states = self.node_states.read();
        node_states.get(&node_id)
            .cloned()
            .unwrap_or(NodeUIState::Collapsed)
    }
    
    /// Mark node as expanding (show spinner)
    pub fn mark_expanding(&self, node_id: u64) {
        let mut node_states = self.node_states.write();
        node_states.insert(node_id, NodeUIState::Expanding);
        *self.is_loading.write() = true;
        *self.last_error.write() = None;
    }
    
    /// Mark node as expanded (children loaded)
    pub fn mark_expanded(&self, node_id: u64) {
        let mut node_states = self.node_states.write();
        node_states.insert(node_id, NodeUIState::Expanded);
        *self.is_loading.write() = false;
    }
    
   /// Mark node as collapsed
    pub fn mark_collapsed(&self, node_id: u64) {
        let mut node_states = self.node_states.write();
        node_states.insert(node_id, NodeUIState::Collapsed);
        *self.last_error.write() = None;
    }
    
    /// Check if node is expanded
    pub fn is_expanded(&self, node_id: u64) -> bool {
        self.get_node_state(node_id) == NodeUIState::Expanded
    }
    
    /// Check if node is expanding (loading)
    pub fn is_expanding(&self, node_id: u64) -> bool {
        self.get_node_state(node_id) == NodeUIState::Expanding
    }
    
    /// ========================================
    /// Selection State Management (STEP 3.1)
    /// ========================================
    
    /// Get current selection
    pub fn get_selection(&self) -> Option<SelectionInfo> {
        self.selection.read().clone()
    }
    
    /// Select a node
    pub fn select_node(&self, selection: SelectionInfo) {
        *self.selection.write() = Some(selection);
        *self.last_error.write() = None;
    }
    
    /// Clear selection
    pub fn clear_selection(&self) {
        *self.selection.write() = None;
    }
    
    /// Check if a node is selected
    pub fn is_selected(&self, node_id: u64) -> bool {
        self.selection.read()
            .as_ref()
            .map(|s| s.node_id == node_id)
            .unwrap_or(false)
    }
    
    /// ========================================
    /// Pending Protection (STEP 3.3)
    /// ========================================
    
    /// Get pending protection
    pub fn get_pending_protection(&self) -> Option<PendingProtection> {
        self.pending_protection.read().clone()
    }
    
    /// Set pending protection (Mark for Protection button clicked)
    pub fn set_pending_protection(&self, protection: PendingProtection) {
        // Store the fields before moving protection
        let node_id = protection.node_id;
        let name = protection.name.clone();
        let node_type = protection.node_type.clone();
        
        // Now move protection
        *self.pending_protection.write() = Some(protection);
        
        // Use the stored fields
        println!("✅ UI: Node marked for protection (STEP 4 will handle)");
        println!("   ID: {}, Name: {}, Type: {}", node_id, name, node_type);
    }
    
    /// Clear pending protection
    pub fn clear_pending_protection(&self) {
        *self.pending_protection.write() = None;
    }
    
    /// ========================================
    /// Search State
    /// ========================================
    
    /// Set current search query
    pub fn set_search_query(&self, query: Option<String>) {
        *self.current_search.write() = query;
    }
    
    /// Get current search query
    pub fn get_search_query(&self) -> Option<String> {
        self.current_search.read().clone()
    }
    
    /// ========================================
    /// Loading & Error States
    /// ========================================
    
    /// Check if UI is loading
    pub fn is_loading(&self) -> bool {
        *self.is_loading.read()
    }
    
    /// Set loading state
    pub fn set_loading(&self, loading: bool) {
        *self.is_loading.write() = loading;
    }
    
    /// Set error message
    pub fn set_error(&self, error: Option<String>) {
        *self.last_error.write() = error;
    }
    
    /// Get last error
    pub fn get_error(&self) -> Option<String> {
        self.last_error.read().clone()
    }
    
    /// Clear error
    pub fn clear_error(&self) {
        *self.last_error.write() = None;
    }
    
    /// ========================================
    /// Utility Methods
    /// ========================================
    
    /// Reset all UI state
    pub fn reset(&self) {
        *self.node_states.write() = HashMap::new();
        *self.selection.write() = None;
        *self.pending_protection.write() = None;
        *self.current_search.write() = None;
        *self.is_loading.write() = false;
        *self.last_error.write() = None;
    }
    
    /// Get statistics about UI state
    pub fn get_stats(&self) -> ExplorerStats {
        let node_states = self.node_states.read();
        
        ExplorerStats {
            total_tracked_nodes: node_states.len(),
            expanded_nodes: node_states.values()
                .filter(|&state| *state == NodeUIState::Expanded)
                .count(),
            expanding_nodes: node_states.values()
                .filter(|&state| *state == NodeUIState::Expanding)
                .count(),
            has_selection: self.selection.read().is_some(),
            has_pending_protection: self.pending_protection.read().is_some(),
            has_search: self.current_search.read().is_some(),
        }
    }
}

/// UI statistics
#[derive(Debug, Clone)]
pub struct ExplorerStats {
    pub total_tracked_nodes: usize,
    pub expanded_nodes: usize,
    pub expanding_nodes: usize,
    pub has_selection: bool,
    pub has_pending_protection: bool,
    pub has_search: bool,
}