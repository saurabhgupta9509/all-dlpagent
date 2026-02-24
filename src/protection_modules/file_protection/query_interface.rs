//! Query Interface - Safe, read-only API for Admin Server
//! Core Principle: Admin only sees IDs, never NT paths
// src/query_interface.rs
use super::fs_index::{FilesystemIndex, FileSystemNode, EntryType};
use std::sync::Arc;

/// Safe node information for Admin (no NT paths!)
#[derive(Debug, Clone)]
pub struct SafeNodeInfo {
    pub id: u64,
    pub name: String,
    pub entry_type: String,
    pub size: Option<u64>,
    pub modified_time: u64,
    pub created_time: u64,
    pub has_children: bool,
    pub is_expanded: bool,
    pub is_accessible: bool,
    pub display_path: String,
}

/// Drive information for Admin
#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub drive_letter: String,
    pub display_name: String,
    pub node_id: u64,
}

/// System statistics - proper struct, not string parsing
#[derive(Debug, Clone)]
pub struct SystemStats {
    pub total_nodes: usize,
    pub total_drives: usize,
    pub expanded_nodes: usize,
    pub memory_usage_bytes: usize,
    pub scan_state: ScanState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Expanding,
    Ready,
    Error(String),
}

impl ScanState {
    pub fn as_str(&self) -> &str {
        match self {
            ScanState::Idle => "idle",
            ScanState::Expanding => "expanding",
            ScanState::Ready => "ready",
            ScanState::Error(_) => "error",
        }
    }
}

/// Query response (simple enum)
#[derive(Debug)]
pub enum QueryResponse {
    Drives(Vec<DriveInfo>),
    Nodes(Vec<SafeNodeInfo>),
    Node(SafeNodeInfo),
    Stats(SystemStats),
    Error(String),
}

/// Main query interface
pub struct QueryInterface {
    index: Arc<FilesystemIndex>,
}

impl QueryInterface {
    /// Create new query interface
    pub fn new(index: Arc<FilesystemIndex>) -> Self {
        QueryInterface { index }
    }
    
    /// Get all drives
    pub fn get_drives(&self) -> QueryResponse {
        let drives = self.index.get_drives();
        let mut drive_infos = Vec::new();
        
        for (drive_letter, node_id) in drives {
            if let Some(node) = self.index.get_node(node_id) {
                drive_infos.push(DriveInfo {
                    drive_letter,
                    display_name: node.name,
                    node_id,
                });
            }
        }
        
        QueryResponse::Drives(drive_infos)
    }
    
    /// Get children of a node (LOCAL ONLY - only expanded children)
    pub fn list_children(&self, parent_id: u64) -> QueryResponse {
        if self.index.get_node(parent_id).is_none() {
            return QueryResponse::Error(format!("Parent node {} not found", parent_id));
        }
        
        let children = self.index.get_children(parent_id);
        let safe_children: Vec<SafeNodeInfo> = children
            .into_iter()
            .map(|node| self.convert_to_safe_info(&node))
            .collect();
        
        QueryResponse::Nodes(safe_children)
    }
    
    /// Get specific node
    pub fn get_node(&self, node_id: u64) -> QueryResponse {
        match self.index.get_node(node_id) {
            Some(node) => QueryResponse::Node(self.convert_to_safe_info(&node)),
            None => QueryResponse::Error(format!("Node {} not found", node_id)),
        }
    }
    
    /// Search within expanded nodes only (LOCAL SEARCH)
    /// ⚠️ IMPORTANT: This only searches already-loaded children, not the entire filesystem
    pub fn search_local(&self, parent_id: u64, query: &str) -> QueryResponse {
        if query.trim().is_empty() {
            return QueryResponse::Error("Empty search query".to_string());
        }
        
        // Get LOCAL children only (already expanded)
        let children = match self.list_children(parent_id) {
            QueryResponse::Nodes(nodes) => nodes,
            _ => return QueryResponse::Error("Could not list children".to_string()),
        };
        
        let query_lower = query.to_lowercase();
        let matches: Vec<SafeNodeInfo> = children
            .into_iter()
            .filter(|node| node.name.to_lowercase().contains(&query_lower))
            .collect();
        
        QueryResponse::Nodes(matches)
    }
    
    /// Resolve ID to NT path (INTERNAL USE ONLY)
    pub fn resolve_nt_path_internal(&self, node_id: u64) -> Result<String, String> {
        self.index.resolve_nt_path(node_id)
            .ok_or_else(|| format!("NT path not found for node {}", node_id))
    }
    
    /// Get system statistics
    pub fn get_stats(&self) -> QueryResponse {
        let total_nodes = self.index.node_count();
        let drives = self.index.get_drives();
        
        // Count expanded nodes
        let expanded_nodes = self.index.count_expanded_nodes();
        
        let stats = SystemStats {
            total_nodes,
            total_drives: drives.len(),
            expanded_nodes,
            memory_usage_bytes: 0, // Will be implemented later
            scan_state: ScanState::Idle,
        };
        
        QueryResponse::Stats(stats)
    }
    
    /// Get display path for debugging
    pub fn get_display_path(&self, node_id: u64) -> Result<String, String> {
        self.index.get_display_path(node_id)
            .ok_or_else(|| format!("Display path not found for node {}", node_id))
    }
    
    /// Convert internal node to safe info
    fn convert_to_safe_info(&self, node: &FileSystemNode) -> SafeNodeInfo {
        let has_children = !node.children_ids.is_empty() || 
            (node.entry_type == EntryType::Directory || 
             node.entry_type == EntryType::Drive);
        
        let entry_type_str = match node.entry_type {
            EntryType::VirtualRoot => "VirtualRoot",
            EntryType::Drive => "Drive",
            EntryType::Directory => "Directory",
            EntryType::File => "File",
        }.to_string();
        
        SafeNodeInfo {
            id: node.id,
            name: node.name.clone(),
            entry_type: entry_type_str,
            size: node.size,
            modified_time: node.modified_time,
            created_time: node.created_time,
            has_children,
            is_expanded: node.is_expanded,
            is_accessible: node.is_accessible,
            display_path: node.display_path.clone(),
        }
    }
}