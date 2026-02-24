// src/fs_index.rs (fixed)
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;

/// Filesystem entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryType {
    VirtualRoot,  // "This PC"
    Drive,
    Directory,
    File,
}

/// Filesystem node with lazy loading support
#[derive(Debug, Clone)]
pub struct FileSystemNode {
    pub id: u64,
    pub name: String,
    pub entry_type: EntryType,
    pub parent_id: Option<u64>,
    pub children_ids: Vec<u64>,
    pub nt_path: String,          // INTERNAL ONLY
    pub display_path: String,     // For debugging/admin display
    pub size: Option<u64>,
    pub modified_time: u64,
    pub created_time: u64,
    pub attributes: u32,
    pub is_expanded: bool,        // Has children been loaded?
    pub is_accessible: bool,      // Can we access this path?
}

/// Main filesystem index with lazy loading
pub struct FilesystemIndex {
    nodes: RwLock<HashMap<u64, FileSystemNode>>,
    path_to_id: RwLock<HashMap<String, u64>>,  // Display path → ID cache
    id_to_path: RwLock<HashMap<u64, String>>,  // ID → Display path cache
    next_id: RwLock<u64>,
}

impl FilesystemIndex {
    /// Create new empty index with virtual root
    pub fn new() -> Self {  // Changed from Arc<Self> to Self
        let index = FilesystemIndex {
            nodes: RwLock::new(HashMap::new()),
            path_to_id: RwLock::new(HashMap::new()),
            id_to_path: RwLock::new(HashMap::new()),
            next_id: RwLock::new(2),  // Start from 2 (1 is root)
        };
        
        // Create virtual root
        index.add_virtual_root();
        index
    }
    
    /// Create new index wrapped in Arc
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }
    
    /// Add virtual root "This PC"
    fn add_virtual_root(&self) {
        let root_node = FileSystemNode {
            id: 1,
            name: "This PC".to_string(),
            entry_type: EntryType::VirtualRoot,
            parent_id: None,
            children_ids: Vec::new(),
            nt_path: String::new(),
            display_path: "This PC".to_string(),
            size: None,
            modified_time: 0,
            created_time: 0,
            attributes: 0,
            is_expanded: false,
            is_accessible: true,
        };
        
        let mut nodes = self.nodes.write();
        nodes.insert(1, root_node);
    }
    
    /// Add a new node with proper parent-child linking
    pub fn add_node(&self, node: FileSystemNode) -> u64 {
        let id = node.id;
        let display_path = node.display_path.clone();
        
        // Update parent's children list
        if let Some(parent_id) = node.parent_id {
            let mut nodes = self.nodes.write();
            if let Some(parent) = nodes.get_mut(&parent_id) {
                if !parent.children_ids.contains(&id) {
                    parent.children_ids.push(id);
                }
            }
        }
        
        // Store the node
        {
            let mut nodes = self.nodes.write();
            nodes.insert(id, node);
        }
        
        // Update path caches
        {
            let mut path_to_id = self.path_to_id.write();
            path_to_id.insert(display_path.clone(), id);
            
            let mut id_to_path = self.id_to_path.write();
            id_to_path.insert(id, display_path);
        }
        
        id
    }

    /// Count expanded nodes
    pub fn count_expanded_nodes(&self) -> usize {
        let nodes = self.nodes.read();
        nodes.values()
            .filter(|node| node.is_expanded)
            .count()
    }

    /// Get next available ID
    pub fn get_next_id(&self) -> u64 {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id += 1;
        id
    }
    
    /// Get node by ID (safe for Admin)
    pub fn get_node(&self, id: u64) -> Option<FileSystemNode> {
        let nodes = self.nodes.read();
        nodes.get(&id).cloned()
    }
    
    /// Get node by display path (internal use)
    pub fn get_node_by_path(&self, display_path: &str) -> Option<FileSystemNode> {
        let path_to_id = self.path_to_id.read();
        path_to_id.get(display_path)
            .and_then(|&id| self.get_node(id))
    }
    
    /// Get node ID by path
    pub fn get_id_by_path(&self, display_path: &str) -> Option<u64> {
        let path_to_id = self.path_to_id.read();
        path_to_id.get(display_path).copied()
    }
    
    /// Get children of a node (already loaded children only)
    pub fn get_children(&self, parent_id: u64) -> Vec<FileSystemNode> {
        let nodes = self.nodes.read();
        
        if let Some(parent) = nodes.get(&parent_id) {
            parent.children_ids.iter()
                .filter_map(|id| nodes.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Check if node is expanded (children loaded)
    pub fn is_expanded(&self, node_id: u64) -> bool {
        let nodes = self.nodes.read();
        nodes.get(&node_id)
            .map(|node| node.is_expanded)
            .unwrap_or(false)
    }
    
    /// Mark node as expanded
    pub fn mark_expanded(&self, node_id: u64) {
        let mut nodes = self.nodes.write();
        if let Some(node) = nodes.get_mut(&node_id) {
            node.is_expanded = true;
        }
    }
    
    /// Mark node as not expanded (children removed)
    pub fn mark_collapsed(&self, node_id: u64) {
        let mut nodes = self.nodes.write();
        if let Some(node) = nodes.get_mut(&node_id) {
            node.is_expanded = false;
            node.children_ids.clear();
        }
    }
    
    /// Add a drive to the index (lazy - no scanning yet)
    pub fn add_drive(&self, drive_letter: &str, display_name: &str, nt_path: &str) -> u64 {
        let id = self.get_next_id();
        let display_path = format!("{}\\", drive_letter);
        
        let drive_node = FileSystemNode {
            id,
            name: display_name.to_string(),
            entry_type: EntryType::Drive,
            parent_id: Some(1),  // Child of "This PC"
            children_ids: Vec::new(),
            nt_path: nt_path.to_string(),
            display_path,
            size: None,
            modified_time: 0,
            created_time: 0,
            attributes: 0,
            is_expanded: false,
            is_accessible: true,
        };
        
        self.add_node(drive_node)
    }
    
    /// Get all drives
    pub fn get_drives(&self) -> Vec<(String, u64)> {
        let nodes = self.nodes.read();
        let root = match nodes.get(&1) {
            Some(root) => root,
            None => return Vec::new(),
        };
        
        root.children_ids.iter()
            .filter_map(|&id| {
                nodes.get(&id).and_then(|node| {
                    if node.entry_type == EntryType::Drive {
                        let drive_letter = node.display_path
                            .trim_end_matches('\\')
                            .to_string();
                        Some((drive_letter, id))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
    
    /// Get node count
    pub fn node_count(&self) -> usize {
        let nodes = self.nodes.read();
        nodes.len()
    }
    
    /// Clear all nodes except root
    pub fn clear(&self) {
        let mut nodes = self.nodes.write();
        let mut path_to_id = self.path_to_id.write();
        let mut id_to_path = self.id_to_path.write();
        
        // Keep only the root node (ID 1)
        let root_node = nodes.remove(&1);
        nodes.clear();
        path_to_id.clear();
        id_to_path.clear();
        
        if let Some(root) = root_node {
            nodes.insert(1, root);
        }
        
        // Reset ID counter
        *self.next_id.write() = 2;
    }
    
    /// Resolve ID to NT path (INTERNAL - for kernel use only)
    pub fn resolve_nt_path(&self, id: u64) -> Option<String> {
        let nodes = self.nodes.read();
        nodes.get(&id).map(|node| node.nt_path.clone())
    }
    
    /// Get display path for ID
    pub fn get_display_path(&self, id: u64) -> Option<String> {
        let id_to_path = self.id_to_path.read();
        id_to_path.get(&id).cloned()
    }
}

// Helper implementations for the index
impl FilesystemIndex {
    /// Convert EntryType to string for UI
    pub fn entry_type_to_string(&self, entry_type: EntryType) -> &'static str {
        match entry_type {
            EntryType::VirtualRoot => "virtual_root",
            EntryType::Drive => "drive",
            EntryType::Directory => "directory",
            EntryType::File => "file",
        }
    }
    
    /// Get all nodes (for debugging)
    pub fn get_all_nodes(&self) -> Vec<FileSystemNode> {
        let nodes = self.nodes.read();
        nodes.values().cloned().collect()
    }
    
    /// Search for nodes by name within expanded nodes only
    pub fn search_local(&self, parent_id: u64, query: &str) -> Vec<FileSystemNode> {
        let nodes = self.nodes.read();
        let parent = match nodes.get(&parent_id) {
            Some(parent) => parent,
            None => return Vec::new(),
        };
        
        // Only search in expanded children
        parent.children_ids.iter()
            .filter_map(|&child_id| {
                nodes.get(&child_id).and_then(|child| {
                    if child.name.to_lowercase().contains(&query.to_lowercase()) {
                        Some(child.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}