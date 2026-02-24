//! Filesystem Scanner - Lazy directory expansion only
// src/filesystem_scanner.rs
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::protection_modules::file_protection::policy::PathResolver;

use super::fs_index::{FilesystemIndex, FileSystemNode, EntryType};
use super::path_normalizer::PathNormalizer;
use super::nt_path_resolver::NtPathResolver;
use std::sync::Arc;

/// Configuration for scanning
pub struct ScanConfig {
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    pub skip_system: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            follow_symlinks: false,
            skip_hidden: true,
            skip_system: true,
        }
    }
}

/// Main scanner with lazy loading
pub struct FileSystemScanner {
    index: Arc<FilesystemIndex>,
    path_resolver: Arc<PathResolver>,  // For DOS → NT path conversion
    config: ScanConfig,
}

impl FileSystemScanner {
    /// Create a new scanner
    pub fn new(index: Arc<FilesystemIndex>,path_resolver: Arc<PathResolver>) -> Self {
        FileSystemScanner {
            index,
            path_resolver,  
            config: ScanConfig::default(),
        }
    }
    
    /// Create with custom configuration
    pub fn with_config(index: Arc<FilesystemIndex>, path_resolver: Arc<PathResolver>, config: ScanConfig) -> Self {
        FileSystemScanner { index, path_resolver, config }
    }
    
    /// Initialize with drives only (NO full scan)
    pub fn initialize_drives(&self) -> Result<usize, String> {
        println!("🚀 Initializing drives (lazy loading)...");
        
        // Clear existing index (except root)
        self.index.clear();
        
        // Detect and add drives
        let mut drive_count = 0;
        
        for letter in b'A'..=b'Z' {
            let drive_letter = format!("{}:", letter as char);
            let drive_path = PathBuf::from(&drive_letter);
            
            if drive_path.exists() {
                match fs::metadata(&drive_path) {
                    Ok(_) => {
                        // PLACEHOLDER: Get NT path (would use QueryDosDevice in production)
                        let nt_path_result  = NtPathResolver::dos_to_nt_path(
                            &drive_letter, 
                            true
                        );
                        
                            // Handle the Result
                        let nt_path = match nt_path_result {
                            Ok(path) => path,
                            Err(e) => {
                                println!("⚠️ Failed to get NT path for {}: {}", drive_letter, e);
                                // Use a fallback or continue to next drive
                                continue;
                            }
                        };
                        
                        let display_name = if letter == b'C' {
                            "Local Disk (C:)".to_string()
                        } else {
                            format!("Local Disk ({})", drive_letter)
                        };
                        
                        self.index.add_drive(&drive_letter, &display_name, &nt_path);
                        drive_count += 1;
                        
                        println!("✅ Added drive: {} -> {}", drive_letter, display_name);
                    }
                    Err(e) => {
                        // Skip inaccessible drives silently
                        if e.kind() != std::io::ErrorKind::PermissionDenied {
                            println!("⚠️  Drive {}: {}", drive_letter, e);
                        }
                    }
                }
            }
        }
        
        if drive_count == 0 {
            Err("No accessible drives found".to_string())
        } else {
            println!("✅ Initialized {} drives (ready for lazy expansion)", drive_count);
            Ok(drive_count)
        }
    }
    

       /// Expand a drive (same logic as directory)
    pub fn expand_drive(&self, node_id: u64) -> Result<usize, String> {
        // Drives are expanded exactly like directories
        self.expand_directory(node_id)
    }

    pub fn collapse_drive(&self, node_id: u64) -> Result<usize, String> {
        self.collapse_directory(node_id)
    }
    
    /// Expand a directory (load its children)
    pub fn expand_directory(&self, node_id: u64) -> Result<usize, String> {
        let node = match self.index.get_node(node_id) {
            Some(node) => node,
            None => return Err(format!("Node {} not found", node_id)),
        };
        
        if node.entry_type != EntryType::Directory && node.entry_type != EntryType::Drive {
            return Err(format!("Node {} is not a directory", node_id));
        }
        
        if node.is_expanded {
            // Already expanded, just return count
            let children = self.index.get_children(node_id);
            return Ok(children.len());
        }
        
        println!("📁 Expanding: {} (ID: {})", node.display_path, node_id);
        
        // Convert NT path back to DOS path for scanning
        // This is simplified - in production you'd use the stored display_path
        let scan_path = if node.entry_type == EntryType::Drive {
            PathBuf::from(&node.display_path)
        } else {
            // For directories, we need to reconstruct the full path
            // This is a simplified approach
            PathBuf::from(&node.display_path)
        };
        
        if !scan_path.exists() {
            return Err(format!("Path does not exist: {}", scan_path.display()));
        }
        
        // Read directory contents
        let entries = match fs::read_dir(&scan_path) {
            Ok(entries) => entries,
            Err(e) => return Err(format!("Failed to read directory: {}", e)),
        };
        
        let mut child_count = 0;
        
        for entry in entries {
            match entry {
                Ok(dir_entry) => {
                    if let Ok(child_node) = self.create_child_node(&dir_entry, node_id) {
                        self.index.add_node(child_node);
                        child_count += 1;
                    }
                }
                Err(e) => {
                    // Skip inaccessible entries
                    if e.kind() != std::io::ErrorKind::PermissionDenied {
                        println!("⚠️  Skipping entry: {}", e);
                    }
                }
            }
        }
        
        // Mark as expanded
        self.index.mark_expanded(node_id);
        
        println!("✅ Expanded {} -> {} children", node.name, child_count);
        Ok(child_count)
    }
    
    /// Collapse a directory (remove loaded children)
    pub fn collapse_directory(&self, node_id: u64) -> Result<usize, String> {
        let children = self.index.get_children(node_id);
        let child_count = children.len();
        
        self.index.mark_collapsed(node_id);
        
        println!("📁 Collapsed: ID {} (removed {} children)", node_id, child_count);
        Ok(child_count)
    }
    
    /// Create a child node from directory entry
    fn create_child_node(&self, dir_entry: &fs::DirEntry, parent_id: u64) -> Result<FileSystemNode, String> {
        let path = dir_entry.path();
        let metadata = dir_entry.metadata()
            .map_err(|e| format!("Failed to get metadata: {}", e))?;
        
        // Get entry type
        let entry_type = if metadata.is_dir() {
            EntryType::Directory
        } else if metadata.is_symlink() {
            EntryType::File  // Treat symlinks as files for simplicity
        } else {
            EntryType::File
        };
        
        // Get file name
        let name = match path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => return Err("No filename".to_string()),
        };
        
        // Build display path
        let parent_node = self.index.get_node(parent_id)
            .ok_or("Parent node not found")?;
        let display_path = if parent_node.display_path.ends_with('\\') {
            format!("{}{}", parent_node.display_path, name)
        } else {
            format!("{}\\{}", parent_node.display_path, name)
        };
        
        // For directories, add trailing backslash
        let display_path = if entry_type == EntryType::Directory {
            format!("{}\\", display_path)
        } else {
            display_path
        };
        
        // PLACEHOLDER: Create NT path
        // let nt_path = PathNormalizer::dos_to_real_nt_path(&display_path, 
        //     entry_type == EntryType::Directory);
        // let nt_path = self.path_resolver.dos_to_real_nt_path(&display_path)?;
         // TEMPORARY: Use empty NT path or placeholder
           let is_folder = entry_type == EntryType::Directory || entry_type == EntryType::Drive;
            // let nt_path = match self.path_resolver.(&display_path) {
            //     Ok(path) => path,
            //     Err(e) => {
            //         println!("⚠️ Failed to convert DOS to NT path: {}", e);
            //         println!("   Using placeholder for: {}", display_path);
            //         // Use placeholder or empty string
            //         PathNormalizer::dos_to_nt_path_placeholder(&display_path, 
            //             entry_type == EntryType::Directory)
            //     }
            // };
            let nt_path = match NtPathResolver::dos_to_nt_path(&display_path, is_folder) {
                Ok(path) => path,
                Err(e) => {
                    println!("⚠️ Failed to convert DOS to NT path: {}", e);
                    // Fallback - use display path as NT path (kernel won't match, but won't crash)
                    display_path.clone()
                }
            };
            
        // Get timestamps
        let modified_time = metadata.modified()
            .unwrap_or_else(|_| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let created_time = metadata.created()
            .unwrap_or_else(|_| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Check if accessible
        let is_accessible = metadata.permissions().readonly() || 
            std::fs::metadata(&path).is_ok();
        
        // Get attributes (Windows)
        #[cfg(windows)]
        let attributes = metadata.file_attributes();
        #[cfg(not(windows))]
        let attributes = 0;
        
        Ok(FileSystemNode {
            id: self.index.get_next_id(),
            name,
            entry_type,
            parent_id: Some(parent_id),
            children_ids: Vec::new(),
            nt_path,
            display_path,
            size: if metadata.is_file() { Some(metadata.len()) } else { None },
            modified_time,
            created_time,
            attributes,
            is_expanded: false,
            is_accessible,
        })
    }
    
    /// Get scanner configuration
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }
    
    /// Update scanner configuration
    pub fn set_config(&mut self, config: ScanConfig) {
        self.config = config;
    }
}