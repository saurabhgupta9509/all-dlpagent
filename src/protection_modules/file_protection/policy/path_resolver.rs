// //! Path Resolver (STEP 4.2)
// //! Core Principle: Only Agent resolves IDs to NT paths, never exposed to Admin

// use windows_sys::Win32::Storage::FileSystem::{GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW};

// use crate::fs_index::{EntryType, FilesystemIndex};
// use crate::path_normalizer::PathNormalizer;
// use crate::policy::policy_intent::{PolicyIntent, ProtectionScope};
// use std::sync::Arc;

// /// Resolves node IDs to NT paths (Agent internal only)
// pub struct PathResolver {
//     index: Arc<FilesystemIndex>,
//     volume_cache: parking_lot::Mutex<std::collections::HashMap<String, String>>,
// }

// impl PathResolver {
//     /// Create new path resolver
//     pub fn new(index: Arc<FilesystemIndex>) -> Self {
//         PathResolver { index ,
//         volume_cache: parking_lot::Mutex::new(std::collections::HashMap::new()), }
//     }
    
//     /// Get the filesystem index (for internal use)
//     pub fn index(&self) -> &Arc<FilesystemIndex> {
//         &self.index
//     }
    
//     // fn normalize_nt_path(mut path: String) -> String {
//     // // Collapse \\ into \
//     //     while path.contains("\\\\") {
//     //         path = path.replace("\\\\", "\\");
//     //     }

//     //     // Remove trailing slash except root cases
//     //     if path.ends_with('\\') && !path.ends_with(":\\") {
//     //         path.pop();
//     //     }

//     //     path
//     // }

//     fn normalize_nt_path(path: &str, scope: ProtectionScope) -> String {
//     let mut p = path.trim().replace('/', "\\");

//     match scope {
//         ProtectionScope::File => {
//             // files → NO trailing slash
//             while p.ends_with('\\') {
//                 p.pop();
//             }
//         }
//         ProtectionScope::Folder | ProtectionScope::FolderRecursive => {
//             // folders → MUST have trailing slash
//             if !p.ends_with('\\') {
//                 p.push('\\');
//             }
//         }
//     }

//     p
// }


//     /// Resolve node ID to NT path (INTERNAL USE ONLY)
//     /// ⚠️ This is the SECURITY BOUNDARY - never expose NT paths
//     // pub fn resolve_nt_path(&self, node_id: u64) -> Result<String, String> {
//     //     println!("🔄 PathResolver: Resolving ID {} → NT path", node_id);
        
//     //     match self.index.resolve_nt_path(node_id) {
//     //         Some(nt_path) => {
                
//     //             let nt_path = Self::normalize_nt_path(nt_path);
//     //             // Validate NT path format
//     //             if !nt_path.starts_with("\\Device\\") {
//     //                 return Err(format!("Invalid NT path format: {}", nt_path));
//     //             }
                
//     //             println!("   ✅ Resolved: {}", nt_path);
//     //             Ok(nt_path)
//     //         }
//     //         None => {
//     //             let error = format!("Node ID {} not found in filesystem index", node_id);
//     //             println!("   ❌ {}", error);
//     //             Err(error)
//     //         }
//     //     }
//     // }
    
//     // pub fn resolve_nt_path(&self, node_id: u64) -> Result<String, String> {
//     // let nt_path = self.index.resolve_nt_path(node_id)
//     //         .ok_or("Not found")?;

//     //     // ❗ NO NORMALIZATION HERE
//     //     Ok(nt_path)
//     // }

//     //   pub fn resolve_nt_path(&self, node_id: u64) -> Result<String, String> {
//     //     let nt_path = self.index.resolve_nt_path(node_id)
//     //         .ok_or("Not found")?;
        
//     //     // 🔥 FIX: Remove double backslashes
//     //     let fixed_path = nt_path.replace("\\\\", "\\");
        
//     //     Ok(fixed_path)
//     // }

//    pub fn resolve_nt_path(&self, node_id: u64) -> Result<String, String> {
//         println!("🔄 PathResolver::resolve_nt_path called for node {}", node_id);
        
//         let node = self.index.get_node(node_id)
//             .ok_or_else(|| format!("Node {} not found", node_id))?;
        
//         println!("   Node display path: {}", node.display_path);
//         println!("   Node NT path: {}", node.nt_path);
        
//         // If node already has NT path in index, use it
//         if !node.nt_path.is_empty() && node.nt_path.starts_with("\\Device\\") {
//             println!("   Using cached NT path");
//             return Ok(node.nt_path.clone());
//         }
        
//         println!("   Converting DOS to real NT path...");
//         // Otherwise convert display path to NT path
//         self.dos_to_real_nt_path(&node.display_path)
//     }

//     /// Resolve policy intent to kernel-ready NT path(s)
//     /// This handles recursive folder expansion
//     pub fn resolve_policy_intent(&self, intent: &PolicyIntent) -> Result<Vec<String>, String> {
//         println!("🔄 PathResolver: Resolving policy intent for ID {}", intent.node_id);
//         println!("   Scope: {:?}, Action: {:?}", intent.scope, intent.action);
        
//         let base_nt_path = self.resolve_nt_path(intent.node_id)?;
        
//         match intent.scope {
//             ProtectionScope::File => {
//                 // Single file - exact match
//                 println!("   ✅ Single file: {}", base_nt_path);
//                 Ok(vec![base_nt_path])
//             }
            
//             // ProtectionScope::Folder => {
//             //     // Folder only (non-recursive) - needs trailing backslash
//             //     let mut folder_path = base_nt_path;
//             //     if !folder_path.ends_with('\\') {
//             //         folder_path.push('\\');
//             //     }
//             //     println!("   ✅ Folder (non-recursive): {}", folder_path);
//             //     Ok(vec![folder_path])
//             // }
//             ProtectionScope::Folder => {
//                 // NON-RECURSIVE:
//                 // Resolve only direct children (files only)
//                 let children = self.index.get_children(intent.node_id);

//                 let mut paths = Vec::new();

//                for child in children {
//                     if matches!(child.entry_type, EntryType::File) {
//                         if let Some(p) = self.index.resolve_nt_path(child.id) {
//                             paths.push(p); // exact file paths
//                         }
//                     }
//                 }

//                 println!("   ✅ Folder (non-recursive): {} direct files", paths.len());
//                 Ok(paths)
//             }

//             ProtectionScope::FolderRecursive => {
//                 // Recursive folder - for now, just return folder path
//                 // In production, you might want to enumerate all subpaths
//                 // For kernel minifilter, prefix matching handles recursion
//                 let mut folder_path = base_nt_path;
//                 if !folder_path.ends_with('\\') {
//                     folder_path.push('\\');
//                 }
//                 println!("   ✅ Folder (recursive - prefix match): {}", folder_path);
//                 Ok(vec![folder_path])
//             }
//         }
//     }
    
//     /// Validate that node exists and is accessible
//     pub fn validate_node(&self, node_id: u64) -> Result<(), String> {
//         println!("🔍 PathResolver: Validating node {}", node_id);
        
//         match self.index.get_node(node_id) {
//             Some(node) => {
//                 if node.is_accessible {
//                     println!("   ✅ Node accessible: {} (ID: {})", node.name, node.id);
//                     Ok(())
//                 } else {
//                     let error = format!("Node {} is not accessible", node_id);
//                     println!("   ❌ {}", error);
//                     Err(error)
//                 }
//             }
//             None => {
//                 let error = format!("Node {} not found in index", node_id);
//                 println!("   ❌ {}", error);
//                 Err(error)
//             }
//         }
//     }

//    /// Get actual NT path for a DOS path
// // pub fn dos_to_real_nt_path(&self, dos_path: &str) -> Result<String, String> {
// //     println!("🔄 Converting DOS to NT: {}", dos_path);
    
// //     // Extract drive letter
// //     let drive_letter = if dos_path.len() >= 2 && dos_path.chars().nth(1) == Some(':') {
// //         &dos_path[0..2]  // "C:" or "D:"
// //     } else {
// //         return Err("Invalid DOS path format".to_string());
// //     };
    
// //     // Get volume name for drive
// //     let volume_name = self.get_volume_name(drive_letter)?;
// //     println!("   Volume name: {}", volume_name);
    
// //     // Convert volume name to device path
// //     let nt_path = self.volume_name_to_device_path(&volume_name)?;
// //     println!("   Device path: {}", nt_path);
    
// //     // Append rest of path
// //     let relative_path = &dos_path[2..]; // Remove "C:" or "D:"
// //     let full_nt_path = format!("{}{}", nt_path, relative_path);
    
// //     // Ensure proper trailing backslash
// //     let final_path = if dos_path.ends_with('\\') && !full_nt_path.ends_with('\\') {
// //         format!("{}\\", full_nt_path)
// //     } else if !dos_path.ends_with('\\') && full_nt_path.ends_with('\\') {
// //         full_nt_path.trim_end_matches('\\').to_string()
// //     } else {
// //         full_nt_path
// //     };
    
// //     println!("   Final NT path: {}", final_path);
// //     Ok(final_path)
// // }    

//     pub fn dos_to_real_nt_path(&self, dos_path: &str) -> Result<String, String> {
//         println!("🔄 PathResolver: Converting DOS to NT: {}", dos_path);
        
//         // Extract drive letter
//         let drive_letter = if dos_path.len() >= 2 && dos_path.chars().nth(1) == Some(':') {
//             &dos_path[0..2]  // "C:" or "D:"
//         } else {
//             return Err("Invalid DOS path format".to_string());
//         };
        
//         // Try to get real NT path
//         match self.get_volume_name(drive_letter) {
//             Ok(volume_name) => {
//                 println!("   Volume name: {}", volume_name);
                
//                 match self.volume_name_to_device_path(&volume_name) {
//                     Ok(nt_path) => {
//                         println!("   Device path: {}", nt_path);
                        
//                         // Append rest of path
//                         let relative_path = &dos_path[2..]; // Remove "C:" or "D:"
//                         let full_nt_path = format!("{}{}", nt_path, relative_path);
                        
//                         // Replace forward slashes with backslashes and normalize
//                         let final_path = full_nt_path.replace('/', "\\");
                        
//                         println!("   Final NT path: {}", final_path);
//                         Ok(final_path)
//                     }
//                     Err(e) => {
//                         println!("   ⚠️ Failed to get device path: {}", e);
//                         println!("   Falling back to placeholder...");
//                         // Fallback to placeholder
//                         let is_folder = dos_path.ends_with('\\');
//                         Ok(PathNormalizer::dos_to_nt_path_placeholder(dos_path, is_folder))
//                     }
//                 }
//             }
//             Err(e) => {
//                 println!("   ⚠️ Failed to get volume name: {}", e);
//                 println!("   Falling back to placeholder...");
//                 // Fallback to placeholder
//                 let is_folder = dos_path.ends_with('\\');
//                 Ok(PathNormalizer::dos_to_nt_path_placeholder(dos_path, is_folder))
//             }
//         }
//     }

//     /// Get volume name (like \\?\Volume{guid}\) for a drive
//     fn get_volume_name(&self, drive_letter: &str) -> Result<String, String> {
//         let mut drive_with_slash = drive_letter.to_string();
//         if !drive_with_slash.ends_with('\\') {
//             drive_with_slash.push('\\');
//         }
        
//         let drive_wide: Vec<u16> = drive_with_slash.encode_utf16().chain(Some(0)).collect();
//         let mut volume_name = vec![0u16; 50]; // Usually enough
        
//         unsafe {
//             let success = GetVolumeNameForVolumeMountPointW(
//                 drive_wide.as_ptr(),
//                 volume_name.as_mut_ptr(),
//                 volume_name.len() as u32
//             );
            
//             if success == 0 {
//                 return Err(format!("Failed to get volume name for {}", drive_letter));
//             }
            
//             let len = volume_name.iter().position(|&c| c == 0).unwrap_or(0);
//             Ok(String::from_utf16_lossy(&volume_name[..len]))
//         }
//     }

//     /// Convert volume name to device path (like \Device\HarddiskVolumeX)
//     fn volume_name_to_device_path(&self, volume_name: &str) -> Result<String, String> {
//         // Check cache first
//         {
//             let cache = self.volume_cache.lock();
//             if let Some(cached) = cache.get(volume_name) {
//                 return Ok(cached.clone());
//             }
//         }
        
//         // Volume names look like: \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\
//         // We need to query DOS device names
//         let volume_wide: Vec<u16> = volume_name.encode_utf16().chain(Some(0)).collect();
//         let mut buffer = vec![0u16; 1024];
        
//         unsafe {
//             let mut required_size = 0;
            
//             // First call to get required size
//             GetVolumePathNamesForVolumeNameW(
//                 volume_wide.as_ptr(),
//                 buffer.as_mut_ptr(),
//                 buffer.len() as u32,
//                 &mut required_size
//             );
            
//             // If buffer too small, allocate bigger buffer
//             if required_size > buffer.len() as u32 {
//                 buffer = vec![0u16; required_size as usize];
//             }
            
//             let success = GetVolumePathNamesForVolumeNameW(
//                 volume_wide.as_ptr(),
//                 buffer.as_mut_ptr(),
//                 buffer.len() as u32,
//                 &mut required_size
//             );
            
//             if success == 0 {
//                 return Err("Failed to get device path".to_string());
//             }
            
//             // Find first device path
//             let mut paths = Vec::new();
//             let mut start = 0;
//             for i in 0..buffer.len() {
//                 if buffer[i] == 0 {
//                     if start < i {
//                         let path = String::from_utf16_lossy(&buffer[start..i]);
//                         if path.starts_with("\\Device\\") {
//                             paths.push(path);
//                         }
//                     }
//                     start = i + 1;
//                 }
//             }
            
//             if let Some(device_path) = paths.first() {
//                 // Cache it
//                 let mut cache = self.volume_cache.lock();
//                 cache.insert(volume_name.to_string(), device_path.clone());
//                 Ok(device_path.clone())
//             } else {
//                 Err("No device path found".to_string())
//             }
//         }
//     }
// }

//! Path Resolver (STEP 4.2) - Uses unified NT path resolver
//! Core Principle: Only Agent resolves IDs to NT paths, never exposed to Admin
// src/policy/path_resolver.rs
use std::sync::Arc;

use crate::protection_modules::file_protection::{fs_index::{EntryType, FilesystemIndex}, nt_path_resolver::NtPathResolver, policy::{PolicyIntent, ProtectionScope}};

/// Resolves node IDs to NT paths (Agent internal only)
pub struct PathResolver {
    index: Arc<FilesystemIndex>,
}

impl PathResolver {
    /// Create new path resolver
    pub fn new(index: Arc<FilesystemIndex>) -> Self {
        PathResolver { index }
    }
    
    /// Get the filesystem index (for internal use)
    pub fn index(&self) -> &Arc<FilesystemIndex> {
        &self.index
    }
    
    /// Resolve node ID to NT path (INTERNAL USE ONLY)
    pub fn resolve_nt_path(&self, node_id: u64) -> Result<String, String> {
        println!("🔄 PathResolver::resolve_nt_path called for node {}", node_id);
        
        let node = self.index.get_node(node_id)
            .ok_or_else(|| format!("Node {} not found", node_id))?;
        
        println!("   Node display path: {}", node.display_path);
        println!("   Node NT path: {}", node.nt_path);
        
        // If node already has NT path in index, use it
        if !node.nt_path.is_empty() && NtPathResolver::validate_nt_path(&node.nt_path) {
            println!("   Using cached NT path");
            return Ok(node.nt_path.clone());
        }
        
        println!("   Converting DOS to NT path...");
        // Convert display path to NT path
        let is_folder = matches!(node.entry_type, EntryType::Directory | EntryType::Drive);
        NtPathResolver::dos_to_nt_path(&node.display_path, is_folder)
    }
    
    /// Resolve policy intent to kernel-ready NT path(s)
    pub fn resolve_policy_intent(&self, intent: &PolicyIntent) -> Result<Vec<String>, String> {
        println!("🔄 PathResolver: Resolving policy intent for ID {}", intent.node_id);
        println!("   Scope: {:?}, Action: {:?}", intent.scope, intent.action);
        
        let base_nt_path = self.resolve_nt_path(intent.node_id)?;
        
        match intent.scope {
            ProtectionScope::File => {
                println!("   ✅ Single file: {}", base_nt_path);
                Ok(vec![base_nt_path])
            }
            
            ProtectionScope::Folder => {
                // NON-RECURSIVE: Resolve only direct children (files only)
                let children = self.index.get_children(intent.node_id);
                let mut paths = Vec::new();

                for child in children {
                    if matches!(child.entry_type, EntryType::File) {
                        if let Some(p) = self.index.resolve_nt_path(child.id) {
                            paths.push(p);
                        }
                    }
                }

                println!("   ✅ Folder (non-recursive): {} direct files", paths.len());
                Ok(paths)
            }

            ProtectionScope::FolderRecursive => {
                // Recursive folder - prefix match
                let mut folder_path = base_nt_path;
                if !folder_path.ends_with('\\') {
                    folder_path.push('\\');
                }
                println!("   ✅ Folder (recursive - prefix match): {}", folder_path);
                Ok(vec![folder_path])
            }
        }
    }
    
    /// Validate that node exists and is accessible
    pub fn validate_node(&self, node_id: u64) -> Result<(), String> {
        println!("🔍 PathResolver: Validating node {}", node_id);
        
        match self.index.get_node(node_id) {
            Some(node) => {
                if node.is_accessible {
                    println!("   ✅ Node accessible: {} (ID: {})", node.name, node.id);
                    Ok(())
                } else {
                    let error = format!("Node {} is not accessible", node_id);
                    println!("   ❌ {}", error);
                    Err(error)
                }
            }
            None => {
                let error = format!("Node {} not found in index", node_id);
                println!("   ❌ {}", error);
                Err(error)
            }
        }
    }
}