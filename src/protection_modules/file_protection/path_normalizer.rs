// //! Path Normalizer - Converts user paths to kernel-safe NT paths
// //! IMPORTANT: Internal to Agent only

// use std::collections::HashMap;
// use std::path::{Path, PathBuf};
// use std::ffi::OsStr;
// use std::os::windows::ffi::OsStrExt;
// use std::sync::OnceLock;

// use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
// pub struct PathNormalizer;

//     static VOLUME_CACHE: OnceLock<std::sync::Mutex<HashMap<String, String>>> = OnceLock::new();

// /// Get volume cache (thread-safe)
// fn get_volume_cache() -> &'static std::sync::Mutex<HashMap<String, String>> {
//     VOLUME_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
// }

// /// Detect actual NT volume for a drive letter at runtime
// pub fn detect_volume_for_drive(drive_letter: &str) -> Result<String, String> {
//     println!("🔍 Detecting volume for drive: {}", drive_letter);
    
//     // Check cache first
//     let cache = get_volume_cache();
//     let cache_lock = cache.lock().unwrap();
//     if let Some(cached) = cache_lock.get(drive_letter) {
//         println!("   Cache hit: {}", cached);
//         return Ok(cached.clone());
//     }
//     drop(cache_lock); // Release lock before making API calls
    
//     // Ensure drive letter format: "C:" or "C"
//     let normalized_drive = if drive_letter.ends_with(':') {
//         drive_letter.to_string()
//     } else {
//         format!("{}:", drive_letter)
//     };
    
//     // Add backslash for API call
//     let drive_with_slash = if normalized_drive.ends_with('\\') {
//         normalized_drive
//     } else {
//         format!("{}\\", normalized_drive)
//     };
    
//     // Get volume name (like \\?\Volume{guid}\)
//     let volume_name = get_volume_name(&drive_with_slash)?;
//     println!("   Volume name: {}", volume_name);
    
//     // Try to extract volume number from the volume name
//     let volume_number = extract_volume_number(&volume_name);
    
//     // Store in cache
//     let mut cache = get_volume_cache().lock().unwrap();
//     cache.insert(drive_letter.to_string(), volume_number.clone());
    
//     println!("   Detected: {} → {}", drive_letter, volume_number);
//     Ok(volume_number)
// }

// /// Get volume name using Windows API
// fn get_volume_name(drive_with_slash: &str) -> Result<String, String> {
//     let drive_wide: Vec<u16> = drive_with_slash.encode_utf16().chain(Some(0)).collect();
//     let mut volume_name = vec![0u16; 50];
    
//     unsafe {
//         let success = GetVolumeNameForVolumeMountPointW(
//             drive_wide.as_ptr(),
//             volume_name.as_mut_ptr(),
//             volume_name.len() as u32
//         );
        
//         if success == 0 {
//             return Err(format!("Failed to get volume name for {}", drive_with_slash));
//         }
        
//         let len = volume_name.iter().position(|&c| c == 0).unwrap_or(0);
//         Ok(String::from_utf16_lossy(&volume_name[..len]))
//     }
// }

// /// Extract volume number from volume GUID
// fn extract_volume_number(volume_name: &str) -> String {
//     // Volume names look like: \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\
//     // We can extract the GUID and map it to a number
    
//     if volume_name.starts_with("\\\\?\\Volume{") && volume_name.ends_with("}\\") {
//         // Extract GUID
//         let guid_start = volume_name.find('{').unwrap();
//         let guid_end = volume_name.find('}').unwrap();
//         let guid = &volume_name[guid_start + 1..guid_end];
        
//         // Create a hash of the GUID to get a consistent number
//         use std::collections::hash_map::DefaultHasher;
//         use std::hash::{Hash, Hasher};
        
//         let mut hasher = DefaultHasher::new();
//         guid.hash(&mut hasher);
//         let hash = hasher.finish();
        
//         // Map to volume number 2-10 (avoid 0,1 which are system volumes)
//         let volume_num = (hash % 9) as u8 + 2;
        
//         return volume_num.to_string();
//     }
    
//     // Fallback based on common patterns
//     match volume_name {
//         s if s.contains("7d087599-e14e-4bee-a1a5-76bf27b34c94") => "3".to_string(), // Your C: drive GUID
//         s if s.contains("24fe6ac5-1436-4e44-9353-52f02782fca6") => "4".to_string(), // Your D: drive GUID
//         _ => "3".to_string() // Default
//     }
// }


// impl PathNormalizer {


//     /// Convert DOS path to display format (for debugging only)
//     pub fn normalize_display_path(path: &str) -> String {
//         let mut normalized: String = path.replace('/', "\\").trim().to_string();
        
//         if !normalized.ends_with('\\') && Path::new(&normalized).is_dir() {
//             normalized.push('\\');
//         }
        
//         normalized
//     }
    
//     /// Convert to UTF-16 for Windows APIs
//     pub fn to_wide_string(path: &str) -> Vec<u16> {
//         OsStr::new(path)
//             .encode_wide()
//             .chain(Some(0))
//             .collect()
//     }
    
//     /// Check if path looks like an NT path
//     pub fn is_nt_path_like(path: &str) -> bool {
//         path.trim().starts_with("\\Device\\") || path.trim().starts_with("\\\\?\\")
//     }
    
//     /// PLACEHOLDER: Convert DOS path to NT format
//     /// ⚠️ TODO: Implement proper Windows API conversion (QueryDosDevice, NtCreateFile, etc.)
//     // pub fn dos_to_nt_path_placeholder(dos_path: &str, is_folder: bool) -> String {
//     //     // This is a PLACEHOLDER - real implementation would use:
//     //     // 1. QueryDosDevice to get device mapping
//     //     // 2. NtCreateFile with OBJ_CASE_INSENSITIVE
//     //     // 3. QueryObject to get NT path
        
//     //     let normalized = Self::normalize_display_path(dos_path);
        
//     //     // Simple placeholder conversion
//     //     if normalized.starts_with("C:") {
//     //         if is_folder {
//     //             format!("\\Device\\HarddiskVolume4\\{}", &normalized[2..])
//     //         } else {
//     //             format!("\\Device\\HarddiskVolume4\\{}", &normalized[2..])
//     //         }
//     //     } else if normalized.starts_with("D:") {
//     //         if is_folder {
//     //             format!("\\Device\\HarddiskVolume5\\{}", &normalized[2..])
//     //         } else {
//     //             format!("\\Device\\HarddiskVolume5\\{}", &normalized[2..])
//     //         }
//     //     } else {
//     //         // Generic fallback
//     //         if is_folder {
//     //             format!("\\Device\\HarddiskVolume4\\Placeholder\\{}", normalized)
//     //         } else {
//     //             format!("\\Device\\HarddiskVolume4\\Placeholder\\{}", normalized)
//     //         }
//     //     }
//     // }

    
    
//        pub fn dos_to_nt_path_placeholder(dos_path: &str, is_folder: bool) -> String {
//     let mut normalized = dos_path.trim().replace('/', "\\");
    
//     // Remove trailing backslash for files
//     if !is_folder && normalized.ends_with('\\') {
//         normalized.pop();
//     }
//     // Add trailing backslash for folders
//     else if is_folder && !normalized.ends_with('\\') {
//         normalized.push('\\');
//     }
    
//     // Extract drive letter
//     let drive_letter = if normalized.len() >= 2 && normalized.chars().nth(1) == Some(':') {
//         &normalized[0..1]  // Just "C" or "D"
//     } else {
//         "C"
//     };
    
//     let path_without_drive = &normalized[2..];
        
//         // ⭐⭐ AUTOMATIC DETECTION
//         let volume_number = match detect_volume_for_drive(drive_letter) {
//             Ok(num) => num,
//             Err(e) => {
//                 println!("⚠️ Failed to detect volume for {}: {}, using fallback", drive_letter, e);
//                 // Fallback based on drive letter
//                 match drive_letter {
//                     "C" => "3".to_string(),
//                     "D" => "4".to_string(),
//                     "E" => "5".to_string(),
//                     _ => "3".to_string(),
//                 }
//             }
//         };
        
//         let nt_path = format!("\\Device\\HarddiskVolume{}{}", volume_number, path_without_drive);
        
//         println!("🔧 PathNormalizer: Converted {} → {}", dos_path, nt_path);
//         nt_path
//     }

//     /// Validate path format
//     pub fn validate_path_format(path: &str) -> Result<(), String> {
//         if path.is_empty() {
//             return Err("Path cannot be empty".to_string());
//         }
        
//         if path.contains('\0') {
//             return Err("Path contains null character".to_string());
//         }
        
//         // Check for invalid characters
//         let invalid_chars = ['<', '>', ':', '"', '|', '?', '*'];
//         for ch in invalid_chars {
//             if path.contains(ch) {
//                 return Err(format!("Path contains invalid character: '{}'", ch));
//             }
//         }
        
//         Ok(())
//     }
// }

//! Basic path utilities - No NT path conversion here!
// src/path_normalizer.rs
use std::path::Path;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub struct PathNormalizer;

impl PathNormalizer {
    /// Convert to display format (for debugging only)
    pub fn normalize_display_path(path: &str) -> String {
        let mut normalized: String = path.replace('/', "\\").trim().to_string();
        
        if !normalized.ends_with('\\') && Path::new(&normalized).is_dir() {
            normalized.push('\\');
        }
        
        normalized
    }
    
    /// Convert to UTF-16 for Windows APIs
    pub fn to_wide_string(path: &str) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }
    
    /// Check if path looks like an NT path
    pub fn is_nt_path_like(path: &str) -> bool {
        path.trim().starts_with("\\Device\\") || path.trim().starts_with("\\\\?\\")
    }
    
    /// Validate path format
    pub fn validate_path_format(path: &str) -> Result<(), String> {
        if path.is_empty() {
            return Err("Path cannot be empty".to_string());
        }
        
        if path.contains('\0') {
            return Err("Path contains null character".to_string());
        }
        
        let invalid_chars = ['<', '>', ':', '"', '|', '?', '*'];
        for ch in invalid_chars {
            if path.contains(ch) {
                return Err(format!("Path contains invalid character: '{}'", ch));
            }
        }
        
        Ok(())
    }
}