//! NT Path Resolver - Single source of truth for DOS → NT path conversion
//! IMPORTANT: Internal to Agent only
// src/nt_path_resolver.rs
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW,
    GetVolumePathNamesForVolumeNameW
};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Cache for volume GUID → NT device path mapping
static VOLUME_CACHE: OnceLock<std::sync::Mutex<HashMap<String, String>>> = OnceLock::new();

/// Get volume cache (thread-safe)
fn get_volume_cache() -> &'static std::sync::Mutex<HashMap<String, String>> {
    VOLUME_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Main NT path resolver
pub struct NtPathResolver;

impl NtPathResolver {
    /// Convert DOS path to NT path (with fallback logic)
    pub fn dos_to_nt_path(dos_path: &str, is_folder: bool) -> Result<String, String> {
        println!("🔄 NtPathResolver: Converting DOS to NT: {}", dos_path);
        
        let mut normalized = dos_path.trim().replace('/', "\\");
        
        // Handle trailing backslash
        if !is_folder && normalized.ends_with('\\') {
            normalized.pop();
        } else if is_folder && !normalized.ends_with('\\') {
            normalized.push('\\');
        }
        
        // Extract drive letter
        let drive_letter = if normalized.len() >= 2 && normalized.chars().nth(1) == Some(':') {
            &normalized[0..1]  // "C" or "D"
        } else {
            return Err("Invalid DOS path format".to_string());
        };
        
        // Try to get real NT path using Windows APIs
        match Self::get_real_nt_path(&normalized) {
            Ok(nt_path) => {
                println!("   ✅ Real NT path: {}", nt_path);
                Ok(nt_path)
            }
            Err(e) => {
                println!("   ⚠️ Real path failed: {}, using hardcoded mapping", e);
                // Fallback to hardcoded mapping based on your system
                Self::dos_to_nt_path_hardcoded(&normalized, is_folder)
            }
        }
    }
    
    /// Try to get real NT path using Windows APIs
    fn get_real_nt_path(dos_path: &str) -> Result<String, String> {
        // Extract drive letter with backslash
        let drive_letter = if dos_path.len() >= 2 && dos_path.chars().nth(1) == Some(':') {
            &dos_path[0..2]  // "C:" or "D:"
        } else {
            return Err("Invalid DOS path format".to_string());
        };
        
        let drive_with_slash = format!("{}\\", drive_letter);
        
        // Get volume GUID
        let volume_name = Self::get_volume_name(&drive_with_slash)?;
        println!("   Volume GUID: {}", volume_name);
        
        // Convert volume GUID to device path
        let device_path = Self::volume_guid_to_device_path(&volume_name)?;
        println!("   Device path: {}", device_path);
        
        // Append rest of path
        let relative_path = &dos_path[2..];
        let full_nt_path = format!("{}{}", device_path, relative_path);
        
        Ok(full_nt_path.replace('/', "\\"))
    }
    
    /// Get volume GUID for a drive
    fn get_volume_name(drive_with_slash: &str) -> Result<String, String> {
        let drive_wide: Vec<u16> = drive_with_slash.encode_utf16().chain(Some(0)).collect();
        let mut volume_name = vec![0u16; 50];
        
        unsafe {
            let success = GetVolumeNameForVolumeMountPointW(
                drive_wide.as_ptr(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32
            );
            
            if success == 0 {
                return Err(format!("Failed to get volume GUID for {}", drive_with_slash));
            }
            
            let len = volume_name.iter().position(|&c| c == 0).unwrap_or(0);
            Ok(String::from_utf16_lossy(&volume_name[..len]))
        }
    }
    
    /// Convert volume GUID to device path
    fn volume_guid_to_device_path(volume_name: &str) -> Result<String, String> {
        // Check cache
        {
            let cache = get_volume_cache().lock().unwrap();
            if let Some(cached) = cache.get(volume_name) {
                return Ok(cached.clone());
            }
        }
        
        let volume_wide: Vec<u16> = volume_name.encode_utf16().chain(Some(0)).collect();
        let mut buffer = vec![0u16; 1024];
        
        unsafe {
            let mut required_size = 0;
            
            // First call to get required size
            GetVolumePathNamesForVolumeNameW(
                volume_wide.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut required_size
            );
            
            if required_size > buffer.len() as u32 {
                buffer = vec![0u16; required_size as usize];
            }
            
            let success = GetVolumePathNamesForVolumeNameW(
                volume_wide.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut required_size
            );
            
            if success == 0 {
                // Windows API failed, use hardcoded mapping based on volume GUID
                return Self::guid_to_hardcoded_path(volume_name);
            }
            
            // Parse buffer for device paths
            let mut paths = Vec::new();
            let mut start = 0;
            for i in 0..buffer.len() {
                if buffer[i] == 0 {
                    if start < i {
                        let path = String::from_utf16_lossy(&buffer[start..i]);
                        if path.starts_with("\\Device\\") {
                            paths.push(path);
                        }
                    }
                    start = i + 1;
                }
            }
            
            if let Some(device_path) = paths.first() {
                // Cache it
                let mut cache = get_volume_cache().lock().unwrap();
                cache.insert(volume_name.to_string(), device_path.clone());
                Ok(device_path.clone())
            } else {
                // No device path found, use hardcoded
                Self::guid_to_hardcoded_path(volume_name)
            }
        }
    }
    
    /// Hardcoded mapping based on your volume GUIDs
    fn guid_to_hardcoded_path(volume_name: &str) -> Result<String, String> {
        // From your logs:
        // C: → Volume{7d087599-e14e-4bee-a1a5-76bf27b34c94} → HarddiskVolume3 (NOT 6!)
        // D: → Volume{24fe6ac5-1436-4e44-9353-52f02782fca6} → HarddiskVolume4 (NOT 3!)
        
        let device_path = if volume_name.contains("7d087599-e14e-4bee-a1a5-76bf27b34c94") {
            "\\Device\\HarddiskVolume3".to_string()
        } else if volume_name.contains("24fe6ac5-1436-4e44-9353-52f02782fca6") {
            "\\Device\\HarddiskVolume4".to_string()
        } else {
            // Default fallback
            "\\Device\\HarddiskVolume3".to_string()
        };
        
        println!("   Using hardcoded mapping: {} → {}", volume_name, device_path);
        Ok(device_path)
    }
    
    /// Hardcoded fallback mapping
    fn dos_to_nt_path_hardcoded(dos_path: &str, is_folder: bool) -> Result<String, String> {
        let mut normalized = dos_path.trim().replace('/', "\\");
        
        // Handle trailing backslash
        if !is_folder && normalized.ends_with('\\') {
            normalized.pop();
        } else if is_folder && !normalized.ends_with('\\') {
            normalized.push('\\');
        }
        
        // Extract drive letter
        let drive_letter = if normalized.len() >= 2 && normalized.chars().nth(1) == Some(':') {
            &normalized[0..1]  // "C" or "D"
        } else {
            return Err("Invalid DOS path format".to_string());
        };
        
        let path_without_drive = &normalized[2..];
        
        // ⭐⭐ CORRECT HARDCODED MAPPING FOR YOUR SYSTEM
        let volume_number = match drive_letter {
            "C" => "3",  // C: is HarddiskVolume3
            "D" => "4",  // D: is HarddiskVolume4
            "E" => "5",
            "F" => "6",
            _ => "3",
        };
        
        let nt_path = format!("\\Device\\HarddiskVolume{}{}", volume_number, path_without_drive);
        
        println!("🔧 NtPathResolver (hardcoded): {} → {}", dos_path, nt_path);
        Ok(nt_path)
    }
    
    /// Validate that a path is a valid NT path
    pub fn validate_nt_path(nt_path: &str) -> bool {
        nt_path.starts_with("\\Device\\HarddiskVolume")
    }
}