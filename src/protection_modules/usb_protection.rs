use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::policy_constants::*;
use serde::{ Deserialize, Serialize };
use std::any::Any;
use std::collections::{ HashMap, HashSet };
use std::time::{ SystemTime, UNIX_EPOCH };
use std::path::Path;
// use std::ffi::OsString;
// use std::os::windows::ffi::OsStringExt;
use std::fs;
use log::{ info, warn, error, debug };
// use tokio::time;

// --- CORRECTED WINDOWS API IMPORTS ---
// --- CORRECTED WINDOWS API IMPORTS ---
use windows_sys::Win32::Foundation::{
    CloseHandle,
    GENERIC_READ,
    // MAX_PATH, // <-- Unused, removed
    INVALID_HANDLE_VALUE,
    // DRIVE_REMOVABLE // <-- Moved back to Foundation
};
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives,
    GetDriveTypeW,
    CreateFileW,
    OPEN_EXISTING,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE, // <-- Moved to FileSystem
};
// 'use windows_sys::Win32::System::SystemServices' is no longer needed
use windows_sys::Win32::System::Ioctl::IOCTL_STORAGE_EJECT_MEDIA;
use windows_sys::Win32::System::IO::DeviceIoControl;
// --- END OF IMPORTS ---
/// Information about a USB device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct USBDeviceInfo {
    pub drive_letter: String, // e.g. "F:"
    pub volume_name: String,
    pub total_size: u64,
    pub free_space: u64,
    pub file_system: String,
    pub serial_number: String,
    pub insertion_time: u64,
}

/// Analysis results of files on a USB device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct USBFileAnalysis {
    pub total_files: usize,
    pub total_folders: usize,
    pub total_size: u64,
    pub file_types: HashMap<String, usize>,
    pub file_list: Vec<String>,
    pub suspicious_files: Vec<String>,
}

impl USBFileAnalysis {
    /// Creates an empty analysis result, used for alerts where no scan was performed.
    fn empty() -> Self {
        Self {
            total_files: 0,
            total_folders: 0,
            total_size: 0,
            file_types: HashMap::new(),
            file_list: Vec::new(),
            suspicious_files: Vec::new(),
        }
    }
}

// ===== USB PROTECTION MODULE =====

/// USB protection module that monitors and controls USB devices
pub struct USBProtection {
    known_devices: HashSet<String>, // Tracks known USB devices (drive letters like "F:")
    known_files: HashSet<String>, // Track files we've already seen (full path strings)
    last_scan_time: u64, // Last scan time for rate limiting (epoch seconds)
}

impl USBProtection {
    /// Create a new USB protection module
    pub fn new() -> Self {
        Self {
            known_devices: HashSet::new(),
            known_files: HashSet::new(),
            last_scan_time: 0,
        }
    }

    fn calculate_content_based_severity(
        &self,
        analysis: &USBFileAnalysis,
        device: &USBDeviceInfo
    ) -> &'static str {
        let mut flags = vec![];

        // CRITICAL: Executables + Documents combination (potential malware + data)
        if self.count_executables(analysis) > 0 && self.count_documents(analysis) > 20 {
            return "CRITICAL";
        }

        // HIGH: Any of these conditions
        if self.count_executables(analysis) > 0 {
            flags.push("executables");
        }
        if analysis.suspicious_files.len() > 0 {
            flags.push("suspicious_files");
        }
        if analysis.total_size > 500 * 1024 * 1024 {
            // > 500MB
            flags.push("large_data");
        }

        if !flags.is_empty() {
            return "HIGH";
        }

        // MEDIUM: Documents or moderate data
        if self.count_documents(analysis) > 10 {
            return "MEDIUM";
        }
        if analysis.total_files > 100 {
            return "MEDIUM";
        }

        // LOW: Everything else
        "LOW"
    }
    fn count_executables(&self, analysis: &USBFileAnalysis) -> usize {
        let exec_extensions = ["exe", "dll", "sys", "bat", "cmd", "msi", "ps1", "com", "scr"];
        analysis.file_types
            .iter()
            .filter(|(ext, _)| exec_extensions.contains(&ext.as_str()))
            .map(|(_, count)| count)
            .sum()
    }

    fn count_documents(&self, analysis: &USBFileAnalysis) -> usize {
        let doc_extensions = [
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "txt",
            "csv",
            "sql",
        ];
        analysis.file_types
            .iter()
            .filter(|(ext, _)| doc_extensions.contains(&ext.as_str()))
            .map(|(_, count)| count)
            .sum()
    }

    fn get_risk_summary(&self, analysis: &USBFileAnalysis) -> String {
        let exec_count = self.count_executables(analysis);
        let doc_count = self.count_documents(analysis);
        let suspicious_count = analysis.suspicious_files.len();

        if exec_count > 0 && doc_count > 0 {
            format!("⚠️ HIGH RISK: {} executables + {} documents found", exec_count, doc_count)
        } else if exec_count > 0 {
            format!("⚠️ Contains {} executable files", exec_count)
        } else if suspicious_count > 0 {
            format!("⚠️ Contains {} suspicious files", suspicious_count)
        } else if doc_count > 10 {
            format!("📄 Contains {} documents", doc_count)
        } else if analysis.total_files == 0 {
            "📭 Empty USB device".to_string()
        } else {
            "📁 Safe files only".to_string()
        }
    }
    /// Main monitoring logic for USB devices
    async fn execute_monitoring(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Use the new, reliable scan method to find *only* removable drives
        let current_devices = self.scan_usb_devices();

        // 2. Process all connected removable devices
        for device in &current_devices {
            // Priority 1: BLOCK (Highest Priority)
            if policy_engine.is_policy_active(POLICY_USB_DEVICE_BLOCK) {
                // Persistent Ejection: Always try to eject if it's there
                if let Err(e) = self.handle_ejection_only(device).await {
                    error!("❌ Persistent USB ejection failed for {}: {}", device.drive_letter, e);
                }

                // Alert only on first detection
                if !self.known_devices.contains(&device.drive_letter) {
                    warn!("🚫 USB BLOCKED by policy: {}. Persistent ejection active.", device.drive_letter);
                    self.send_usb_alert(
                        device,
                        &USBFileAnalysis::empty(),
                        "BLOCKED",
                        communicator,
                        agent_id,
                        token
                    ).await?;
                    self.known_devices.insert(device.drive_letter.clone());
                }
                continue; 
            }

            // Priority 2: Standard Monitoring for new devices
            if !self.known_devices.contains(&device.drive_letter) {
                info!("🎯 New USB device detected: {}", device.drive_letter);
                self.known_devices.insert(device.drive_letter.clone());

                // Policy: MONITOR CONNECTION (Send simple alert)
                if policy_engine.is_policy_active(POLICY_USB_DEVICE_MONITOR) {
                    info!("👀 USB CONNECTION MONITORED: {}", device.drive_letter);
                    self.send_usb_alert(
                        device,
                        &USBFileAnalysis::empty(),
                        "MONITORED",
                        communicator,
                        agent_id,
                        token
                    ).await?;
                }

                // Other monitoring policies (Disabled in this version as per requested focus)
                // if policy_engine.is_policy_active(POLICY_USB_SCAN_FILES) { ... }
            }
        }

        // 3. Process device removals
        let current_drives: HashSet<String> = current_devices
            .iter()
            .map(|d| d.drive_letter.clone())
            .collect();
        self.known_devices.retain(|known_drive| {
            let is_still_connected = current_drives.contains(known_drive);
            if !is_still_connected {
                info!("📤 USB device removed: {}", known_drive);
            }
            is_still_connected // Keep if true, remove if false
        });

        self.last_scan_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(())
    }

    /// Handle a USB device that should be blocked
    async fn handle_blocked_usb(
        &self,
        device: &USBDeviceInfo,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        warn!(
            "🛑 USB device {} has been blocked by DLP policy. Attempting eject.",
            device.drive_letter
        );

        // 1. Send the alert *before* ejecting
        self.send_usb_alert(
            device,
            &USBFileAnalysis::empty(),
            "BLOCKED",
            communicator,
            agent_id,
            token
        ).await?;

        // 2. Perform ejection
        self.handle_ejection_only(device).await
    }

    /// NEW: Perform the actual ejection via Windows API without sending alerts
    async fn handle_ejection_only(
        &self,
        device: &USBDeviceInfo,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Format the drive path for the Windows API: "\\.\E:"
        let volume_path_str = format!(r"\\.\{}", device.drive_letter);
        let mut volume_path_w: Vec<u16> = volume_path_str.encode_utf16().collect();
        volume_path_w.push(0); // Null terminator

        unsafe {
            let handle = CreateFileW(
                volume_path_w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(), // security attributes
                OPEN_EXISTING,
                0,
                0
            );

            if handle == INVALID_HANDLE_VALUE {
                error!("Failed to get handle for drive {}. Cannot eject.", device.drive_letter);
                return Ok(());
            }

            // Send the "Eject" command to the drive
            let mut bytes_returned: u32 = 0;
            let result = DeviceIoControl(
                handle,
                IOCTL_STORAGE_EJECT_MEDIA,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut()
            );

            if result == 0 {
                // error!(
                //     "Failed to send eject command to {}. The drive may be in use.",
                //     device.drive_letter
                // );
            } else {
                info!("✅ Successfully ejected device {}", device.drive_letter);
            }

            CloseHandle(handle);
        }

        Ok(())
    }

    /// Monitor file operations on a USB drive (single scan pass)
    async fn monitor_file_operations(
        &mut self,
        drive_letter: &str,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let drive_path = format!("{}\\", drive_letter);

        let current_files = match Self::scan_files(&drive_path) {
            Ok(files) => files,
            Err(e) => {
                warn!("⚠️ Cannot scan files on drive {}: {}", drive_letter, e);
                return Ok(());
            }
        };

        let new_files: Vec<String> = current_files
            .iter()
            .filter(|file_path| !self.known_files.contains(*file_path))
            .cloned()
            .collect();

        if !new_files.is_empty() {
            info!("📄 Found {} new files on USB drive {}", new_files.len(), drive_letter);

            for file_path in &new_files {
                let path = Path::new(file_path);

                // if policy_engine.is_policy_active(POLICY_USB_BLOCK_EXECUTABLES) {
                //     if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                //         let ext_lower = ext.to_lowercase();
                //         let executable_extensions = [
                //             "exe",
                //             "bat",
                //             "msi",
                //             "ps1",
                //             "cmd",
                //             "com",
                //             "scr",
                //             "vbs",
                //         ];

                //         if executable_extensions.contains(&ext_lower.as_str()) {
                //             warn!("🚫 Executable file BLOCKED by policy: {}", file_path);

                //             if let Err(e) = fs::remove_file(file_path) {
                //                 error!("❌ Failed to remove blocked file {}: {}", file_path, e);
                //             } else {
                //                 info!("✅ Blocked executable file removed: {}", file_path);
                //                 Self::send_file_block_alert(
                //                     communicator,
                //                     agent_id,
                //                     token,
                //                     file_path,
                //                     &ext_lower,
                //                     POLICY_USB_BLOCK_EXECUTABLES
                //                 ).await?;
                //             }
                //             continue;
                //         }
                //     }
                // }

                // if policy_engine.is_policy_active(POLICY_USB_DETECT_SUSPICIOUS) {
                //     if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                //         if self.is_suspicious_file(&ext.to_lowercase(), path) {
                //             warn!("⚠️ Suspicious file detected by policy: {}", file_path);
                //             Self::send_suspicious_file_alert(
                //                 communicator,
                //                 agent_id,
                //                 token,
                //                 file_path
                //             ).await?;
                //         }
                //     }
                // }
            }

            self.known_files.extend(new_files);
        }
        Ok(())
    }

    // ===== WINDOWS API USB DETECTION =====

    /// Scan for USB devices on the system using the Windows API.
    pub fn scan_usb_devices(&self) -> Vec<USBDeviceInfo> {
        info!("🔍 Scanning for removable USB drives...");
        let mut devices = Vec::new();

        let drive_mask = unsafe { GetLogicalDrives() };

        for i in 0..26 {
            if ((drive_mask >> i) & 1) == 1 {
                let drive_letter = (b'A' + i) as char;
                let drive_path_str = format!("{}:\\", drive_letter);

                if self.is_removable_drive(&drive_path_str) {
                    info!("✅ Found removable drive: {}", drive_path_str);
                    if let Some(device_info) = self.get_drive_info(&drive_path_str) {
                        devices.push(device_info);
                    }
                } else {
                    debug!("  Ignoring non-removable drive: {}", drive_path_str);
                }
            }
        }
        info!("📊 Scan complete. Found {} removable drives.", devices.len());
        devices
    }

    /// Check if a drive is a removable drive (like a USB stick).
    fn is_removable_drive(&self, drive_path: &str) -> bool {
        let mut path_w: Vec<u16> = drive_path.encode_utf16().collect();
        path_w.push(0); // Null-terminate the string

        let drive_type = unsafe { GetDriveTypeW(path_w.as_ptr()) };

        // Use the correctly imported constant (DRIVE_REMOVABLE = 2)
        drive_type == 2
    }

    // ===== UTILITY & FILE ANALYSIS METHODS =====

    /// Get information about a drive (Prototype)
    fn get_drive_info(&self, drive_path: &str) -> Option<USBDeviceInfo> {
        let drive_letter = drive_path[0..2].to_string();

        let (volume_name, total_size) = self.get_real_drive_info_prototype(drive_path);

        Some(USBDeviceInfo {
            drive_letter,
            volume_name,
            total_size,
            free_space: 0, // Placeholder
            file_system: "Unknown".to_string(), // Placeholder
            serial_number: "Unknown".to_string(), // Placeholder
            insertion_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        })
    }

    /// Prototype method to get drive info.
    fn get_real_drive_info_prototype(&self, drive_path: &str) -> (String, u64) {
        let mut volume_name = format!("Drive_{}", &drive_path[0..1]);
        let mut total_size = 0;

        if
            let Ok(output) = std::process::Command
                ::new("cmd")
                .args(&["/C", &format!("vol {}", drive_path)])
                .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("Volume in drive") && line.contains("is") {
                    if let Some(name_start) = line.find("is ") {
                        let name = line[name_start + 3..].trim();
                        if !name.is_empty() && name != "has no label" {
                            volume_name = name.to_string();
                        }
                    }
                }
            }
        }

        if let Ok(metadata) = fs::metadata(drive_path) {
            total_size = metadata.len();
        }

        (volume_name, total_size)
    }

    /// Scan files in a directory (top-level only)
    fn scan_files(drive_path: &str) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
        let mut files = HashSet::new();
        if let Ok(entries) = fs::read_dir(drive_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(path_str) = path.to_str() {
                        files.insert(path_str.to_string());
                    }
                }
            }
        }
        Ok(files)
    }

    /// Analyze files on a USB drive (recursive)
    pub fn analyze_usb_files(&self, drive_letter: &str) -> USBFileAnalysis {
        let mut analysis = USBFileAnalysis::empty();
        let drive_path = format!("{}\\", drive_letter);
        info!("   📁 Scanning all files and folders on {}...", drive_letter);
        self.analyze_directory(Path::new(&drive_path), &mut analysis);
        info!(
            "   📊 Scan complete: Found {} files, {} folders",
            analysis.total_files,
            analysis.total_folders
        );
        analysis
    }

    /// Recursively analyze directory
    fn analyze_directory(&self, dir_path: &Path, analysis: &mut USBFileAnalysis) {
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    analysis.total_folders += 1;
                    self.analyze_directory(&path, analysis);
                } else if path.is_file() {
                    self.analyze_file(&path, analysis);
                }
            }
        }
    }

    /// Analyze a single file
    fn analyze_file(&self, file_path: &Path, analysis: &mut USBFileAnalysis) {
        analysis.total_files += 1;

        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("no_extension")
            .to_lowercase();

        *analysis.file_types.entry(extension.clone()).or_insert(0) += 1;

        if let Ok(metadata) = fs::metadata(file_path) {
            analysis.total_size += metadata.len();
        }

        if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
            analysis.file_list.push(file_name.to_string());
        }

        if self.is_suspicious_file(&extension, file_path) {
            if let Some(file_name) = file_path.file_name().and_then(|name| name.to_str()) {
                analysis.suspicious_files.push(file_name.to_string());
            }
        }
    }

    /// Check if a file is suspicious by extension or name
    fn is_suspicious_file(&self, extension: &str, file_path: &Path) -> bool {
        let suspicious_extensions = [
            "exe",
            "bat",
            "cmd",
            "ps1",
            "vbs",
            "js",
            "jar",
            "scr",
            "pif",
            "com",
            "msi",
        ];
        let suspicious_keywords = [
            "keygen",
            "crack",
            "serial",
            "patch",
            "loader",
            "activator",
            "torrent",
            "hack",
            "exploit",
        ];

        if suspicious_extensions.contains(&extension) {
            return true;
        }

        if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
            let filename_lower = filename.to_lowercase();
            for keyword in &suspicious_keywords {
                if filename_lower.contains(keyword) {
                    return true;
                }
            }
        }
        false
    }

    // --- ALERT SENDING METHODS ---

    fn get_hostname() -> String {
        // Method 1: Use whoami crate (already in your dependencies)
        whoami::hostname()

        // OR Method 2: Use Windows API directly
        // use windows::Win32::System::SystemInformation::GetComputerNameW;
        // ... Windows API code ...
    }

    fn calculate_usb_severity(
        file_analysis: &USBFileAnalysis,
        device_info: &USBDeviceInfo,
        action_taken: &str
    ) -> &'static str {
        let mut risk_score = 0;

        // === PRIMARY: Content Risk Assessment ===

        // 1. Suspicious/Risky Files (HIGHEST WEIGHT)
        risk_score += file_analysis.suspicious_files.len() * 15;

        // 2. Executable/Binary Files
        let executable_extensions = ["exe", "dll", "sys", "bat", "cmd", "msi", "ps1"];
        let mut executable_count = 0;
        for (ext, count) in &file_analysis.file_types {
            if executable_extensions.contains(&ext.as_str()) {
                executable_count += count;
            }
        }
        risk_score += executable_count * 10;

        // 3. Script Files (Medium Risk)
        let script_extensions = ["vbs", "js", "py", "rb", "sh"];
        let mut script_count = 0;
        for (ext, count) in &file_analysis.file_types {
            if script_extensions.contains(&ext.as_str()) {
                script_count += count;
            }
        }
        risk_score += script_count * 5;

        // 4. Large Data Transfers (Potential exfiltration)
        if file_analysis.total_size > 100 * 1024 * 1024 {
            // > 100MB
            risk_score += 20; // High risk of data theft
        } else if file_analysis.total_size > 10 * 1024 * 1024 {
            // > 10MB
            risk_score += 10;
        }

        // 5. Large Number of Documents (Potential data leak)
        let document_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"];
        let mut document_count = 0;
        for (ext, count) in &file_analysis.file_types {
            if document_extensions.contains(&ext.as_str()) {
                document_count += count;
            }
        }
        if document_count > 50 {
            risk_score += 15; // Many sensitive documents
        } else if document_count > 10 {
            risk_score += 5;
        }

        // === SECONDARY: Device Characteristics ===

        // 6. Unknown/Unregistered Device
        if device_info.serial_number == "Unknown" || device_info.serial_number.is_empty() {
            risk_score += 10;
        }

        // 7. Large Capacity USB (could store more data)
        if device_info.total_size > 64 * 1024 * 1024 * 1024 {
            // > 64GB
            risk_score += 5;
        }

        // === TERTIARY: Action Taken (Minor adjustment) ===
        // The action reflects OUR response, not the device's risk level
        match action_taken {
            "BLOCKED" => {
                risk_score += 5;
            } // We blocked it because it was high risk
            "EJECTED" => {
                risk_score += 5;
            } // We ejected it because it was high risk
            "SCANNED" => {
                risk_score += 0;
            } // Neutral - just scanned
            "MONITORED" => {
                risk_score += 0;
            } // Neutral - just observed
            _ => {
                risk_score += 0;
            }
        }

        // === FINAL SEVERITY MAPPING ===
        match risk_score {
            0..=10 => "LOW", // Empty or only safe files
            11..=30 => "MEDIUM", // Some documents, small data
            31..=60 => "HIGH", // Executables or large data
            _ => "CRITICAL", // Multiple risks combined
        }
    }

    /// Send a generic USB alert to the backend
    async fn send_usb_alert(
        &self,
        device: &USBDeviceInfo,
        file_analysis: &USBFileAnalysis,
        action: &str,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Calculate severity based on CONTENT, not action
        let severity = self.calculate_content_based_severity(file_analysis, device);

        // Get risk summary for description
        let risk_summary = self.get_risk_summary(file_analysis);

        let alert_data =
            serde_json::json!({
            "agentId": agent_id,
            "agentHostname": whoami::hostname(),
            "alertType": "USB ENCRYPTION",
            "description": format!("USB device detected: {}. Action: {}.", device.drive_letter, action),
            "deviceInfo": format!("Drive: {}, Volume: {}, Size: {}GB", 
                                 device.drive_letter, device.volume_name, 
                                 device.total_size / 1_000_000_000),
            "fileDetails": format!("Files: {}, Folders: {}, Total Size: {}MB, Suspicious: {}", 
                                  file_analysis.total_files, file_analysis.total_folders,
                                  file_analysis.total_size / 1_000_000, file_analysis.suspicious_files.len()),
            "severity": severity,
            "actionTaken": action,
        });

        info!("📤 Sending USB alert to backend...");
        communicator.send_alert(&alert_data, token).await
    }

    /// Send a generic USB alert to the backend
    async fn send_file_block_alert(
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
        file_path: &str,
        file_extension: &str,
        policy_code: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let alert_data =
            serde_json::json!({
            "agentId": agent_id,
            "alertType": "FILE_BLOCKED",
            "description": format!("Executable file blocked by policy: {}", file_path),
            "deviceInfo": "USB Device",
            "fileDetails": format!("File: {}, Extension: {}, Policy: {}", file_path, file_extension, policy_code),
            "severity": "HIGH",
            "actionTaken": "BLOCKED"
        });

        communicator
            .send_alert(&alert_data, token).await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })
    }

    async fn send_suspicious_file_alert(
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
        file_path: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let alert_data =
            serde_json::json!({
            "agentId": agent_id,
            "alertType": "SUSPICIOUS_FILE_DETECTED",
            "description": format!("Suspicious file detected on USB: {}", file_path),
            "deviceInfo": "USB Device",
            "fileDetails": format!("File: {}", file_path),
            "severity": "MEDIUM",
            "actionTaken": "DETECTED"
        });

        communicator
            .send_alert(&alert_data, token).await
            .map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::<dyn std::error::Error + Send + Sync>::from(e)
                }
            )
    }
}

// ===== PROTECTION MODULE IMPLEMENTATION =====

#[async_trait::async_trait]
impl ProtectionModule for USBProtection {
    /// Execute USB protection based on active policies
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Only run if any USB protection policy is active
        if policy_engine.is_usb_protection_enabled() {
            self.execute_monitoring(policy_engine, communicator, agent_id, token).await?;
        }
        Ok(())
    }

    /// Get module name
    fn get_name(&self) -> &str {
        "USB"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
