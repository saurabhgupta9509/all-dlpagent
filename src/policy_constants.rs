// policy_constants.rs
// Defines all policy codes as constants to ensure consistency between Rust and Java

// USB Protection Policies
pub const POLICY_USB_DEVICE_BLOCK: &str = "USB_DEVICE_BLOCK";
pub const POLICY_USB_DEVICE_MONITOR: &str = "USB_DEVICE_MONITOR";
// pub const POLICY_USB_BLOCK_EXECUTABLES: &str = "USB_BLOCK_EXECUTABLES";
// pub const POLICY_USB_DETECT_SUSPICIOUS: &str = "USB_DETECT_SUSPICIOUS";
// pub const POLICY_USB_SCAN_FILES: &str = "USB_SCAN_FILES";
// File Protection Policies  
// pub const POLICY_FILE_MONITOR_ACCESS: &str = "FILE_MONITOR_ACCESS";

// Network Protection Policies
pub const POLICY_NETWORK_DNS_BLOCK: &str = "NETWORK_DNS_BLOCK";

pub const FILE_PROTECTION_ENABLED: &str = "POLICY_FILE_PROTECTION";

// App Tracking Policies
pub const POLICY_APP_TRACKING: &str = "APP_TRACKING";

// Browser Monitoring Policies
pub const POLICY_BROWSER_MONITOR: &str = "BROWSER_URL_MONITOR";

// Partial Access Policies
pub const POLICY_PARTIAL_ACCESS: &str = "PARTIAL_ACCESS_CONTROL";
// src/policy_constants.rs
// pub const POLICY_WEB_URL_BLOCK: &str = "WEB_URL_BLOCK";
// pub const POLICY_WEB_UPLOAD_BLOCK: &str = "WEB_UPLOAD_BLOCK";
// pub const POLICY_WEB_DOWNLOAD_BLOCK: &str = "WEB_DOWNLOAD_BLOCK";
// pub const POLICY_WEB_MONITOR_HISTORY: &str = "WEB_MONITOR_HISTORY";


// --- Path-Based Blocking ---
// pub const FILE_BLOCK_CREATE_PATHS: &str = "block_paths_create";
// pub const FILE_BLOCK_READ_PATHS: &str = "block_paths_read";
// pub const FILE_BLOCK_WRITE_PATHS: &str = "block_paths_write";
// pub const FILE_BLOCK_DELETE_PATHS: &str = "block_paths_delete";
// pub const FILE_BLOCK_RENAME_PATHS: &str = "block_paths_rename";
// pub const FILE_BLOCK_COPY_PATHS: &str = "block_paths_copy";
// pub const FILE_BLOCK_MOVE_PATHS: &str = "block_paths_move";
// pub const FILE_BLOCK_OPEN_PATHS: &str = "block_paths_open";

// --- Extension-Based Blocking ---
// pub const FILE_BLOCK_CREATE_EXTENSIONS: &str = "block_extensions_create";
// pub const FILE_BLOCK_READ_EXTENSIONS: &str = "block_extensions_read";
// pub const FILE_BLOCK_WRITE_EXTENSIONS: &str = "block_extensions_write";
// pub const FILE_BLOCK_DELETE_EXTENSIONS: &str = "block_extensions_delete";
// pub const FILE_BLOCK_RENAME_EXTENSIONS: &str = "block_extensions_rename";
// pub const FILE_BLOCK_COPY_EXTENSIONS: &str = "block_extensions_copy";
// pub const FILE_BLOCK_MOVE_EXTENSIONS: &str = "block_extensions_move";
// pub const FILE_BLOCK_OPEN_EXTENSIONS: &str = "block_extensions_open";

// --- Read-Only Policies ---
// pub const FILE_READONLY_PATHS: &str = "readonly_paths";
// pub const FILE_READONLY_EXTENSIONS: &str = "readonly_extensions";

// --- Global Operation Blocking ---
// These policies block ALL operations of a type, everywhere.
// pub const FILE_BLOCK_CREATE_GLOBAL: &str = "block_create";
// pub const FILE_BLOCK_READ_GLOBAL: &str = "block_read";
// pub const FILE_BLOCK_WRITE_GLOBAL: &str = "block_write";
// pub const FILE_BLOCK_DELETE_GLOBAL: &str = "block_delete";
// pub const FILE_BLOCK_RENAME_GLOBAL: &str = "block_rename";
// pub const FILE_BLOCK_COPY_GLOBAL: &str = "block_copy";
// pub const FILE_BLOCK_MOVE_GLOBAL: &str = "block_move";
// pub const FILE_BLOCK_OPEN_GLOBAL: &str = "block_open";
