use core::fmt;
// src/protection_modules/dto.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebLog {
    pub url: String,
    pub browser: String,
    pub timestamp: String,
    pub action: String,
    pub blocked: bool,
    pub file_info: Option<String>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebHistoryRequest {
    pub agent_id: u64,
    pub logs: Vec<WebLog>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub policy_type: String,
    pub enabled: bool,
    pub block_list: Vec<String>,
    pub monitor_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Block,
    Audit, // Log but don't block
}

#[derive(Serialize, Deserialize, Debug , Clone)]
pub struct FileSystemItemDTO {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "fullPath")]
    pub full_path: String,

    #[serde(rename = "isDirectory")]
    pub is_directory: bool,

    #[serde(rename = "size")]
    pub size: u64,
}



#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileBrowseResponseDTO {
    pub agent_id: u64,
    pub current_path: String,
    pub parent_path: Option<String>,
    pub items: Vec<FileSystemItemDTO>,
    pub partial: bool,
    pub complete: bool,
    pub chunk_id: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppUsageData {
    pub device_id: String,
    pub timestamp: String,
    pub current_app: String,
    pub current_session_duration: f64,
    pub total_apps_tracked: u32,
    pub total_time_tracked: f64,
    pub active_usage_time: f64,
    pub top_apps: Vec<serde_json::Value>,
    pub category_breakdown: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UrlMonitoringData {
    pub device_id: String,
    pub timestamp: String,
    pub urls: Vec<String>,
    pub blocked_count: u32,
    pub suspicious_count: u32,
    pub total_visits: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessAttemptData {
    pub url: String,
    pub domain: String,
    #[serde(rename = "fileType")]
    pub file_type: String,
    pub blocked: bool,
    #[serde(rename = "monitorMode")]
    pub monitor_mode: String,
}
