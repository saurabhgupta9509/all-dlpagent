use crate::capabilities::PolicyCapability;
use crate::protection_modules::dto::{ FileBrowseResponseDTO, FileSystemItemDTO };
use crate::protection_modules::dto::{ WebHistoryRequest, WebLog };
// use crate::protection_modules::file_protection::FileEventRequest;
use crate::protection_modules::security_monitor::types::RealtimeUpdate;
use chrono::Utc;
use log::debug;
use log::error;
use log::warn;
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use network_interface::NetworkInterfaceConfig;

/// Response from authentication endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "agentId")]
    pub agent_id: u64,
    pub username: String,
    pub password: Option<String>,
    pub status: String,
    #[serde(rename = "userId")] // ✅ Optional: include both for compatibility
    pub user_id: Option<u64>,
    pub token: String,
}

/// Credentials stored for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub agent_id: u64,
    pub username: String,
    pub password: String,
    pub token: Option<String>,
}

/// Response from login endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(rename = "agentId")]
    pub agent_id: u64,
    pub username: String,
    pub role: String,
    pub token: String,
}

/// Response containing policies for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    #[serde(rename = "agentId")]
    pub agent_id: u64,
    pub policies: Vec<crate::policy_engine::Policy>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyUpdateRequest {
    pub agent_id: u64,
    pub capabilities: Vec<PolicyCapability>,
}

/// Standard API response format from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

#[derive(Debug, Serialize)]
pub struct WebHistoryDetailedRequest {
    pub agent_id: u64,
    pub url: String,
    pub browser: String,
    pub timestamp: String, // ISO format
    pub action: String,
    pub blocked: bool,
    pub file_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileBrowseRequest {
    pub agent_id: u64,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileBrowseResponse {
    pub items: Vec<FileSystemItem>,
    pub current_path: String,
    pub parent_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileSystemItem {
    pub name: String,
    pub full_path: String,
    pub is_directory: bool,
    pub size: u64,
    pub modified: Option<String>,
    pub extension: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathValidationRequest {
    pub agent_id: u64,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathValidationResponse {
    pub exists: bool,
    pub is_directory: bool,
    pub is_readable: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEventDTO {
    pub operation: String,
    pub file_path: String,
    pub file_extension: String,
    pub file_size: Option<u64>,
    pub process_name: String,
    pub process_id: u32,
    pub user_id: String,
    pub blocked: bool,
    pub reason: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEventRequest {
    pub agent_id: u64,
    pub events: Vec<FileEventDTO>,
}

/// Handles all HTTP communication with the backend server
#[derive(Clone)]
pub struct ServerCommunicator {
    client: reqwest::Client, // HTTP client for making requests
    base_url: String, // Base URL of the backend server
    pub credentials: Option<AgentCredentials>, // Agent credentials
}
#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(rename_all = "camelCase")]
// pub struct OcrStatusUpdate {
//     pub agent_id: u64,
//     pub ocr_enabled: bool,
//     pub last_screenshot_time: String,
//     pub threat_score: f32,
//     pub violations_last_24h: u32,
//     pub agent_hostname: String,
// }

// In your communication.rs or wherever OcrStatusUpdate is defined
pub struct OcrStatusUpdate {
    pub agent_id: u64,
    pub ocr_enabled: bool,
    pub last_screenshot_time: String,
    pub threat_score: f32,
    pub threat_arrow: String, // "↑", "↓", "→"
    pub trend_color: String, // "red", "green", "gray"
    pub violations_last_24h: u32,
    pub agent_hostname: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(rename_all = "camelCase")]
pub struct OcrLiveData {
    pub agent_id: u64,
    pub timestamp: String,
    pub screenshot_path: String,
    pub extracted_text: String,
    pub content_type: String,
    pub language: String,
    pub readability_score: f32,
    pub threat_score: f32,
    pub violation_count: u32,
    pub primary_context: String,
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(rename_all = "camelCase")]
pub struct OcrViolation {
    pub agent_id: u64,
    pub timestamp: String,

    #[serde(rename = "ruleType")]
    pub rule_type: String,

    #[serde(rename = "matchedText")]
    pub matched_text: String,

    #[serde(rename = "confidence")]
    pub confidence: f32,

    pub threat_score: f32,

    #[serde(rename = "contextConfidence")]
    pub context_confidence: f32,

    #[serde(rename = "screenshotPath")]
    pub screenshot_path: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(rename_all = "camelCase")]
pub struct SecurityCertificate {
    pub agent_id: u64,
    pub assessment_time: String,
    pub user_device: String,
    pub threat_level: String,
    pub threat_score: f32,
    pub total_violations: u32,
    pub primary_context: String,
    pub risk_analysis: String,
    pub immediate_actions: Vec<String>,
    // pub rule_breakdown: std::collections::HashMap<String, u32>,
    pub rule_breakdown: HashMap<String, u32>,
    pub emoji: String,
}

#[derive(Debug, Serialize)]
// #[serde(rename_all = "camelCase")]
pub struct OcrAgentRegistration {
    pub agent_id: u64,
    pub hostname: String,
    pub ocr_enabled: bool,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentHeartbeatPayload {
    pub agent_id: u64,
    pub runtime_state: String, // ONLINE | IDLE | LOCKED
    pub ocr_active: bool,
    pub screen_locked: bool,
    pub timestamp: String,
}

#[derive(Serialize)]
struct CertificateWithViolationsRequest<'a> {
    certificate: &'a SecurityCertificate,
    violationIds: &'a Vec<u64>,
}

impl ServerCommunicator {
    /// Create a new ServerCommunicator with default settings
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client
                ::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.to_string(),
            credentials: None,
        }
    }

    //  fn get_local_ip(&self) -> String {
    //     match network_interface::NetworkInterface::show() {
    //         Ok(interfaces) => {
    //             for interface in interfaces {
    //                 for addr in interface.addr {
    //                     match addr {
    //                         network_interface::Addr::V4(v4_addr) => {
    //                             let ip = v4_addr.ip;
    //                             if !ip.is_loopback() && !ip.is_link_local() {
    //                                 return ip.to_string();
    //                             }
    //                         }
    //                         network_interface::Addr::V6(_) => {}
    //                     }
    //                 }
    //             }
    //             "127.0.0.1".to_string()
    //         }
    //         Err(_) => "127.0.0.1".to_string(),
    //     }
    // }
    fn get_local_ip(&self) -> String {
        match network_interface::NetworkInterface::show() {
            Ok(interfaces) => {
                println!("\n=== Smart IP Detection ===");

                // Strategy 1: Look for IP in the 192.168.1.x range (your home network)
                for interface in &interfaces {
                    for addr in &interface.addr {
                        match addr {
                            network_interface::Addr::V4(v4_addr) => {
                                let ip = v4_addr.ip;
                                let octets = ip.octets();

                                // Your home WiFi is 192.168.1.119
                                // Look for 192.168.1.x range
                                if octets[0] == 192 && octets[1] == 168 && octets[2] == 1 {
                                    println!(
                                        "✓ Found home network IP: {} on '{}'",
                                        ip,
                                        interface.name
                                    );
                                    return ip.to_string();
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Strategy 2: Skip VMware ranges (192.168.23.x, 192.168.19.x)
                for interface in &interfaces {
                    let lower_name = interface.name.to_lowercase();

                    // Skip VMware adapters by name
                    if lower_name.contains("vmware") || lower_name.contains("vmnet") {
                        println!("✗ Skipping VMware adapter: {}", interface.name);
                        continue;
                    }

                    for addr in &interface.addr {
                        match addr {
                            network_interface::Addr::V4(v4_addr) => {
                                let ip = v4_addr.ip;
                                let octets = ip.octets();

                                // Skip loopback, link-local, and VMware ranges
                                if !ip.is_loopback() && !ip.is_link_local() {
                                    // Check if it's a VMware IP range
                                    let is_vmware_ip =
                                        octets[0] == 192 &&
                                        octets[1] == 168 &&
                                        (octets[2] == 23 || octets[2] == 19);

                                    if !is_vmware_ip {
                                        println!("✓ Selected IP: {} from '{}'", ip, interface.name);
                                        return ip.to_string();
                                    } else {
                                        println!("✗ Skipping VMware IP: {}", ip);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                println!("⚠️ No suitable IP found");
                "127.0.0.1".to_string()
            }
            Err(_) => "127.0.0.1".to_string(),
        }
    }

    fn prepare_auth_header(token: &str) -> String {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return "Bearer ".to_string();
        }
        if trimmed.starts_with("Bearer ") {
            trimmed.to_string()
        } else {
            format!("Bearer {}", trimmed)
        }
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.client
    }

    pub async fn send_realtime_update(
        &self,
        agent_id: u64,
        token: &str,
        update: &RealtimeUpdate
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/{}/security-monitor/realtime", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self
            .http()
            .post(&url)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .json(update)
            .send().await?;

        if !response.status().is_success() {
            return Err(
                format!("Failed to send real-time update: HTTP {}", response.status()).into()
            );
        }

        Ok(())
    }
    pub async fn send_ocr_live_data(
        &self,
        agent_id: u64,
        token: &str,
        live_data: &OcrLiveData
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/ocr/live", self.base_url);
        // let url = format!("{}/api/agent/{}/ocr/live", self.base_url , agent_id);

        let auth_header = Self::prepare_auth_header(token);

        let response = self.client
            .post(&url)
            // .bearer_auth(token)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .json(live_data)
            .send().await?;

        if response.status().is_success() {
            log::debug!("✅ OCR live data sent successfully");
            Ok(())
        } else {
            let body = response.text().await?;
            Err(format!("Failed to send OCR live data: {}", body).into())
        }
    }
    pub async fn send_ocr_status(
        &self,
        agent_id: u64,
        token: &str,
        status: &OcrStatusUpdate
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/ocr/status", self.base_url);
        // let url = format!("{}/api/agent/{}/ocr/status", self.base_url , agent_id);

        log::info!("📤 [OCR] POST to {} with token: {}...", url, &token[..10]);
        log::debug!("[OCR] Request body: {:?}", status);

        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            // .bearer_auth(token)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .json(status)
            .send().await?;

        if response.status().is_success() {
            println!("✅ OCR status sent successfully {}", agent_id);
            Ok(())
        } else {
            let body = response.text().await?;
            log::error!("❌ [OCR] Failed to send status: HTTP {}", body);
            Err(format!("Failed to send OCR status: {}", body).into())
        }
    }

    pub async fn send_ocr_violation(
        &self,
        agent_id: u64,
        token: &str,
        violation: &OcrViolation
    ) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/ocr/violation", self.base_url);
        // let url = format!("{}/api/agent/{}/ocr/violation", self.base_url , agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            // .bearer_auth(token)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .json(violation)
            .send().await?;

        if response.status().is_success() {
            println!("✅ OCR violation sent successfully {}", agent_id);

            let status = response.status();

            let body = response.text().await?;
            // if !status.is_success() {
            //     return Err(format!("Failed OCR violation: {}", body).into());
            // }
            // Parse saved object
            let api_response: ApiResponse<serde_json::Value> = serde_json::from_str(&body)?;

            let saved_id = api_response.data
                .as_ref()
                .and_then(|d| d.get("id"))
                .and_then(|id| id.as_u64())
                .ok_or("Missing id in response")?;

            Ok(saved_id)
        } else {
            let body = response.text().await?;
            Err(format!("Failed to send OCR violation: {}", body).into())
        }
    }

    /// Send OCR high threat alert (threat score ≥ 70)
    /// Send OCR high threat alert (threat score ≥ 70)
    pub async fn send_ocr_high_threat_alert(
        &self,
        agent_id: u64,
        token: &str,
        violation: &OcrViolation,
        hostname: &str,
        username: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/alerts", self.base_url);
        let auth_header = Self::prepare_auth_header(token);

        // Determine severity based on threat score
        let severity = if violation.threat_score >= 90.0 {
            "CRITICAL"
        } else if violation.threat_score >= 80.0 {
            "HIGH"
        } else {
            "MEDIUM"
        };

        let alert_data =
            serde_json::json!({
        "agentId": agent_id,
        "agentHostname": hostname,
        "alertType": "OCR_HIGH_THREAT",
        "description": format!("OCR High Threat Detection - Score: {:.1} - Type: {}", 
                               violation.threat_score, violation.rule_type),
        "deviceInfo": format!("Rule: {}, Confidence: {:.1}%", 
                             violation.rule_type, 
                             violation.confidence * 100.0),
        "fileDetails": format!("Matched Text: {}, Screenshot: {}", 
                              if violation.matched_text.len() > 100 {
                                  format!("{}...", &violation.matched_text[..100])
                              } else {
                                  violation.matched_text.clone()
                              },
                              violation.screenshot_path),
        "severity": severity,
        "actionTaken": "DETECTED",
        "timestamp": Utc::now().to_rfc3339(),
    });

        log::info!(
            "🚨 Sending OCR high threat alert for agent {}: Score {:.1}, Type {}",
            agent_id,
            violation.threat_score,
            violation.rule_type
        );

        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .json(&alert_data)
            .send().await?;

        if response.status().is_success() {
            log::info!("✅ OCR high threat alert sent successfully");
            Ok(())
        } else {
            let body = response.text().await?;
            log::error!("❌ Failed to send OCR high threat alert: {}", body);
            Err(format!("Failed to send OCR high threat alert: {}", body).into())
        }
    }

    pub async fn send_ocr_certificate(
        &self,
        agent_id: u64,
        token: &str,
        certificate: &SecurityCertificate,
        violation_ids: &Vec<u64>
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/ocr/certificate", self.base_url);
        // let url = format!("{}/api/agent/{}/ocr/certificate", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        // Build wrapper body expected by backend
        let body =
            serde_json::json!({
            "certificate": certificate,
            "violationIds": violation_ids
        });

        let response = self.client
            .post(&url)
            // .bearer_auth(token)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .json(&body)
            .send().await?;

        if response.status().is_success() {
            println!("✅ OCR certificate sent successfully");
            Ok(())
        } else {
            let body = response.text().await?;
            Err(format!("Failed to send OCR certificate: {}", body).into())
        }
    }

    pub async fn get_security_monitor_status(
        &self,
        agent_id: u64,
        token: &str
    ) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
        // let url = format!("{}/api/agent/{}/security-monitor/status", self.base_url, agent_id);
        let url = format!("{}/api/agent/{}/security-monitor/status", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self
            .http()
            .get(&url)
            // .header("Authorization", format!("Bearer {}", token))
            .header("Authorization", auth_header)
            .send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(format!("Failed to get status: HTTP {}", response.status()).into())
        }
    }

    // pub async fn send_file_browse_response(
    //     &self,
    //     browse: FileBrowseResponse,
    //     token: &str,
    //     agent_id: u64,
    // ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     let items: Vec<FileSystemItemDTO> = browse
    //         .items
    //         .into_iter()
    //         .map(|i| FileSystemItemDTO {
    //             name: i.name,
    //             full_path: i.full_path,
    //             is_directory: i.is_directory,
    //             size: i.size,
    //         })
    //         .collect();

    //     let response = FileBrowseResponseDTO {
    //         agent_id,
    //         current_path: browse.current_path,
    //         parent_path: browse.parent_path,
    //         items,
    //     };

    //     let json_body = serde_json::to_string(&response)?;

    //     log::info!("📤 Sending browse response to backend...");

    //     let url = format!("{}/api/agent/file-browse-response", self.base_url);

    //     // ❗ FIXED: Always send Bearer <token>
    //     let resp = self
    //         .client
    //         .post(&url)
    //         .header("Authorization", format!("Bearer {}", token))
    //         .header("Content-Type", "application/json")
    //         .body(json_body.clone())
    //         .send()
    //         .await?;

    //     if !resp.status().is_success() {
    //         let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
    //         log::error!("❌ Failed to send browse response: {}", body);
    //     } else {
    //         log::info!("📁 File browse response sent successfully");
    //     }

    //     Ok(())
    // }

    pub async fn send_file_browse_response_chunked(
        &self,
        agent_id: u64,
        current_path: String,
        parent_path: Option<String>,
        items: Vec<FileSystemItemDTO>,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let chunk_size = 200;
        let mut chunk_id = 0;

        for chunk in items.chunks(chunk_size) {
            let dto = FileBrowseResponseDTO {
                agent_id,
                current_path: current_path.clone(),
                parent_path: parent_path.clone(),
                items: chunk.to_vec(),
                partial: true,
                complete: false,
                chunk_id: Some(chunk_id),
            };

            let url = format!("{}/api/agent/file-browse-response", self.base_url);

            let resp = self.client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&dto)
                .send().await?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                log::error!("❌ Failed chunk {}: {}", chunk_id, body);
            }

            chunk_id += 1;
        }

        // ---- Final completion message ----
        let dto = FileBrowseResponseDTO {
            agent_id,
            current_path,
            parent_path,
            items: vec![],
            partial: false,
            complete: true,
            chunk_id: None,
        };

        let url = format!("{}/api/agent/file-browse-response", self.base_url);
        let resp = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&dto)
            .send().await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            log::error!("❌ Final chunk failed: {}", body);
        } else {
            log::info!("📁 All browse chunks sent successfully");
        }

        Ok(())
    }

    pub async fn handle_file_browse_request(
        &self,
        path: Option<String>
    ) -> Result<FileBrowseResponse, Box<dyn std::error::Error + Send + Sync>> {
        let target_path = if let Some(p) = path {
            if p.trim().is_empty() {
                if cfg!(target_os = "windows") { PathBuf::from("C:\\") } else { PathBuf::from("/") }
            } else {
                PathBuf::from(p)
            }
        } else {
            if cfg!(target_os = "windows") { PathBuf::from("C:\\") } else { PathBuf::from("/") }
        };
        let items = self.list_directory(&target_path).await?;
        let parent_path = target_path.parent().map(|p| p.to_string_lossy().to_string());

        Ok(FileBrowseResponse {
            items,
            current_path: target_path.to_string_lossy().to_string(),
            parent_path,
        })
    }

    async fn list_directory(
        &self,
        path: &PathBuf
    ) -> Result<Vec<FileSystemItem>, Box<dyn std::error::Error + Send + Sync>> {
        let mut items = Vec::new();

        // On Windows, if we're at root, show drives
        if
            cfg!(target_os = "windows") &&
            (path.to_string_lossy() == "C:\\" || path.to_string_lossy() == "/")
        {
            return self.list_windows_drives().await;
        }

        if path.exists() && path.is_dir() {
            let mut entries = fs::read_dir(path).await?;

            while let Some(entry) = entries.next_entry().await? {
                let metadata = entry.metadata().await.ok();
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy().to_string();
                let full_path = entry.path().to_string_lossy().to_string();
                let is_directory = metadata
                    .as_ref()
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                let size = metadata
                    .as_ref()
                    .map(|m| m.len())
                    .unwrap_or(0);

                let extension = if !is_directory {
                    entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|s| s.to_lowercase())
                } else {
                    None
                };

                let modified = metadata.and_then(|m| {
                    m.modified()
                        .ok()
                        .map(|t| {
                            let datetime: chrono::DateTime<chrono::Utc> = t.into();
                            datetime.to_rfc3339()
                        })
                });

                items.push(FileSystemItem {
                    name,
                    full_path,
                    is_directory,
                    size,
                    modified,
                    extension,
                });
            }

            // Sort: directories first, then by name
            items.sort_by(|a, b| {
                if a.is_directory && !b.is_directory {
                    std::cmp::Ordering::Less
                } else if !a.is_directory && b.is_directory {
                    std::cmp::Ordering::Greater
                } else {
                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                }
            });
        }

        Ok(items)
    }

    async fn list_windows_drives(
        &self
    ) -> Result<Vec<FileSystemItem>, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::process::Command;
        let mut drives = Vec::new();

        // Try using wmic first for detailed drive info
        if
            let Ok(output) = Command::new("wmic")
                .args(&["logicaldisk", "get", "name,size", "/format:csv"])
                .output().await
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines().skip(1) {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 3 {
                        let drive_letter = parts[2].trim();
                        if !drive_letter.is_empty() {
                            let size_str = parts.get(3).unwrap_or(&"0");
                            let size = size_str.parse::<u64>().unwrap_or(0);

                            drives.push(FileSystemItem {
                                name: format!("{} Drive", drive_letter),
                                full_path: drive_letter.to_string(),
                                is_directory: true,
                                size,
                                modified: None,
                                extension: None,
                            });
                        }
                    }
                }
            }
        }

        // Fallback: check common drives
        if drives.is_empty() {
            for drive in &['C', 'D', 'E', 'F', 'G', 'H'] {
                let drive_path = format!("{}:\\", drive);
                let path_buf = PathBuf::from(&drive_path);

                if path_buf.exists() {
                    let metadata = fs::metadata(&path_buf).await.ok();
                    let size = metadata
                        .as_ref()
                        .map(|m| m.len())
                        .unwrap_or(0);

                    drives.push(FileSystemItem {
                        name: format!("{} Drive", drive_path),
                        full_path: drive_path,
                        is_directory: true,
                        size,
                        modified: None,
                        extension: None,
                    });
                }
            }
        }

        Ok(drives)
    }

    /// Handle path validation request from admin
    pub async fn handle_path_validation_request(
        &self,
        path: &str
    ) -> Result<PathValidationResponse, Box<dyn std::error::Error + Send + Sync>> {
        let path_buf = PathBuf::from(path);

        let exists = path_buf.exists();
        let is_directory = exists && path_buf.is_dir();
        let is_readable = exists && fs::metadata(&path_buf).await.is_ok();
        let size = if exists && !is_directory {
            fs::metadata(&path_buf).await
                .ok()
                .map(|m| m.len())
        } else {
            None
        };

        Ok(PathValidationResponse {
            exists,
            is_directory,
            is_readable,
            size,
        })
    }

    // New method to get file metadata
    pub async fn get_file_metadata(
        &self,
        path: &str
    ) -> Result<FileSystemItem, Box<dyn std::error::Error + Send + Sync>> {
        let path_buf = PathBuf::from(path);
        let metadata = fs::metadata(&path_buf).await?;

        let name = path_buf
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let is_directory = metadata.is_dir();
        let size = metadata.len();

        let extension = if !is_directory {
            path_buf
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|s| s.to_lowercase())
        } else {
            None
        };

        let modified = metadata
            .modified()
            .ok()
            .map(|t| {
                let datetime: chrono::DateTime<chrono::Utc> = t.into();
                datetime.to_rfc3339()
            });

        Ok(FileSystemItem {
            name,
            full_path: path_buf.to_string_lossy().to_string(),
            is_directory,
            size,
            modified,
            extension,
        })
    }

    pub async fn get_file_policies(
        &self,
        agent_id: u64,
        token: &str
    ) -> Result<HashMap<String, Vec<String>>, Box<dyn std::error::Error + Send + Sync>> {
        // Updated to match AgentController.java: @GetMapping("/file-policies/{agentId}")
        let url = format!("{}/api/agent/file-policies/{}", self.base_url, agent_id);
        
        log::info!("🔍 Fetching file policies from: {}", url);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .get(&url)
            .header("Authorization", auth_header)
            .send().await?;
        let status = response.status();
        if status.is_success() {
            // Read body as text first for debugging
            let body_text = response.text().await?;
            log::info!("[FILE-POLICIES] Raw server response: {}", body_text);

            // Parse the ApiResponse<Map<String, List<String>>>
            let api_response: ApiResponse<HashMap<String, Vec<String>>> = serde_json::from_str(&body_text)?;
            if api_response.success {
                let data = api_response.data.unwrap_or_default();
                log::info!("[FILE-POLICIES] Parsed {} categories: {:?}", data.len(), data.keys().collect::<Vec<_>>());
                Ok(data)
            } else {
                log::warn!("[FILE-POLICIES] Server returned success=false: {}", api_response.message);
                Ok(HashMap::new())
            }
        } else {
            let body_text = response.text().await.unwrap_or_default();
            log::error!("[FILE-POLICIES] HTTP {} from {}: {}", status, url, body_text);
            Ok(HashMap::new())
        }
    }

    /// NEW: This function sends the batched file events to the backend.
    pub async fn send_file_events(
        &self,
        request: &FileEventRequest,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/agent/file-events", self.base_url);

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(request)
            .send().await?;
        let status = response.status();
        if status.is_success() {
            debug!("📤 File events batch sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to send file events batch: HTTP {} - {}", status, error_text);
            Err(format!("HTTP {}: {}", status, error_text).into())
        }
    }
    pub async fn send_web_history_detailed(
        &self,
        web_log: WebLog
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (agent_id, token) = match &self.credentials {
            Some(creds) => {
                let token = creds.token.clone().ok_or("No session token available")?;
                (creds.agent_id, token)
            }
            None => {
                return Err("No credentials available".into());
            }
        };

        let url = format!("{}/api/agent/web-history-detailed", self.base_url);

        let payload =
            serde_json::json!({
            "agentId": agent_id,
            "url": web_log.url,
            "browser": web_log.browser,
            "timestamp": web_log.timestamp,
            "action": web_log.action,
            "blocked": web_log.blocked,
            "fileInfo": web_log.file_info
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send().await?;

        // Check status BEFORE consuming the response body
        let status = response.status();
        if status.is_success() {
            debug!("✅ Web history sent: {} - {}", web_log.action, web_log.url);
            Ok(())
        } else {
            // Now we can safely consume the body
            let error_body = response.text().await?;
            error!("❌ Failed to send web history: HTTP {} - {}", status, error_body);
            Err(format!("HTTP {}: {}", status, error_body).into())
        }
    }

    // ===== AUTHENTICATION METHODS =====
    /// Register agent with the backend server
    pub async fn agent_register(
        &mut self,
        hostname: &str,
        mac_address: &str,
        ip_address: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/register", self.base_url);

        log::info!("🔐 Registering agent with server...");

        let auth_data =
            serde_json::json!({
            "hostname": hostname,
            "macAddress": mac_address,
            "ipAddress": ip_address,
        });

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&auth_data)
            .send().await?;

        let raw_response = response.text().await?;
        log::debug!("Raw registration response: {}", raw_response);

        match serde_json::from_str::<ApiResponse<AuthResponse>>(&raw_response) {
            Ok(api_response) => {
                if api_response.success {
                    if let Some(data) = api_response.data {
                        let password = data.password.unwrap_or_else(|| {
                            log::warn!("Password is null, generating fallback");
                            "default_password".to_string()
                        });

                        self.credentials = Some(AgentCredentials {
                            agent_id: data.agent_id,
                            username: data.username.clone(),
                            password: password.clone(),
                            token: None,
                        });

                        log::info!(
                            "🔐 Credentials stored - Username: {}, Password: {}",
                            data.username,
                            password
                        );
                        return Ok(());
                    }
                }
                Err(format!("Registration failed: {}", api_response.message).into())
            }
            Err(e) => {
                log::error!("Failed to parse registration response: {}", e);
                log::error!("Response was: {}", raw_response);
                Err(format!("Invalid server response: {}", e).into())
            }
        }
    }

    /// Login agent with credentials
    pub async fn agent_login(
        &mut self,
        hostname: Option<&str>,
        mac_address: Option<&str>, // This exists
        ip_address: Option<&str>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/login", self.base_url);

        if let Some(creds) = &self.credentials {
            //    let hostname = hostname.map(|s| s.to_string())
            //     .unwrap_or_else(|| whoami::hostname());
            let hostname = whoami::devicename();
            let mac_address = mac_address
                .map(|s| s.to_string())
                .unwrap_or_else(|| "00:11:22:33:44:55".to_string());
            let ip_addr = ip_address.map(|s| s.to_string()).unwrap_or_else(|| self.get_local_ip());

            let auth_data =
                serde_json::json!({
                "username": creds.username,
                "password": creds.password,
                "hostname": hostname,
                "macAddress": mac_address,
                "ipAddress": ip_addr
            });

            let response = self.client
                .post(&url)
                // .header("Content-Type", "application/json")
                .json(&auth_data)
                .send().await?;

            let status = response.status();
            log::debug!("Login response status: {}", status);

            let raw_response = response.text().await?;
            log::debug!("Raw login response: {}", raw_response);

            if status.is_success() {
                // ✅ First try parsing with the new structure (agentId)
                match serde_json::from_str::<ApiResponse<AuthResponse>>(&raw_response) {
                    Ok(api_response) => {
                        if api_response.success {
                            if let Some(data) = api_response.data {
                                if let Some(mut creds) = self.credentials.take() {
                                    creds.agent_id = data.agent_id;
                                    creds.token = Some(data.token);
                                    self.credentials = Some(creds);
                                }

                                log::info!(
                                    "✅ Agent logged in successfully! Agent ID: {}",
                                    data.agent_id
                                );
                                return Ok(());
                            }
                        } else {
                            log::error!(
                                "Login API returned success=false: {}",
                                api_response.message
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to parse with AuthResponse, trying alternative parsing: {}",
                            e
                        );
                        // ✅ Fallback: Try alternative parsing if needed
                        self.try_alternative_login_parsing(&raw_response).await?;
                    }
                }
            } else {
                log::error!("Login HTTP error: {}", status);
                log::error!("Response body: {}", raw_response);
            }
        } else {
            log::error!("No credentials available for login");
        }

        Err("Agent login failed - check credentials and server response".into())
    }

    pub async fn agent_login_with_info(
        &mut self,
        hostname: &str,
        mac_address: &str,
        ip_address: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/login", self.base_url);
        // DEBUG: Check what IP we're receiving
        println!("🔍 DEBUG in agent_login_with_info: Received IP parameter: {}", ip_address);
        if let Some(creds) = &self.credentials {
            let auth_data =
                serde_json::json!({
                "username": creds.username,
                "password": creds.password,
                "hostname": hostname,        // ← CORRECT
                "macAddress": mac_address,   // ← CORRECT  
                "ipAddress": ip_address   
            });

            let response = self.client
                .post(&url)
                // .header("Content-Type", "application/json")
                .json(&auth_data)
                .send().await?;

            let status = response.status();
            log::debug!("Login response status: {}", status);

            let raw_response = response.text().await?;
            log::debug!("Raw login response: {}", raw_response);

            if status.is_success() {
                // ✅ First try parsing with the new structure (agentId)
                match serde_json::from_str::<ApiResponse<AuthResponse>>(&raw_response) {
                    Ok(api_response) => {
                        if api_response.success {
                            if let Some(data) = api_response.data {
                                if let Some(mut creds) = self.credentials.take() {
                                    creds.agent_id = data.agent_id;
                                    creds.token = Some(data.token);
                                    self.credentials = Some(creds);
                                }

                                log::info!(
                                    "✅ Agent logged in successfully! Agent ID: {}",
                                    data.agent_id
                                );
                                return Ok(());
                            }
                        } else {
                            log::error!(
                                "Login API returned success=false: {}",
                                api_response.message
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to parse with AuthResponse, trying alternative parsing: {}",
                            e
                        );
                        // ✅ Fallback: Try alternative parsing if needed
                        self.try_alternative_login_parsing(&raw_response).await?;
                    }
                }
            } else {
                log::error!("Login HTTP error: {}", status);
                log::error!("Response body: {}", raw_response);
            }
        } else {
            log::error!("No credentials available for login");
        }

        Err("Agent login failed - check credentials and server response".into())
    }

    async fn try_alternative_login_parsing(
        &mut self,
        raw_response: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try to manually extract fields from JSON
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(raw_response) {
            if let Some(data) = json_value.get("data") {
                if
                    let (Some(agent_id), Some(token)) = (
                        data.get("agentId").and_then(|v| v.as_u64()),
                        data.get("token").and_then(|v| v.as_str()),
                    )
                {
                    if let Some(mut creds) = self.credentials.take() {
                        creds.agent_id = agent_id;
                        creds.token = Some(token.to_string());
                        self.credentials = Some(creds);
                        log::info!(
                            "✅ Agent logged in via alternative parsing! Agent ID: {}",
                            agent_id
                        );
                        return Ok(());
                    }
                }
            }
        }

        Err("Alternative login parsing failed".into())
    }

    // ===== POLICY MANAGEMENT METHODS =====

    /// Report agent capabilities to backend.
    ///
    /// Sends a flat list of PolicyCapabilityDTO objects. Each capability includes
    /// `isActive` and `policyData` so the backend can persist and group them.
    /// The backend's /api/admin/agents/{id}/capabilities endpoint handles grouping.
    pub async fn report_capabilities(
        &self,
        agent_id: u64,
        token: &str,
        capabilities: &[PolicyCapability]
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/agent/capabilities", self.base_url);

        let request_data = serde_json::json!({
            "agentId": agent_id,
            "capabilities": capabilities
        });
        log::info!("[CAPS] Reporting {} capabilities to backend for agent {}...", capabilities.len(), agent_id);
        log::debug!("Capabilities payload: {}", serde_json::to_string_pretty(&request_data).unwrap_or_default());

        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .json(&request_data)
            .send().await?;

        if response.status().is_success() {
            log::info!("[OK] Capabilities reported successfully");
            Ok(())
        } else {
            let error_text = response.text().await?;
            log::error!("[ERR] Failed to report capabilities: {}", error_text);
            Err(format!("Failed to report capabilities: {}", error_text).into())
        }
    }

    /// Get active policies assigned to this agent
    pub async fn get_active_policies(
        &self,
        agent_id: u64,
        token: &str
    ) -> Result<Vec<crate::policy_engine::Policy>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/agent/active-policies?agentId={}", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.get(&url).header("Authorization", auth_header).send().await?;

        if response.status().is_success() {
            let api_response: ApiResponse<PolicyResponse> = response.json().await?;
            if api_response.success {
                if let Some(data) = api_response.data {
                    log::info!("📋 Received {} active policies from backend", data.policies.len());
                    // Debug: print FILE category policies and their policyData
                    for p in &data.policies {
                        if p.category == "FILE" {
                            log::info!("[ACTIVE-POLICY] FILE policy: code={}, isActive={}, policyData={:?}",
                                p.code, p.is_active, p.policy_data);
                        }
                    }
                    return Ok(data.policies);
                }
            }
        }

        log::warn!("⚠️ No active policies received from backend");
        Ok(vec![]) // Return empty if no policies
    }

    /// Get all agent policies (legacy method)
    pub async fn get_agent_policies(
        &self
    ) -> Result<Vec<crate::policy_engine::Policy>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/policies", self.base_url);

        if let Some(creds) = &self.credentials {
            if let Some(token) = &creds.token {
                let auth_header = Self::prepare_auth_header(token);
                let response = self.client.get(&url).header("Authorization", auth_header).send().await?;

                if response.status().is_success() {
                    let api_response: ApiResponse<PolicyResponse> = response.json().await?;
                    if api_response.success {
                        if let Some(data) = api_response.data {
                            log::info!("✅ Retrieved {} policies", data.policies.len());
                            return Ok(data.policies);
                        }
                    }
                    Err(format!("Failed to get policies: {}", api_response.message).into())
                } else {
                    Err(format!("HTTP {}: Failed to get policies", response.status()).into())
                }
            } else {
                Err("No session token available - agent not logged in".into())
            }
        } else {
            Err("No credentials available - agent not registered".into())
        }
    }

    // ===== AGENT OPERATIONS =====

    /// Send heartbeat to backend
    pub async fn send_heartbeat(
        &self,
        agent_id: u64,
        token: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/heartbeat?agentId={}", self.base_url, agent_id);

        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .send().await?;

        if response.status().is_success() {
            log::debug!("💓 Heartbeat sent successfully");
            Ok(())
        } else {
            Err(format!("HTTP {}: Heartbeat failed", response.status()).into())
        }
    }

    /// Poll backend for pending commands for this agent
    pub async fn get_commands(
        &self,
        agent_id: u64,
        token: &str
    ) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
        let url = format!("{}/api/agent/commands/{}", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .get(&url)
            .header("Authorization", auth_header)
            .send().await?;

        if response.status().is_success() {
            let body: serde_json::Value = response.json().await?;
            Ok(body)
        } else {
            log::warn!("⚠️ Command API returned status: {}", response.status());
            Ok(serde_json::Value::Null) // Return null instead of error for resilience
        }
    }

    /// Send alert to backend
    pub async fn send_alert(
        &self,
        alert_data: &serde_json::Value,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/agent/alerts", self.base_url);

        println!("DEBUG: Sending alert to: {}", url); // ← ADD THIS
        println!("DEBUG: Alert data: {}", alert_data); // ← ADD THIS

        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .json(alert_data)
            .send().await?;

        if response.status().is_success() {
            log::debug!("📤 Alert sent successfully");
            log::info!("✅ Alert saved to backend");
            Ok(())
        } else {
            Err(format!("HTTP {}: Alert sending failed", response.status()).into())
        }
    }

    /// Send USB-specific alert to backend
    pub async fn send_usb_alert(
        &self,
        usb_alert_data: &serde_json::Value,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/agent/usb-alert", self.base_url);

        let auth_header = Self::prepare_auth_header(token);
        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .json(usb_alert_data)
            .send().await?;

        if response.status().is_success() {
            log::info!("📤 USB alert sent successfully");
            Ok(())
        } else {
            Err(format!("HTTP {}: USB alert sending failed", response.status()).into())
        }
    }
    // === WEB ALERT METHOD =====
    pub async fn send_web_alert(
        &self,
        alert_type: &str,
        details: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Ensure we have credentials and a token
        let (agent_id, token) = match &self.credentials {
            Some(creds) => {
                let token = creds.token
                    .clone()
                    .ok_or("No session token available in communicator.credentials")?;
                (creds.agent_id, token)
            }
            None => {
                return Err("No credentials available - cannot send web alert".into());
            }
        };

        let url = format!("{}/api/agent/web-alerts", self.base_url);

        let payload =
            serde_json::json!({
            "type": alert_type,
            "details": details,
            "agentId": agent_id,
            "timestamp": Utc::now().to_rfc3339(),
        });

        log::debug!("Sending web alert to {}: {:?}", url, payload);

        let resp = self.client.post(&url).bearer_auth(token).json(&payload).send().await?;

        let status = resp.status(); // ✅ store before consuming
        let body = resp.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());

        if status.is_success() {
            log::info!("📤 Web alert sent successfully: {} - {}", alert_type, details);
            Ok(())
        } else {
            log::error!("Failed to send web alert (HTTP {}): {}", status, body);
            Err(format!("Failed to send web alert: HTTP {}: {}", status, body).into())
        }
    }

    pub async fn queue_url_visit(&self, url_visit: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (agent_id, token) = match &self.credentials {
            Some(creds) => {
                let token = creds.token
                    .clone()
                    .ok_or("No session token available in communicator.credentials")?;
                (creds.agent_id, token)
            }
            None => {
                return Err("No credentials available - cannot send url visit".into());
            }
        };

        let url = format!("{}/api/agent/web-visits", self.base_url);

        let payload =
            serde_json::json!({
            "url": url_visit,
            "agentId": agent_id,
            "timestamp": Utc::now().to_rfc3339(),
        });

        log::debug!("Queueing URL visit to {}: {}", url, url_visit);

        let resp = self.client.post(&url).bearer_auth(token).json(&payload).send().await?;

        let status = resp.status(); // ✅ store status before text()
        let body = resp.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());

        if status.is_success() {
            log::debug!("✅ URL visit sent: {}", url_visit);
            Ok(())
        } else {
            log::warn!("Failed to send URL visit (HTTP {}): {}", status, body);
            Err(format!("Failed to send URL visit: HTTP {}: {}", status, body).into())
        }
    }

    pub async fn upload_app_usage(
        &self,
        data: crate::protection_modules::dto::AppUsageData,
        token: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let agent_id = data.device_id.clone();
        let url = format!("{}/api/python-client/devices/{}/app-usage", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.post(&url).header("Authorization", auth_header).json(&data).send().await?;
        let status = response.status();
        if status.is_success() {
            log::info!("📤 App usage uploaded successfully for agent {}", agent_id);
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(format!("Failed to upload app usage: HTTP {} - {}", status, body).into())
        }
    }

    pub async fn upload_urls(
        &self,
        data: crate::protection_modules::dto::UrlMonitoringData,
        token: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let agent_id = data.device_id.clone();
        let url = format!("{}/api/python-client/devices/{}/urls", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.post(&url).header("Authorization", auth_header).json(&data).send().await?;
        let status = response.status();
        if status.is_success() {
            log::info!("📤 URL data uploaded successfully for agent {}", agent_id);
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(format!("Failed to upload URLs: HTTP {} - {}", status, body).into())
        }
    }

    pub async fn get_blocked_urls(&self, token: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let (agent_id, _) = match &self.credentials {
            Some(creds) => (creds.agent_id, creds.token.as_deref().unwrap_or("")),
            None => return Err("No credentials available".into()),
        };
        let url = format!("{}/api/python-client/devices/{}/blocked-urls", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.get(&url).header("Authorization", auth_header).send().await?;
        let status = response.status();
        if status.is_success() {
            let api_response: ApiResponse<Vec<String>> = response.json().await?;
            Ok(api_response.data.unwrap_or_default())
        } else {
            Err(format!("Failed to get blocked URLs: HTTP {}", status).into())
        }
    }

    pub async fn get_partial_access_config(&self, token: &str) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
        let (agent_id, _) = match &self.credentials {
            Some(creds) => (creds.agent_id, creds.token.as_deref().unwrap_or("")),
            None => return Err("No credentials available".into()),
        };
        let url = format!("{}/api/python-client/devices/{}/partial-access", self.base_url, agent_id);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.get(&url).header("Authorization", auth_header).send().await?;
        let status = response.status();
        if status.is_success() {
            let api_response: ApiResponse<serde_json::Value> = response.json().await?;
            Ok(api_response.data.unwrap_or_default())
        } else {
            Err(format!("Failed to get partial access config: HTTP {}", status).into())
        }
    }

    pub async fn record_access_attempt(
        &self,
        data: crate::protection_modules::dto::AccessAttemptData,
        is_upload: bool,
        token: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (agent_id, _) = match &self.credentials {
            Some(creds) => (creds.agent_id, creds.token.as_deref().unwrap_or("")),
            None => return Err("No credentials available".into()),
        };
        let endpoint = if is_upload { "upload-attempt" } else { "download-attempt" };
        let url = format!("{}/api/python-client/devices/{}/partial-access/{}", self.base_url, agent_id, endpoint);
        let auth_header = Self::prepare_auth_header(token);
        let response = self.client.post(&url).header("Authorization", auth_header).json(&data).send().await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(format!("Failed to record access attempt: HTTP {} - {}", status, body).into())
        }
    }

    pub async fn send_web_history(
        &self,
        agent_id: u64,
        token: &str,
        logs: Vec<WebLog>
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if logs.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/agent/web-history", self.base_url);
        let request_payload = WebHistoryRequest { agent_id, logs };

        let response = self.client
            .post(&url)
            // .header("Authorization", token)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request_payload)
            .send().await?;

        if response.status().is_success() {
            log::info!(
                "✅ Successfully sent {} web history logs to backend.",
                request_payload.logs.len()
            );
        } else {
            log::error!(
                "❌ Failed to send web history. Status: {}, Body: {}",
                response.status(),
                response.text().await?
            );
        }
        Ok(())
    }

    // ===== UTILITY METHODS =====

    /// Set credentials manually (for GUI login)
    pub fn set_credentials(&mut self, username: String, password: String) {
        self.credentials = Some(AgentCredentials {
            agent_id: 0,
            username,
            password,
            token: None,
        });
    }

    /// Get current credentials
    pub fn get_credentials(&self) -> Option<&AgentCredentials> {
        self.credentials.as_ref()
    }

    /// Get agent ID from credentials
    pub fn get_agent_id(&self) -> Option<u64> {
        self.credentials.as_ref().map(|creds| creds.agent_id)
    }

    /// Get token from credentials
    pub fn get_token(&self) -> Option<String> {
        self.credentials.as_ref().and_then(|creds| creds.token.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCRConfiguration {
    pub enabled: bool,
    pub scan_interval: u64,
    pub sensitivity: f32,
    pub monitored_applications: Vec<String>,
}

impl Default for OCRConfiguration {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval: 5,
            sensitivity: 0.7,
            monitored_applications: vec![],
        }
    }
}
