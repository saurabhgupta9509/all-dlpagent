use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetClassNameW, GetWindowTextW, PostMessageW, WM_CLOSE};
use windows::Win32::Foundation::{LPARAM, WPARAM, HWND};
use uiautomation::{UIAutomation, UIElement, UITreeWalker, types::UIProperty};
use serde::{Deserialize, Serialize};
use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::protection_modules::dto::AccessAttemptData;
use std::any::Any;
use std::error::Error;
use log::{warn, debug, info};

pub struct PartialAccessModule {
    pub running: bool,
    pub config: Arc<Mutex<PartialAccessConfig>>,
    pub context: Arc<Mutex<PartialAccessContextLocal>>,
    pub agent_id: u64,
    pub token: String,
}

#[derive(Clone, Default)]
pub struct PartialAccessContextLocal {
    pub current_url: String,
    pub current_domain: String,
}

#[derive(PartialEq)]
pub enum DialogType {
    None,
    Upload,
    Download,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct PartialAccessSite {
    #[serde(rename = "urlPattern")]
    pub url_pattern: String,
    #[serde(rename = "allowUpload")]
    pub allow_upload: bool,
    #[serde(rename = "allowDownload")]
    pub allow_download: bool,
    #[serde(rename = "monitorMode")]
    pub monitor_mode: String,
    pub active: bool,
}

#[derive(Clone, Default)]
pub struct PartialAccessConfig {
    pub enabled: bool,
    pub sites: Vec<PartialAccessSite>,
}

impl PartialAccessModule {
    pub fn new(agent_id: u64, token: String) -> Self {
        Self {
            running: false,
            config: Arc::new(Mutex::new(PartialAccessConfig {
                enabled: true,
                sites: Vec::new(),
            })),
            context: Arc::new(Mutex::new(PartialAccessContextLocal::default())),
            agent_id,
            token,
        }
    }

    pub fn start_monitoring(&mut self, communicator: Arc<tokio::sync::RwLock<ServerCommunicator>>) {
        if self.running { return; }
        self.running = true;
        info!("🏷️ Partial Access Monitoring started for agent {}", self.agent_id);
        
        let config = self.config.clone();
        let context = self.context.clone();
        let agent_id = self.agent_id;
        let token = self.token.clone();
        
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut last_blocked_hwnd: Option<HWND> = None;
            let mut last_blocked_time = Instant::now();

            loop {
                let current_config = {
                    let c = config.lock().unwrap();
                    c.clone()
                };

                if current_config.enabled {
                    let ctx = {
                        let c = context.lock().unwrap();
                        c.clone()
                    };

                    let site_config = current_config.sites.iter().find(|s| {
                        if !s.active { return false; }
                        let url_lower = ctx.current_url.to_lowercase();
                        let pattern_lower = s.url_pattern.to_lowercase();

                        if pattern_lower.contains('*') {
                            let escaped = regex::escape(&pattern_lower);
                            let regex_pattern = escaped.replace("\\*", ".*");
                            if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex_pattern)) {
                                re.is_match(&url_lower)
                            } else {
                                false
                            }
                        } else {
                            url_lower.contains(&pattern_lower)
                        }
                    });

                    if let Some(site) = site_config {
                        unsafe {
                            let hwnd = GetForegroundWindow();
                            if hwnd.0 != 0 {
                                // Avoid repetitive blocking
                                if Some(hwnd) == last_blocked_hwnd && last_blocked_time.elapsed() < Duration::from_secs(2) {
                                    std::thread::sleep(Duration::from_millis(200));
                                    continue;
                                }

                                let mut class_name = [0u16; 256];
                                let mut title = [0u16; 256];
                                
                                GetClassNameW(hwnd, &mut class_name);
                                let len = GetWindowTextW(hwnd, &mut title);
                                
                                if len > 0 {
                                    let class_name_str = String::from_utf16_lossy(&class_name).trim_matches('\0').to_string();
                                    let title_str = String::from_utf16_lossy(&title).trim_matches('\0').to_string();
                                    
                                    let dialog_type = get_dialog_type(&class_name_str, &title_str, site);
                                    if dialog_type != DialogType::None {
                                        warn!("ðŸ›‘ Blocking partial-access dialog: {} ({}) for site: {}", 
                                            title_str, class_name_str, site.url_pattern);
                                        
                                        PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                                        
                                        last_blocked_hwnd = Some(hwnd);
                                        last_blocked_time = Instant::now();
                                        
                                        let attempt_data = AccessAttemptData {
                                            url: ctx.current_url.clone(),
                                            domain: ctx.current_domain.clone(),
                                            file_type: "Unknown".to_string(),
                                            blocked: true,
                                            monitor_mode: site.monitor_mode.clone(),
                                        };

                                        let is_upload = dialog_type == DialogType::Upload;
                                        let comm = communicator.clone();
                                        let t = token.clone();
                                        
                                        rt.spawn(async move {
                                            let c = comm.read().await;
                                            if let Err(e) = c.record_access_attempt(attempt_data, is_upload, &t).await {
                                                debug!("âš ï¸ Failed to record access attempt: {}", e);
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
    }
}

fn get_dialog_type(class_name: &str, title: &str, site: &PartialAccessSite) -> DialogType {
    let dialog_classes = ["#32770", "FileChooserDialogClass", "NativeHWNDHost"];
    let title_lower = title.to_lowercase();

    let is_dialog_class = dialog_classes.iter().any(|&c| class_name.contains(c));
    if !is_dialog_class {
        return DialogType::None;
    }

    if !site.allow_upload && site.monitor_mode == "block" {
        let upload_keywords = ["open", "upload", "select file", "choose file", "attach", "browse"];
        if upload_keywords.iter().any(|&k| title_lower.contains(k)) {
            return DialogType::Upload;
        }
    }

    if !site.allow_download && site.monitor_mode == "block" {
        let download_keywords = ["save", "download", "save as", "export"];
        if download_keywords.iter().any(|&k| title_lower.contains(k)) {
            return DialogType::Download;
        }
    }

    DialogType::None
}

#[async_trait::async_trait]
impl ProtectionModule for PartialAccessModule {
    async fn execute(
        &mut self,
        _policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        _agent_id: u64,
        token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // 1. Update config periodically (handled here for simplicity)
        static LAST_CONFIG_UPDATE: Mutex<Option<Instant>> = Mutex::new(None);
        let should_update = {
            let mut last = LAST_CONFIG_UPDATE.lock().unwrap();
            if last.map_or(true, |t| t.elapsed() >= Duration::from_secs(30)) {
                *last = Some(Instant::now());
                true
            } else {
                false
            }
        };

        if should_update {
            match communicator.get_partial_access_config(token).await {
                Ok(conf_val) => {
                    let mut config = self.config.lock().unwrap();
                    if let Some(enabled) = conf_val.get("enabled").and_then(|v| v.as_bool())
                        .or_else(|| conf_val.get("active").and_then(|v| v.as_bool())) {
                        config.enabled = enabled;
                    }

                    if let Some(sites_array) = conf_val.get("partialAccessSites").and_then(|v| v.as_array())
                        .or_else(|| conf_val.get("sites").and_then(|v| v.as_array())) {
                        let sites: Vec<PartialAccessSite> = sites_array.iter()
                            .filter_map(|s| serde_json::from_value(s.clone()).ok())
                            .collect();
                        config.sites = sites;
                        info!("📋 Partial Access config updated: {} sites monitored.", config.sites.len());
                    }
                }
                Err(e) => debug!("âš ï¸ Failed to fetch partial access config: {}", e),
            }
        }

        // 2. Update context (current URL)
        // We can try to get it from uiautomation again or pass it if we have a global state
        // For now, let's use the UI automation logic directly here to update common context
        if let Some(automation) = UIAutomation::new().ok() {
            if let Some(root) = automation.get_root_element().ok() {
                if let Some(walker) = automation.get_control_view_walker().ok() {
                    let mut current_url = None;
                    let mut current = walker.get_first_child(&root).ok();
                    while let Some(el) = current {
                        if let Ok(name) = el.get_name() {
                            let name_lower = name.to_lowercase();
                            if name_lower.contains("chrome") || name_lower.contains("edge") || name_lower.contains("brave") {
                                if let Some(address_bar) = find_address_bar_recursive(&automation, &walker, &el, 0) {
                                    if let Ok(val) = address_bar.get_property_value(UIProperty::ValueValue) {
                                        let mut url_str = val.to_string();
                                        if url_str.starts_with("STRING(") && url_str.ends_with(')') {
                                            url_str = url_str[7..url_str.len()-1].to_string();
                                        }
                                        if !url_str.is_empty() {
                                            current_url = Some(url_str);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        current = walker.get_next_sibling(&el).ok();
                    }

                    if let Some(url) = current_url {
                        let mut ctx = self.context.lock().unwrap();
                        ctx.current_url = url.clone();
                        ctx.current_domain = if let Some(domain_part) = url.split("://").nth(1).and_then(|s| s.split('/').next()) {
                            domain_part.to_string()
                        } else {
                            url.clone()
                        };
                    }
                }
            }
        }

        // 3. Ensure monitoring thread is started
        // Actually, start_monitoring needs Arc<Mutex<ServerCommunicator>> which we don't have here easily
        // I'll leave starting to AgentCore or handle it differently.
        // Actually, I'll pass the communicator in AgentCore.

        Ok(())
    }

    fn get_name(&self) -> &str {
        "PartialAccess"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn find_address_bar_recursive(_automation: &UIAutomation, walker: &UITreeWalker, element: &UIElement, depth: u32) -> Option<UIElement> {
    if depth > 12 { return None; }
    let mut current = walker.get_first_child(element).ok()?;
    loop {
        if let Ok(name) = current.get_name() {
            let name_lower = name.to_lowercase();
            if name_lower.contains("address and search bar") || name_lower.contains("address bar") {
                return Some(current.clone());
            }
        }
        if let Ok(auto_id) = current.get_automation_id() {
            if auto_id == "addressEditBox" || auto_id.contains("url") || auto_id.contains("address") {
                return Some(current.clone());
            }
        }
        if let Some(found) = find_address_bar_recursive(_automation, walker, &current, depth + 1) {
            return Some(found);
        }
        if let Ok(next) = walker.get_next_sibling(&current) {
            current = next;
        } else {
            break;
        }
    }
    None
}
