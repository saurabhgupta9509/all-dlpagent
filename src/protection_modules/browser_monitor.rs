use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use uiautomation::{UIAutomation, UIElement, UITreeWalker};
use uiautomation::types::UIProperty;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, PostMessageW, WM_CLOSE};
use windows::Win32::Foundation::{LPARAM, WPARAM, HWND};
use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::protection_modules::dto::UrlMonitoringData;
use std::any::Any;
use std::error::Error;
use log::{warn, debug, info};
use chrono::Local;

pub struct BrowserMonitorModule {
    pub last_url: String,
    pub blocked_count: u32,
    pub suspicious_count: u32,
    pub url_timers: HashMap<String, f64>,
    pub total_times: HashMap<String, f64>,
    urls_for_upload: VecDeque<String>,
    pub api_blacklist: Vec<String>,
    last_upload_time: SystemTime,
    last_blacklist_update: SystemTime,
}

impl BrowserMonitorModule {
    pub fn new() -> Self {
        Self {
            last_url: String::new(),
            blocked_count: 0,
            suspicious_count: 0,
            url_timers: HashMap::new(),
            total_times: HashMap::new(),
            urls_for_upload: VecDeque::new(),
            api_blacklist: Vec::new(),
            last_upload_time: SystemTime::now(),
            last_blacklist_update: SystemTime::now() - Duration::from_secs(3600), // Force initial update
        }
    }

    pub fn get_active_browser_url_optimized(&self) -> Option<String> {
        let automation = UIAutomation::new().ok()?;
        let root = automation.get_root_element().ok()?;
        let walker = automation.get_control_view_walker().ok()?;
        
        let mut current = match walker.get_first_child(&root) {
            Ok(el) => el,
            _ => return None,
        };
        
        loop {
            if let Ok(name) = current.get_name() {
                let name_lower = name.to_lowercase();
                if name_lower.contains("chrome") || name_lower.contains("edge") || name_lower.contains("brave") {
                    if let Some(url) = self.find_address_bar_url(&automation, &walker, &current) {
                        return Some(url);
                    }
                }
            }
            
            if let Ok(next) = walker.get_next_sibling(&current) {
                current = next;
            } else {
                break;
            }
        }

        None
    }

    fn find_address_bar_url(&self, automation: &UIAutomation, walker: &UITreeWalker, browser_window: &UIElement) -> Option<String> {
        if let Some(address_bar) = self.find_address_bar_recursive(automation, walker, browser_window, 0) {
            if let Ok(val) = address_bar.get_property_value(UIProperty::ValueValue) {
                let mut url_str = val.to_string();
                if url_str.starts_with("STRING(") && url_str.ends_with(')') {
                    url_str = url_str[7..url_str.len()-1].to_string();
                }
                
                if !url_str.is_empty() {
                    return Some(url_str);
                }
            }
        }
        None
    }

    fn find_address_bar_recursive(&self, _automation: &UIAutomation, walker: &UITreeWalker, element: &UIElement, depth: u32) -> Option<UIElement> {
        if depth > 12 { return None; }

        let mut current = match walker.get_first_child(element) {
            Ok(el) => el,
            _ => return None,
        };
        
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

            if let Some(found) = self.find_address_bar_recursive(_automation, walker, &current, depth + 1) {
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

    pub fn update_timing(&mut self, current_url: Option<String>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        if let Some(url) = current_url {
            if self.is_blocked(&url) {
                warn!("🛑 Accessing blocked URL: {}. Closing window...", url);
                self.blocked_count += 1;
                
                if let Some(automation) = UIAutomation::new().ok() {
                    if let Some(root) = automation.get_root_element().ok() {
                        if let Some(walker) = automation.get_control_view_walker().ok() {
                            let mut handle_found = false;
                            
                            if let Some(browser_el) = self.find_browser_window_with_url(&automation, &walker, &root, &url) {
                                if let Ok(val) = browser_el.get_property_value(UIProperty::NativeWindowHandle) {
                                    let mut handle_str = val.to_string();
                                    if let Some(start) = handle_str.find('(') {
                                        if let Some(end) = handle_str.rfind(')') {
                                            handle_str = handle_str[start+1..end].to_string();
                                        }
                                    }
                                    
                                    if let Ok(hwnd_val) = handle_str.parse::<isize>() {
                                        if hwnd_val != 0 {
                                            debug!("[INFO] Found browser window HWND: {}. Sending close message...", hwnd_val);
                                            unsafe {
                                                PostMessageW(HWND(hwnd_val as _), WM_CLOSE, WPARAM(0), LPARAM(0));
                                            }
                                            handle_found = true;
                                        }
                                    }
                                }
                            }

                            if !handle_found {
                                unsafe {
                                    let hwnd = GetForegroundWindow();
                                    if hwnd.0 != 0 {
                                        PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if url != self.last_url {
                if !self.last_url.is_empty() {
                    let start_time = self.url_timers.remove(&self.last_url).unwrap_or(now);
                    let duration = now - start_time;
                    *self.total_times.entry(self.last_url.clone()).or_insert(0.0) += duration;
                }
                
                self.last_url = url.clone();
                self.url_timers.insert(url.clone(), now);
                
                info!("🌐 New URL detected: {}", url);
                
                self.urls_for_upload.push_back(url);
                if self.urls_for_upload.len() > 50 {
                    self.urls_for_upload.pop_front();
                }
            }
        } else if !self.last_url.is_empty() {
            let start_time = self.url_timers.remove(&self.last_url).unwrap_or(now);
            let duration = now - start_time;
            *self.total_times.entry(self.last_url.clone()).or_insert(0.0) += duration;
            self.last_url = String::new();
        }
    }

    pub fn update_blacklist(&mut self, new_blacklist: Vec<String>) {
        self.api_blacklist = new_blacklist.into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        info!("📋 Blacklist updated. {} patterns active.", self.api_blacklist.len());
    }

    fn is_blocked(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        if url_lower.is_empty() { return false; }

        for pattern in &self.api_blacklist {
            let pattern_lower = pattern.to_lowercase();
            
            // Handle wildcards or direct contains
            if pattern_lower.contains('*') {
                let escaped = regex::escape(&pattern_lower);
                let regex_pattern = escaped.replace("\\*", ".*");
                if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex_pattern)) {
                    if re.is_match(&url_lower) {
                        return true;
                    }
                }
            } else if url_lower.contains(&pattern_lower) {
                return true;
            }
        }
        false
    }

    pub fn get_url_data_for_api(&mut self, agent_id: u64, clear_after: bool) -> UrlMonitoringData {
        let urls: Vec<String> = self.urls_for_upload.iter().cloned().collect();
        let total_visits = self.total_times.values().map(|&v| v as u32).sum::<u32>();

        let result = UrlMonitoringData {
            device_id: agent_id.to_string(),
            timestamp: Local::now().to_rfc3339(),
            urls,
            blocked_count: self.blocked_count,
            suspicious_count: self.suspicious_count,
            total_visits,
        };
        
        if clear_after {
            self.urls_for_upload.clear();
        }
        
        result
    }

    fn find_browser_window_with_url(&self, automation: &UIAutomation, walker: &UITreeWalker, root: &UIElement, target_url: &str) -> Option<UIElement> {
        let mut current = walker.get_first_child(root).ok()?;
        
        loop {
            if let Ok(name) = current.get_name() {
                let name_lower = name.to_lowercase();
                if name_lower.contains("chrome") || name_lower.contains("edge") || name_lower.contains("brave") {
                    if let Some(url) = self.find_address_bar_url(automation, walker, &current) {
                        if url.contains(target_url) || target_url.contains(&url) {
                            return Some(current);
                        }
                    }
                }
            }
            
            if let Ok(next) = walker.get_next_sibling(&current) {
                current = next;
            } else {
                break;
            }
        }
        None
    }
}

#[async_trait::async_trait]
impl ProtectionModule for BrowserMonitorModule {
    async fn execute(
        &mut self,
        _policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Update blacklist periodically (every 1 minute)
        if self.last_blacklist_update.elapsed().unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(60) {
            match communicator.get_blocked_urls(token).await {
                Ok(urls) => {
                    self.update_blacklist(urls);
                    self.last_blacklist_update = SystemTime::now();
                }
                Err(e) => debug!("⚠️ Failed to fetch blocked URLs: {}", e),
            }
        }

        // Track current URL and check blocking
        let current_url = self.get_active_browser_url_optimized();
        self.update_timing(current_url);

        // Periodic upload (every 60 seconds)
        if self.last_upload_time.elapsed().unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(60) {
            let data = self.get_url_data_for_api(agent_id, true);
            if !data.urls.is_empty() || data.blocked_count > 0 {
                info!("📤 Uploading {} monitored URLs for agent {}...", data.urls.len(), agent_id);
                if let Err(e) = communicator.upload_urls(data, token).await {
                    info!("⚠️ Failed to upload URL data: {}", e);
                }
            }
            self.last_upload_time = SystemTime::now();
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        "BrowserMonitor"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
