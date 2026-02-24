use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::{Arc, Mutex};
use std::fs::OpenOptions;
use std::io::Write;
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};
use sysinfo::{System};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use crate::protection_modules::dto::AppUsageData;
use std::any::Any;
use std::error::Error;
use log::{debug, info};

pub const TRACK_APP_USAGE: bool = true;
pub const MINIMUM_APP_TIME: u64 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct AppDataStore {
    pub app_total_time: HashMap<String, f64>,
    pub app_sessions: HashMap<String, u32>,
    pub app_category_time: HashMap<String, f64>,
}

pub struct AppTrackerModule {
    pub current_app: Option<String>,
    pub app_start_time: Option<f64>,
    pub data: Arc<Mutex<AppDataStore>>,
    sys: System,
    last_upload_time: SystemTime,
}

impl AppTrackerModule {
    pub fn new() -> Self {
        let data = AppDataStore {
            app_total_time: HashMap::new(),
            app_sessions: HashMap::new(),
            app_category_time: HashMap::new(),
        };

        Self {
            current_app: None,
            app_start_time: None,
            data: Arc::new(Mutex::new(data)),
            sys: System::new_all(),
            last_upload_time: SystemTime::now(),
        }
    }

    pub fn track_app_usage(&mut self) -> Option<String> {
        let now = current_time_secs();
        let device_active = self.check_device_active();

        if !device_active {
            if let (Some(app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                let duration = now - start;
                if duration >= MINIMUM_APP_TIME as f64 {
                    self.record_app_session(&app, start, now, duration);
                }
            }
            return None;
        }

        let active_app = self.get_active_app();

        if let Some(app) = active_app {
            if Some(&app) != self.current_app.as_ref() {
                if let (Some(old_app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                    let duration = now - start;
                    if duration >= MINIMUM_APP_TIME as f64 {
                        self.record_app_session(&old_app, start, now, duration);
                    }
                }
                self.current_app = Some(app);
                self.app_start_time = Some(now);
            } else if let Some(start) = self.app_start_time {
                if now - start >= 300.0 {
                    let duration = now - start;
                    self.record_app_session(self.current_app.as_ref().unwrap(), start, now, duration);
                    self.app_start_time = Some(now);
                }
            }
        } else {
            if let (Some(app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                let duration = now - start;
                if duration >= MINIMUM_APP_TIME as f64 {
                    self.record_app_session(&app, start, now, duration);
                }
            }
        }

        self.current_app.clone()
    }

    fn check_device_active(&self) -> bool {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        unsafe {
            if GetLastInputInfo(&mut lii).as_bool() {
                let current_tick = windows::Win32::System::SystemInformation::GetTickCount64();
                
                // Handle the 32-bit wrap around of lii.dwTime
                let current_tick_32 = (current_tick & 0xFFFFFFFF) as u32;
                let idle_ticks = if current_tick_32 >= lii.dwTime {
                    current_tick_32 - lii.dwTime
                } else {
                    (u32::MAX - lii.dwTime) + current_tick_32
                };
                
                let idle_secs = idle_ticks as f64 / 1000.0;
                idle_secs < 120.0 // 2 minutes idle threshold
            } else {
                true
            }
        }
    }

    fn get_active_app(&mut self) -> Option<String> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0 == 0 {
            return None;
        }

        let mut pid: u32 = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

        self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        
        if let Some(process) = self.sys.process(sysinfo::Pid::from(pid as usize)) {
            let name = process.name().to_string_lossy().to_lowercase().replace(".exe", "");
            if self.should_ignore_app(&name) {
                None
            } else {
                Some(name)
            }
        } else {
            None
        }
    }

    fn should_ignore_app(&self, app_name: &str) -> bool {
        let ignores = [
            "explorer", "svchost", "System", "Idle", "Registry", "smss", "csrss",
            "wininit", "winlogon", "services", "lsass", "taskhost", "dwm", "conhost",
            "cmd", "powershell", "pwsh", "python", "pythonw", "javaw", "java",
            "WmiPrvSE", "sihost", "ctfmon", "RuntimeBroker", "SearchUI",
            "StartMenuExperienceHost", "Widgets", "Calculator", "notepad", "wordpad",
            "mspaint", "SystemSettings", "Taskmgr", "SecurityHealthSystray",
            "SecurityHealthService", "CybersecurityMonitor", "dlp-agent"
        ];
        ignores.iter().any(|&i| app_name.contains(&i.to_lowercase()))
    }

    fn record_app_session(&self, app_name: &str, start_time: f64, _end_time: f64, duration: f64) {
        let timestamp = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs_f64(start_time))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        
        let log_line = format!("[{}] {}: {:.1}s\n", timestamp, app_name, duration);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("logs/app_timelog.log") {
            let _ = file.write_all(log_line.as_bytes());
        }

        info!("📊 Recorded app session: {} for {:.1}s", app_name, duration);

        let mut data = self.data.lock().unwrap();
        *data.app_total_time.entry(app_name.to_string()).or_insert(0.0) += duration;
        *data.app_sessions.entry(app_name.to_string()).or_insert(0) += 1;

        let category = self.get_app_category(app_name);
        *data.app_category_time.entry(category).or_insert(0.0) += duration;
    }

    fn get_app_category(&self, app_name: &str) -> String {
        let mut m = HashMap::new();
        m.insert("Browsers", vec!["chrome", "firefox", "msedge", "opera", "brave", "vivaldi", "safari", "tor"]);
        m.insert("Communication", vec!["teams", "zoom", "discord", "slack", "whatsapp", "signal", "telegram", "skype"]);
        m.insert("Social Media", vec!["facebook", "instagram", "twitter", "tiktok", "reddit", "linkedin", "pinterest"]);
        m.insert("Productivity", vec!["winword", "excel", "powerpnt", "outlook", "onenote", "notepad++", "vscode", "code"]);
        m.insert("Entertainment", vec!["spotify", "vlc", "netflix", "disney+", "primevideo", "steam", "epicgameslauncher"]);
        m.insert("Development", vec!["vscode", "code", "pycharm", "intellij", "androidstudio", "visualstudio", "git", "docker"]);
        m.insert("Creative", vec!["photoshop", "illustrator", "premiere", "aftereffects", "blender", "audacity", "obs"]);
        m.insert("Utilities", vec!["explorer", "taskmgr", "control", "settings", "calculator", "mspaint", "cmd", "powershell"]);
        
        for (cat, apps) in m {
            if apps.iter().any(|&a| app_name.contains(&a.to_lowercase())) {
                return cat.to_string();
            }
        }
        "Other".to_string()
    }

    pub fn get_app_data_for_api(&self, agent_id: u64) -> AppUsageData {
        let (data, current_app, start_time) = {
            let data = self.data.lock().unwrap();
            (data.clone(), self.current_app.clone(), self.app_start_time)
        };

        let now = current_time_secs();
        let current_session_duration = if let Some(start) = start_time {
            now - start
        } else {
            0.0
        };

        let mut top_apps = Vec::new();
        let mut sorted_apps: Vec<_> = data.app_total_time.iter().collect();
        sorted_apps.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        for (name, time) in sorted_apps.iter().take(5) {
            let category = self.get_app_category(name);
            top_apps.push(serde_json::json!({
                "app": *name,
                "active_time": **time,
                "category": category,
                "sessions": data.app_sessions.get(*name).unwrap_or(&0)
            }));
        }

        let active_usage_time: f64 = data.app_total_time.values().sum();

        AppUsageData {
            device_id: agent_id.to_string(), // Using agent_id as device_id for now
            timestamp: Local::now().to_rfc3339(),
            current_app: current_app.unwrap_or_else(|| "Idle".to_string()),
            current_session_duration,
            total_apps_tracked: data.app_total_time.len() as u32,
            total_time_tracked: active_usage_time,
            active_usage_time,
            top_apps,
            category_breakdown: data.app_category_time.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ProtectionModule for AppTrackerModule {
    async fn execute(
        &mut self,
        _policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Track current app
        let _ = self.track_app_usage();

        // Periodic upload (every 30 seconds)
        if self.last_upload_time.elapsed().unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(30) {
            info!("📤 Uploading app usage data for agent {}...", agent_id);
            let data = self.get_app_data_for_api(agent_id);
            if let Err(e) = communicator.upload_app_usage(data, token).await {
                info!("⚠️ Failed to upload app usage: {}", e);
            }
            self.last_upload_time = SystemTime::now();
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        "AppTracker"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn current_time_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}
