use crate::capabilities::PolicyCapability;
use crate::communication:: ServerCommunicator ;
use crate::config::{BASE_URLS};
use crate::policy_engine::PolicyEngine;
use crate::protection_modules::dto::FileSystemItemDTO;
use tokio::sync::Mutex;
// use crate::protection_modules::file_protection::FileMonitorProtection;
use crate::protection_modules::network_protection::NetworkProtection;
use crate::protection_modules::security_monitor::ThreadSafeSecurityMonitorProtection;
use crate::protection_modules::{ FileProtectionModule, ProtectionModule };
use crate::protection_modules::{AppTrackerModule, BrowserMonitorModule, PartialAccessModule};
// use crate::protection_modules::web_proxy::WebProxyProtection;
use log;
use std::collections::HashMap;  
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock; // Use Tokio's async-friendly RwLock
use chrono::{Utc, DateTime};
use std::collections::HashSet;

/// Configuration for the agent
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String, // Backend server URL
    pub hostname: String, // Agent hostname
    pub mac_address: String, // Agent MAC address
    pub poll_interval_sec: u64, // How often to poll for updates
}

/// Main agent core that coordinates all components
pub struct AgentCore {
    pub agent_id: u64, // Agent ID from backend
    pub token: String, // Authentication token
    pub config: AgentConfig, // Agent configuration
    pub policy_engine: Arc<RwLock<PolicyEngine>>, // Policy management
    pub communicator: Arc<RwLock<ServerCommunicator>>, // Server communication
    pub protection_modules: HashMap<String, Box<dyn ProtectionModule + Send + Sync>>, // Active protection modules
    pub last_policy_check_time: Arc<Mutex<chrono::DateTime<Utc>>>,
    pub last_token_refresh_time: Arc<Mutex<chrono::DateTime<Utc>>>,
    pub active_policies_cache: Arc<Mutex<HashSet<String>>>,
}

impl AgentCore {
    /// Create a new AgentCore with default configuration
    pub fn new() -> Self {
        let config = AgentConfig {
             server_url: BASE_URLS.clone(),
            hostname: whoami::devicename(), // Use devicename()
            mac_address: Self::get_mac_address(),
            poll_interval_sec: 15, // A more reasonable default poll
        };

        Self {
            agent_id: 0,
            token: String::new(),
            config,
            policy_engine: Arc::new(RwLock::new(PolicyEngine::new())),
            communicator: Arc::new(RwLock::new(ServerCommunicator::new(&BASE_URLS))),
            protection_modules: HashMap::new(),
            last_policy_check_time: Arc::new(Mutex::new(Utc::now())),
            last_token_refresh_time: Arc::new(Mutex::new(Utc::now())),
            active_policies_cache: Arc::new(Mutex::new(HashSet::new())),
        }
    }



    /// Main agent loop - runs continuously
    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        log::info!("🚀 AgentCore running with requested feature intervals...");

        let mut high_freq_interval = tokio::time::interval(Duration::from_secs(1));
        let mut usb_interval = tokio::time::interval(Duration::from_secs(5));
        let mut dns_interval = tokio::time::interval(Duration::from_secs(10));
        let mut url_interval = tokio::time::interval(Duration::from_secs(10));
        let mut partial_interval = tokio::time::interval(Duration::from_secs(15));
        
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
        let mut policy_check_interval = tokio::time::interval(Duration::from_secs(300));
        let mut token_refresh_interval = tokio::time::interval(Duration::from_secs(300));
        let mut command_check_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = high_freq_interval.tick() => {
                    self.execute_specific_modules(vec![
                        "SecurityMonitor".to_string(), 
                        "AppTracker".to_string(), 
                        "FileProtection".to_string()
                    ]).await;
                }
                _ = usb_interval.tick() => {
                    self.execute_specific_modules(vec!["USB".to_string()]).await;
                }
                _ = dns_interval.tick() => {
                    self.execute_specific_modules(vec!["Network".to_string()]).await;
                }
                _ = url_interval.tick() => {
                    self.execute_specific_modules(vec!["BrowserMonitor".to_string()]).await;
                }
                _ = partial_interval.tick() => {
                    self.execute_specific_modules(vec!["PartialAccess".to_string()]).await;
                }
                _ = heartbeat_interval.tick() => {
                    if let Err(e) = self.send_heartbeat().await {
                        log::warn!("⚠️ Heartbeat failed: {}", e);
                    }
                }
                _ = policy_check_interval.tick() => {
                    log::info!("🔄 Refreshing security policies...");
                    if let Err(e) = self.fetch_policies().await {
                        log::warn!("⚠️ Policy fetch failed: {}", e);
                    }
                }
                _ = token_refresh_interval.tick() => {
                    if let Err(e) = self.refresh_security_monitor_token().await {
                        log::warn!("⚠️ Token refresh failed: {}", e);
                    }
                }
                _ = command_check_interval.tick() => {
                    log::debug!("🔄 Checking for pending commands...");
                    if let Err(e) = self.check_for_commands().await {
                        log::warn!("⚠️ Command check failed: {}", e);
                    }
                }
            }
        }
    }

    /// Helper to execute a specific subset of modules
    async fn execute_specific_modules(&mut self, module_names: Vec<String>) {
        let active_cache = {
            let cache = self.active_policies_cache.lock().await;
            cache.clone()
        };

        for name in module_names {
            if active_cache.contains(&name) {
                if let Some(module) = self.protection_modules.get_mut(&name) {
                    let pe_guard = self.policy_engine.read().await;
                    let comm_guard = self.communicator.read().await;
                    
                    if let Err(e) = module.execute(
                        &*pe_guard,
                        &*comm_guard,
                        self.agent_id,
                        &self.token
                    ).await {
                        log::error!("❌ Protection module {} failed: {}", name, e);
                    }
                }
            }
        }
    }


      /// FIXED: Execute protections WITHOUT policy checks every time
    async fn execute_protections_no_policy_check(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Get cached active modules
        let modules_to_run: Vec<String> = {
            let cache = self.active_policies_cache.lock().await;
            cache.iter().cloned().collect()
        };
        
        for name in modules_to_run {
            if let Some(module) = self.protection_modules.get_mut(&name) {
                log::debug!("🛡️ Executing protection module: {}", name);
                let pe_guard = self.policy_engine.read().await;
                let comm_guard = self.communicator.read().await;
                
                if let Err(e) = module.execute(
                    &*pe_guard,
                    &*comm_guard,
                    self.agent_id,
                    &self.token
                ).await {
                    log::error!("❌ Protection module {} failed: {}", name, e);
                }
            }
        }
        Ok(())
    }

    /// Single polling cycle - called repeatedly by main loop
    async fn poll_cycle(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        log::debug!("🔄 Polling cycle started");
        if let Err(e) = self.send_heartbeat().await {
            log::warn!("⚠️ Heartbeat failed: {}", e);
        }
        if let Err(e) = self.fetch_policies().await {
            log::warn!("⚠️ Policy fetch failed: {}", e);
        }
        if let Err(e) = self.execute_protections().await {
            log::warn!("⚠️ Protection execution failed: {}", e);
        }
        if let Err(e) = self.check_for_commands().await {
            log::warn!("⚠️ Command check failed: {}", e);
        }
         if self.should_refresh_token() {
            self.refresh_security_monitor_token().await?;
        }
        log::debug!("✅ Polling cycle completed");
        Ok(())
    }
       fn should_refresh_token(&self) -> bool {
        // Refresh token once every poll (2 seconds)
        // You can later replace this with timestamp-based logic
        true
    }


    async fn refresh_security_monitor_token(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // 1. Get latest token from communicator
        let latest_token = {
            let comm = self.communicator.read().await;
            comm.get_token()
        };

        if latest_token.is_none() {
            log::warn!("⚠️ No token available to refresh SecurityMonitor");
            return Ok(());
        }

        let latest_token = latest_token.unwrap();
        let bearer = format!("Bearer {}", latest_token);

        // 2. Find the SecurityMonitor module and update its token
        if let Some(module_box) = self.protection_modules.get("SecurityMonitor") {
            if let Some(security) = module_box.as_any().downcast_ref::<ThreadSafeSecurityMonitorProtection>() {
                security.update_token(bearer).await;
                log::info!("🔑 SecurityMonitor token refreshed successfully");
            }
        }

        // Update last refresh time
        *self.last_token_refresh_time.lock().await = Utc::now();

        Ok(())
    }

     async fn execute_protections_old(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Keep this for backward compatibility but don't use it
        self.execute_protections_no_policy_check().await
    }

    // pub async fn process_file_browse(agent_id: u64, path: String, http: &HttpClient, token: &str) {
    //     let items = scan_directory(&path);
    //     let parent = Path::new(&path)
    //         .parent()
    //         .map(|x| x.to_string_lossy().to_string())
    //         .unwrap_or("".into());

    //     let chunk_size = 200;
    //     let mut chunk_id = 0;

    //     for chunk in items.chunks(chunk_size) {
    //         let response = BrowseResponse {
    //             agentId: agent_id,
    //             currentPath: path.clone(),
    //             parentPath: parent.clone(),
    //             items: chunk.to_vec(),
    //             partial: true,
    //             complete: false,
    //             chunkId: Some(chunk_id),
    //         };

    //         http.send_browse_response(response, token).await;
    //         chunk_id += 1;
    //     }

    //     // Final batch: complete=true
    //     let response = BrowseResponse {
    //         agentId: agent_id,
    //         currentPath: path.clone(),
    //         parentPath: parent.clone(),
    //         items: vec![],
    //         partial: false,
    //         complete: true,
    //         chunkId: None,
    //     };

    //     http.send_browse_response(response, token).await;
    // }

    async fn check_for_commands(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        log::info!("⏳ Checking for pending commands...");

        // Use ServerCommunicator.get_commands for standardized auth and error handling
        let body = {
            let comm = self.communicator.read().await;
            comm.get_commands(self.agent_id, &self.token).await?
        };

        if body.is_null() {
            return Ok(()); // Command check failed non-fatally, already logged
        }

        log::info!("📥 Server response for commands: {}", body);

        if body.get("pending").and_then(|v| v.as_bool()) != Some(true) {
            log::info!("🚫 No pending command for this agent");
            return Ok(());
        }

        let command = body["command"].as_str().unwrap_or("");
        log::info!("📌 Pending command: {}", command);
        let path = body["path"].as_str().unwrap_or("").to_string();

        match command {
            "FILE_BROWSE" => {
                log::info!("📂 Executing FILE_BROWSE on path: {}", path);
                self.handle_file_browse(&path).await?;
            }
            _ => log::warn!("Unknown command received: {}", command),
        }

        Ok(())
    }

    async fn handle_file_browse(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let token = self.token.clone();
        let agent_id = self.agent_id;

        let comm = self.communicator.read().await;
        let browse = comm.handle_file_browse_request(Some(path.to_string())).await?;
        drop(comm);

        // Convert items to DTO
        let items: Vec<FileSystemItemDTO> = browse.items
            .into_iter()
            .map(|i| FileSystemItemDTO {
                name: i.name,
                full_path: i.full_path,
                is_directory: i.is_directory,
                size: i.size,
            })
            .collect();

        let comm2 = self.communicator.read().await;

        comm2.send_file_browse_response_chunked(
            agent_id,
            browse.current_path,
            browse.parent_path,
            items,
            &token
        ).await?;

        Ok(())
    }

    /// Build the file policy map directly from a set of already-fetched active policies.
    ///
    /// Mirrors the Java backend logic in `AgentController.getFilePolicies()`:
    ///   - Filters for category == "FILE" with non-empty `policy_data`
    ///   - Splits `policy_data` by comma into a `Vec<String>`
    ///   - Maps policy codes to the string keys the file protection module expects
    ///
    /// Returns `HashMap<String, Vec<String>>` e.g.:
    ///   { "block_extensions_create" -> [".exe", ".dll"],
    ///     "block_paths_delete"      -> ["C:\\Secret\\", ...], ... }
    fn build_file_policies_from_active(
        policies: &[crate::policy_engine::Policy],
    ) -> std::collections::HashMap<String, Vec<String>> {
        let mut file_policies: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        for policy in policies {
            if policy.category != "FILE" || !policy.is_active {
                continue;
            }
            if policy.policy_data.trim().is_empty() {
                log::debug!("[FILE-POLICIES] Skipping FILE policy '{}' — policyData is empty", policy.code);
                continue;
            }

            // Split comma-separated values and trim whitespace
            let items: Vec<String> = policy.policy_data
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if items.is_empty() {
                continue;
            }

            // Mirror the Java mapping: policy code → file_policies map key
            let code = policy.code.as_str();
            let map_key: Option<&str> = if code.contains("BLOCK_EXTENSIONS") {
                if code.contains("CREATE")      { Some("block_extensions_create") }
                else if code.contains("WRITE")  { Some("block_extensions_write")  }
                else if code.contains("DELETE") { Some("block_extensions_delete") }
                else if code.contains("READ")   { Some("block_extensions_read")   }
                else { None }
            } else if code.contains("BLOCK_PATHS") {
                if code.contains("CREATE")      { Some("block_paths_create") }
                else if code.contains("WRITE")  { Some("block_paths_write")  }
                else if code.contains("DELETE") { Some("block_paths_delete") }
                else if code.contains("READ")   { Some("block_paths_read")   }
                else { None }
            } else if code == "FILE_READONLY_EXTENSIONS" { Some("readonly_extensions") }
              else if code == "FILE_READONLY_PATHS"       { Some("readonly_paths")       }
              else if code.contains("BLOCK_CREATE")       { Some("block_create")         }
              else if code.contains("BLOCK_WRITE")        { Some("block_write")          }
              else if code.contains("BLOCK_DELETE")       { Some("block_delete")         }
              else if code.contains("BLOCK_READ")         { Some("block_read")           }
              else { None };

            if let Some(key) = map_key {
                log::info!("[FILE-POLICIES] Mapped '{}' -> '{}' ({} items: {:?})",
                    code, key, items.len(), items);
                file_policies.insert(key.to_string(), items);
            } else {
                log::warn!("[FILE-POLICIES] Unknown FILE policy code '{}' — not mapped", code);
            }
        }

        log::info!("[FILE-POLICIES] Built {} file policy categories from active policies", file_policies.len());
        file_policies
    }

    async fn fetch_policies(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let comm = self.communicator.read().await;

        // 1. Fetch the list of active policies
        let policies = comm.get_active_policies(self.agent_id, &self.token).await?;
        // Release communicator read lock — all subsequent work is local
        drop(comm);

        let policies_clone = policies.clone();
        let active_count = policies
            .iter()
            .filter(|p| p.is_active)
            .count();
        let total_count = policies.len();

        // 2. Build the file policy map directly from active FILE policies.
        //    This uses the policyData already returned by /active-policies, which is
        //    set by the admin at assignment time via activateCapability().
        //    We no longer call the separate /file-policies endpoint because it has the
        //    same policyData requirement and adds an unnecessary HTTP round-trip.
        let file_policies = Self::build_file_policies_from_active(&policies);
        let file_policy_categories = file_policies.len();

        // 3. Lock engine and update BOTH
        let mut pe = self.policy_engine.write().await; // Lock for writing
        pe.update_policies(policies);

        // --- THIS IS THE FIX ---
        // This line was missing. Without it, the file module never gets its rules.
        pe.update_file_policies(file_policies);
        // --- END FIX ---

          // 4. Update cache of active protection modules
        let mut cache = self.active_policies_cache.lock().await;
        cache.clear();

        for policy in policies_clone {
            if policy.is_active {
                match policy.category.as_str() {
                    "USB" => { cache.insert("USB".to_string()); }
                    "NETWORK" => { cache.insert("Network".to_string()); }
                    "WEB" => { cache.insert("WebProxy".to_string()); }
                     "FILE" => { 
                    cache.insert("FileProtection".to_string()); 
                        log::info!("[OK] File Protection policy is ACTIVE!");
                    }
                    // Both SECURITY_MONITOR (current) and OCR (legacy) activate SecurityMonitor
                    "SECURITY_MONITOR" | "OCR" => { cache.insert("SecurityMonitor".to_string()); }
                    "MONITORING" => { cache.insert("AppTracker".to_string()); }
                    "WEB_MONITOR" => { cache.insert("BrowserMonitor".to_string()); }
                    "FILE_ACCESS" => { cache.insert("PartialAccess".to_string()); }
                    _ => {}
                }
            }
        }
        // Release the cache lock before re-reporting
        drop(cache);
        drop(pe);

        // 5. Re-report capabilities to backend with correct isActive flags
        //    Builds { policyCode -> Option<policyData> } from active policies in the engine
        {
            let pe_read = self.policy_engine.read().await;
            let active_map: std::collections::HashMap<String, Option<String>> = pe_read
                .get_active_policies()
                .iter()
                .map(|p| {
                    let data = if p.policy_data.is_empty() { None } else { Some(p.policy_data.clone()) };
                    (p.code.clone(), data)
                })
                .collect();
            drop(pe_read);

            let grouped = PolicyCapability::grouped_by_category(&active_map);
            // Flatten to a Vec — the backend POST endpoint expects a flat list
            let flat_caps: Vec<PolicyCapability> = grouped.into_values().flatten().collect();
            let comm = self.communicator.read().await;
            if let Err(e) = comm.report_capabilities(self.agent_id, &self.token, &flat_caps).await {
                log::warn!("[WARN] Could not re-report capabilities after policy refresh: {}", e);
            }
        }

        log::info!("[POLICIES] Updated policies: {} active, {} total, {} file policy categories loaded",
            active_count,
            total_count,
            file_policy_categories
        );
        Ok(())
    }

    async fn execute_protections(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let modules_to_run: Vec<String> = self.protection_modules.keys().cloned().collect();
        for name in modules_to_run {
            let should_run = {
                let pe = self.policy_engine.read().await;
                match name.as_str() {
                    "USB" => pe.is_usb_protection_enabled(),
                    "Network" => pe.is_network_protection_enabled(),
                    "WebProxy" => pe.is_web_protection_enabled(),
                    "FileMonitor" => pe.is_file_protection_enabled(),
                    // "OCR" => pe.is_ocr_protection_enabled(),
                    "SecurityMonitor" => pe.is_policy_active("POLICY_OCR_MONITOR"),
                    "AppTracker" => pe.is_policy_active("APP_TRACKING") || true, 
                    "BrowserMonitor" => pe.is_policy_active("BROWSER_URL_MONITOR") || true,
                    "PartialAccess" => pe.is_policy_active("PARTIAL_ACCESS_CONTROL") || true,
                    _ => false,
                }
            };

            if should_run {
                if let Some(module) = self.protection_modules.get_mut(&name) {
                    log::debug!("🛡️ Executing protection module: {}", name);
                    let pe_guard = self.policy_engine.read().await;
                    let comm_guard = self.communicator.read().await;
                    // Pass the inner objects, not the Arcs
                    if
                        let Err(e) = module.execute(
                            &*pe_guard,
                            &*comm_guard,
                            self.agent_id,
                            &self.token
                        ).await
                    {
                        log::error!("❌ Protection module {} failed: {}", name, e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Initialize the agent - authenticate and report capabilities
    pub async fn initialize(
        &mut self,
        agent_username: String
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        log::info!("\u{1f680} Initializing agent...");

        if self.token.is_empty() {
            return Err("AgentCore started without a valid token.".into());
        }

        // Report capabilities with initial isActive = false (no policies fetched yet).
        // grouped_by_category() sets isActive on any cap found in the active map.
        // We then FLATTEN the grouped map → flat Vec, which is what the backend expects.
        let empty_active: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
        let flat_caps: Vec<PolicyCapability> = PolicyCapability::grouped_by_category(&empty_active)
            .into_values()
            .flatten()
            .collect();
        self.communicator
            .read().await
            .report_capabilities(self.agent_id, &self.token, &flat_caps).await?;

        // FIX: Must .await the async initialize_protection_modules function
        self.initialize_protection_modules(agent_username).await?;

        // Fetch active policies — this will re-report capabilities with correct isActive
        self.fetch_policies().await?;

        log::info!("[OK] Agent initialized and capabilities reported");
        Ok(())
    }

    /// Send heartbeat to backend — delegates to ServerCommunicator for standardized auth
    async fn send_heartbeat(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let comm = self.communicator.read().await;
        comm.send_heartbeat(self.agent_id, &self.token).await
    }

    fn get_mac_address() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255)
        )
    }

    async fn initialize_protection_modules(
        &mut self,
        agent_username: String
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        use crate::protection_modules::usb_protection::USBProtection;
        // Module 1: USB Protection
        self.protection_modules.insert("USB".to_string(), Box::new(USBProtection::new()));

        // Module 2: WFP Firewall - fix error conversion
        let network_module = NetworkProtection::new().map_err(
            |e| e as Box<dyn Error + Send + Sync>
        )?;
        self.protection_modules.insert("Network".to_string(), Box::new(network_module));

        // Module 3: Web Proxy - fix error conversion
        // let web_proxy_module = WebProxyProtection::new(
        //     self.policy_engine.clone(),
        //     self.communicator.clone()
        // ).await.map_err(|e| e as Box<dyn Error + Send + Sync>)?;

        // self.protection_modules.insert("WebProxy".to_string(), Box::new(web_proxy_module));

        // Module 4: File Monitor
        // let file_monitor_module = FileMonitorProtection::new(agent_username);
        // self.protection_modules.insert("FileMonitor".to_string(), Box::new(file_monitor_module));
        
        // Module 3: File Protection - ADD THIS!
        match FileProtectionModule::new(self.agent_id, self.token.clone()).await {
            Ok(module) => {
                self.protection_modules.insert("FileProtection".to_string(), Box::new(module));
                log::info!("✅ File Protection module initialized");
            }
            Err(e) => {
                log::error!("❌ Failed to initialize File Protection: {}", e);
            }
        }
        // Module 5: Security Monitor - FIXED: Pass communicator
        let security_monitor_module = ThreadSafeSecurityMonitorProtection::new(
            self.agent_id,
            self.token.clone(),
            self.communicator.clone()
        );
        self.protection_modules.insert(
            "SecurityMonitor".to_string(),
            Box::new(security_monitor_module)
        );

        // Module 6: App Tracker
        self.protection_modules.insert(
            "AppTracker".to_string(),
            Box::new(AppTrackerModule::new())
        );

        // Module 7: Browser Monitor
        self.protection_modules.insert(
            "BrowserMonitor".to_string(),
            Box::new(BrowserMonitorModule::new())
        );

        // Module 8: Partial Access
        let mut partial_access = PartialAccessModule::new(self.agent_id, self.token.clone());
        partial_access.start_monitoring(self.communicator.clone());
        self.protection_modules.insert(
            "PartialAccess".to_string(),
            Box::new(partial_access)
        );

        log::info!("✅ Initialized {} protection modules", self.protection_modules.len());
        Ok(())
    }

    /// Get active policies for debugging
    pub async fn get_active_policies_info(&self) -> String {
        let policy_engine = self.policy_engine.read().await;
        let active_policies = policy_engine.get_active_policies();

        if active_policies.is_empty() {
            return "No active policies".to_string();
        }

        let mut info = String::from("Active policies:\n");
        for policy in active_policies {
            info.push_str(&format!("  • {} ({})\n", policy.name, policy.code));
        }
        info
    }
}
