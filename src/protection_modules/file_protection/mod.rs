//! File Protection Module - Complete filesystem protection system
//! Integrates the multi-step file protection project into the DLP Agent

use std::sync::Arc;
use std::error::Error;
use std::any::Any;
use tokio::sync::RwLock;
use log;
use std::collections::HashMap;

use crate::protection_modules::ProtectionModule;
use crate::communication::{ServerCommunicator, FileEventRequest, FileEventDTO};
use crate::policy_engine::PolicyEngine;
use crate::protection_modules::file_protection::kernel::KernelEventBridge;

// Re-export all the modules from your project
mod fs_index;
mod path_normalizer;
mod filesystem_scanner;
mod query_interface;
mod comms;
mod fltlib;
mod ui;
mod policy;
mod networking;
mod kernel;
mod nt_path_resolver;

// Re-export main types
use fs_index::FilesystemIndex;
use filesystem_scanner::FileSystemScanner;
use query_interface::QueryInterface;
use policy::PolicyEngine as FilePolicyEngine;
use tokio::sync::Mutex;

/// Thread-safe file protection module
pub struct FileProtectionModule {
    // Core components
    index: Arc<FilesystemIndex>,
    scanner: Arc<FileSystemScanner>,
    query: Arc<QueryInterface>,
    policy_engine: Arc<FilePolicyEngine>,
    
    // Optional HTTP server handle (if running)
    server_handle: Option<networking::ServerHandle>,
    
    // Kernel event bridge and reporting
    kernel_event_sender: Option<tokio::sync::mpsc::Sender<kernel::KernelEvent>>,
    bridge_handle: Option<tokio::task::JoinHandle<()>>,
    event_queue: Arc<Mutex<Vec<FileEventDTO>>>, // Shared event queue for reporting

    // Agent info
    agent_id: u64,
    token: String,
    enabled: bool,
}

impl FileProtectionModule {
    /// Create a new file protection module
    pub async fn new(
        agent_id: u64,
        token: String,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        log::info!("📁 Initializing File Protection Module...");
        
        // STEP 1: Create filesystem index
        let index = Arc::new(FilesystemIndex::new());
        
        // Create path resolver for policy engine
        let path_resolver = Arc::new(policy::PathResolver::new(index.clone()));
        
        // STEP 1: Create scanner
        let scanner = Arc::new(FileSystemScanner::new(
            index.clone(),
            path_resolver.clone(),
        ));
        
        // Initialize drives
        scanner.initialize_drives()
            .map_err(|e| format!("Failed to initialize drives: {}", e))?;
        
        // STEP 2: Create query interface
        let query = Arc::new(QueryInterface::new(index.clone()));
        
        // STEP 4: Create policy engine (without kernel for now)
        let policy_engine = match FilePolicyEngine::new(index.clone(), None) {
            Ok(engine) => engine,
            Err(e) => {
                log::warn!("⚠️ Policy engine in simulation mode: {}", e);
                Arc::new(FilePolicyEngine::new_simulated())
            }
        };
        
        log::info!("✅ File Protection Module initialized with {} drives", 
            scanner.initialize_drives().unwrap_or(0));
        
        Ok(FileProtectionModule {
            index,
            scanner,
            query,
            policy_engine,
            server_handle: None,
            kernel_event_sender: None,
            bridge_handle: None,
            event_queue: Arc::new(Mutex::new(Vec::new())),
            agent_id,
            token,
            enabled: false,
        })
    }
    
    /// Start the HTTP server for admin UI access
    pub async fn start_http_server(&mut self, bind_address: &str) -> Result<(), String> {
        if self.server_handle.is_some() {
            log::warn!("⚠️ HTTP server already running");
            return Ok(());
        }
        
        let addr = bind_address.parse()
            .map_err(|e| format!("Invalid bind address: {}", e))?;
        
        // Create API server for STEP 2
        let api_server = Arc::new(comms::QueryApiServer::new(
            self.scanner.clone(),
            self.query.clone(),
        ));
        
        // Initialize networking (STEP 5)
        let handle = networking::init_step5(
            api_server,
            self.policy_engine.clone(),
            addr,
        ).await
        .map_err(|e| format!("Failed to start HTTP server: {}", e))?;
        
        self.server_handle = Some(handle);
        log::info!("🌐 File Protection HTTP server started on {}", bind_address);
        
        Ok(())
    }
    
     // ADD THIS METHOD for kernel bridge
    // In start_kernel_bridge method:
pub async fn start_kernel_bridge(&mut self, ws_server: Arc<networking::WebSocketServer>) -> Result<(), String> {
    if self.bridge_handle.is_some() {
        log::warn!("⚠️ Kernel bridge already running");
        return Ok(());
    }
    
    log::info!("🔧 Starting kernel event bridge...");
    
    // Initialize kernel bridge (this returns the bridge and a sender)
    let (kernel_event_bridge, sender) = kernel::init_step6(
        ws_server,
        self.index.clone(),
        self.event_queue.clone(),
    );
    
    // ✅ Attach sender to policy engine
    self.policy_engine.attach_kernel_event_sender(sender.clone());
    
    // ✅ Store sender for potential future use
    self.kernel_event_sender = Some(sender);
    
    // ✅ Spawn bridge task - bridge is MOVED here, which is perfect
    // This is EXACTLY what the standalone main.rs does
    let handle = tokio::spawn(async move {
        kernel_event_bridge.start().await;
    });
    
    self.bridge_handle = Some(handle);
    
    log::info!("✅ Kernel event bridge started");
    Ok(())
}

     /// Clean up resources
    fn shutdown(&mut self) {
    if let Some(handle) = self.server_handle.take() {
        log::info!("🛑 File Protection HTTP server shutting down");
    }
    
    // Stop kernel bridge
    if let Some(handle) = self.bridge_handle.take() {
        handle.abort();
        log::info!("🛑 Kernel event bridge stopped");
    }
    
    self.enabled = false;
}

    /// Apply a policy from admin intent
    pub async fn apply_policy(&self, intent: policy::PolicyIntent) -> Result<u64, String> {
        self.policy_engine.apply_protection(intent)
    }
    
    /// Remove a policy
    pub async fn remove_policy(&self, policy_id: u64) -> Result<(), String> {
        self.policy_engine.remove_protection(policy_id)
    }
    
    /// Get all active policies
    pub fn get_policies(&self) -> Vec<policy::policy_store::ActivePolicy> {
        self.policy_engine.get_active_policies()
    }
    
    /// Get filesystem stats
    pub fn get_stats(&self) -> query_interface::SystemStats {
        match self.query.get_stats() {
            query_interface::QueryResponse::Stats(stats) => stats,
            _ => query_interface::SystemStats {
                total_nodes: 0,
                total_drives: 0,
                expanded_nodes: 0,
                memory_usage_bytes: 0,
                scan_state: query_interface::ScanState::Error("Unknown".to_string()),
            },
        }
    }
    
   

}

impl Drop for FileProtectionModule {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait::async_trait]
impl ProtectionModule for FileProtectionModule {
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        communicator: &ServerCommunicator,
        agent_id: u64,
        token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        
        // Check if file protection is enabled in policies
        let is_enabled = policy_engine.is_file_protection_enabled();
        
        if is_enabled && !self.enabled {
            // Enable file protection
            self.enabled = true;
            log::info!("✅ File Protection ENABLED by policy");
            
            match self.start_http_server("0.0.0.0:8081").await {
              Ok(()) => {
                    log::info!("✅ File Protection HTTP server started successfully on 0.0.0.0:8081");
                }
                Err(e) => {
                    log::error!("❌ Failed to start file protection HTTP server: {}", e);
                }
            }
            
        } else if !is_enabled && self.enabled {
            // Disable file protection
            self.enabled = false;
            self.shutdown();
            log::info!("🛑 File Protection DISABLED by policy");
        }
        
        // If enabled, do periodic maintenance or checks
        if self.enabled {
            // SYNC POLICIES from backend
            let file_policies = policy_engine.get_file_policies();
            if !file_policies.is_empty() {
                self.sync_policies_from_backend(file_policies).await;
            }

            // 2. REPORT EVENTS to backend
            let mut events_to_report = Vec::new();
            {
                let mut queue = self.event_queue.lock().await;
                if !queue.is_empty() {
                    events_to_report = std::mem::take(&mut *queue);
                }
            }

            if !events_to_report.is_empty() {
                log::info!("📤 Reporting {} file events to backend...", events_to_report.len());
                let request = FileEventRequest {
                    agent_id,
                    events: events_to_report,
                };
                if let Err(e) = communicator.send_file_events(&request, token).await {
                    log::error!("❌ Failed to report file events: {}", e);
                    // Optional: put them back in queue? Or just lose them to avoid bloat.
                    // For now, we log and drop them.
                } else {
                    log::info!("✅ File events reported successfully");
                }
            }

            // For now, just log stats
            let stats = self.get_stats();
            log::debug!("📊 File Protection Stats: {} nodes, {} drives, {} expanded",
                stats.total_nodes, stats.total_drives, stats.expanded_nodes);
        }
        
        Ok(())
    }
    
    fn get_name(&self) -> &str {
        "FileProtection"
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl FileProtectionModule {
    /// Synchronizes policies fetched from the main agent backend to the internal file engine
    async fn sync_policies_from_backend(&self, backend_policies: HashMap<String, Vec<String>>) {
        use crate::protection_modules::file_protection::policy::{PolicyIntent, ProtectionScope, ProtectionAction, ProtectionOperations};

        for (category, paths) in backend_policies {
            // Flexible action mapping
            let (action, operations) = if category.to_lowercase().contains("readonly") || category.to_lowercase().contains("read_only") {
                (ProtectionAction::Block, ProtectionOperations::default()) // Block mods, Allow read
            } else if category.to_lowercase().contains("audit") {
                (ProtectionAction::Audit, ProtectionOperations::audit_only())
            } else {
                // Default to Block all for anything else
                (ProtectionAction::Block, ProtectionOperations::full_protection())
            };

            for path in paths {
                // Try to find node ID for this path
                if let Some(node_id) = self.index.get_id_by_path(&path) {
                    // Determine scope from node type
                    let scope = if let Some(node) = self.index.get_node(node_id) {
                        match node.entry_type {
                            crate::protection_modules::file_protection::fs_index::EntryType::File => ProtectionScope::File,
                            _ => ProtectionScope::Folder,
                        }
                    } else {
                        ProtectionScope::File
                    };

                    let intent = PolicyIntent::new(
                        node_id,
                        scope,
                        action,
                        operations,
                        "Backend Sync",
                        Some("Automatically synced from backend"),
                    );

                    // Check if already applied (simplified)
                    let active = self.policy_engine.get_active_policies();
                    if !active.iter().any(|p| p.intent.node_id == node_id && p.intent.action == action) {
                        if let Err(e) = self.policy_engine.apply_protection(intent) {
                            log::warn!("⚠️ Failed to apply file policy for {}: {}", path, e);
                        } else {
                            log::info!("🛡️ Applied File Protection Rule: {} ({:?})", path, action);
                        }
                    }
                }
            }
        }
    }
}