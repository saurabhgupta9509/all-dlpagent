// // src/protection_modules/security_monitor/mod.rs

// pub mod image_processing;
// pub mod ocr;
// pub mod rule_engine;
// pub mod llm_threat_assessor;
// pub mod types;
// pub mod monitor;

// use std::error::Error;
// use std::sync::Arc;
// use tokio::sync::RwLock;
// use tokio::sync::mpsc;
// use std::sync::atomic::{AtomicBool, Ordering};
// use std::thread;
// use std::time::Duration;

// use crate::{PolicyEngine, ServerCommunicator, protection_modules::ProtectionModule};

// pub struct SecurityMonitorProtection {
//     command_sender: Option<mpsc::UnboundedSender<MonitorCommand>>,
//     agent_id: u64,
//     token: String,
//     enabled: bool,
//     is_running: Arc<AtomicBool>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
// }

// // Commands to send to the OCR thread
// enum MonitorCommand {
//     Start,
//     Stop,
//     ProcessFrame,
//     Shutdown,
// }

// impl SecurityMonitorProtection {
//     pub fn new(agent_id: u64, token: String, communicator: Arc<RwLock<ServerCommunicator>>) -> Self {
//         Self {
//             command_sender: None,
//             agent_id,
//             token,
//             enabled: false,
//             is_running: Arc::new(AtomicBool::new(false)),
//             communicator,
//         }
//     }

//     fn start_ocr_thread(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         if self.command_sender.is_some() {
//             return Ok(());
//         }

//         let (tx, mut rx) = mpsc::unbounded_channel(); // FIX: make rx mutable
//         self.command_sender = Some(tx);
        
//         let is_running = Arc::clone(&self.is_running);
        
//         // Spawn a dedicated thread for OCR processing (not async)
//         thread::spawn(move || {
//             log::info!("🔄 Starting OCR processing thread");
            
//             // Create the monitor in the dedicated thread
//             let mut monitor = match monitor::SecurityMonitor::new() {
//                 Ok(m) => m,
//                 Err(e) => {
//                     log::error!("❌ Failed to initialize Security Monitor: {}", e);
//                     return;
//                 }
//             };
            
//             // Main thread loop
//             while is_running.load(Ordering::Relaxed) {
//                 // Check for commands
//                 while let Ok(cmd) = rx.try_recv() {
//                     match cmd {
//                         MonitorCommand::Start => {
//                             log::info!("▶️ OCR thread received Start command");
//                         }
//                         MonitorCommand::Stop => {
//                             log::info!("⏸️ OCR thread received Stop command");
//                         }
//                         MonitorCommand::ProcessFrame => {
//                             // Process frame synchronously in this thread
//                             if let Err(e) = monitor.process_frame() {
//                                 log::error!("❌ Error processing frame in OCR thread: {}", e);
//                             }
                            
//                             // Check maintenance periodically
//                             if let Err(e) = monitor.maintenance_check() {
//                                 log::error!("❌ Error in maintenance check: {}", e);
//                             }
//                         }
//                         MonitorCommand::Shutdown => {
//                             log::info!("🛑 OCR thread shutting down");
//                             return;
//                         }
//                     }
//                 }
                
//                 // Sleep a bit to prevent busy waiting
//                 thread::sleep(Duration::from_millis(100));
//             }
            
//             log::info!("🛑 OCR thread exiting");
//         });
        
//         log::info!("✅ OCR processing thread started");
//         Ok(())
//     }

//     fn stop_ocr_thread(&mut self) {
//         self.is_running.store(false, Ordering::Relaxed);
        
//         if let Some(tx) = &self.command_sender {
//             let _ = tx.send(MonitorCommand::Shutdown);
//         }
        
//         self.command_sender = None;
//         log::info!("🧹 OCR thread stopped");
//     }

//     fn send_frame_command(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         if let Some(tx) = &self.command_sender {
//             tx.send(MonitorCommand::ProcessFrame)
//                 .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
//         }
//         Ok(())
//     }
// }

// #[async_trait::async_trait]
// impl ProtectionModule for SecurityMonitorProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         _communicator: &ServerCommunicator,
//         _agent_id: u64,
//         _token: &str,
//     ) -> Result<(), Box<dyn Error + Send + Sync>> {
//         if !policy_engine.is_policy_active("POLICY_OCR_MONITOR") {
//             if self.enabled {
//                 log::info!("🛑 Security Monitor DISABLED by policy");
//                 self.enabled = false;
//                 self.stop_ocr_thread();
//             }
//             return Ok(());
//         }

//         if !self.enabled {
//             log::info!("✅ Security Monitor ENABLED by policy");
//             self.enabled = true;
//             self.start_ocr_thread()?;
//             self.is_running.store(true, Ordering::Relaxed);
            
//             // Send initial start command
//             if let Some(tx) = &self.command_sender {
//                 tx.send(MonitorCommand::Start)
//                     .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
//             }
//         }

//         // Send command to process a frame
//         self.send_frame_command()?;
        
//         Ok(())
//     }
    
//     fn get_name(&self) -> &str {
//         "SecurityMonitor"
//     }
// }

// impl Drop for SecurityMonitorProtection {
//     fn drop(&mut self) {
//         self.stop_ocr_thread();
//     }
// }
// src/protection_modules/security_monitor/mod.rs

// src/protection_modules/security_monitor/mod.rs
// src/protection_modules/security_monitor/mod.rs

// pub mod image_processing;
// pub mod ocr;
// pub mod rule_engine;
// pub mod llm_threat_assessor;
// pub mod types;
// pub mod monitor;

// use std::error::Error;
// use std::sync::Arc;
// use tokio::sync::RwLock;
// use std::time::{Duration, Instant};
// use std::cell::RefCell;

// use crate::{PolicyEngine, ServerCommunicator, protection_modules::ProtectionModule};

// pub struct SecurityMonitorProtection {
//     agent_id: u64,
//     token: String,
//     enabled: bool,
//     last_execution: Instant,
//     last_maintenance: Instant,
//     interval: Duration,
//     maintenance_interval: Duration,
//     // Use RefCell for interior mutability since we're in single-threaded context
//     monitor: RefCell<Option<monitor::SecurityMonitor>>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
// }

// impl SecurityMonitorProtection {
//     pub fn new(agent_id: u64, token: String, communicator: Arc<RwLock<ServerCommunicator>>) -> Self {
//         Self {
//             agent_id,
//             token,
//             enabled: false,
//             last_execution: Instant::now(),
//             last_maintenance: Instant::now(),
//             interval: Duration::from_secs(5), // Process every 5 seconds
//             maintenance_interval: Duration::from_secs(60), // Maintenance every 60 seconds
//             monitor: RefCell::new(None),
//             communicator,
//         }
//     }

//     fn ensure_monitor_initialized(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         let mut monitor_ref = self.monitor.borrow_mut();
//         if monitor_ref.is_none() {
//             log::info!("🔍 Initializing Security Monitor...");
            
//             // Create necessary directories first
//             self.setup_directories()?;
            
//             // Initialize the monitor
//             let monitor = monitor::SecurityMonitor::new()?;
//             *monitor_ref = Some(monitor);
            
//             log::info!("✅ Security Monitor initialized successfully");
//         }
//         Ok(())
//     }

//     fn cleanup(&mut self) {
//         let mut monitor_ref = self.monitor.borrow_mut();
//         *monitor_ref = None;
//         self.enabled = false;
//         log::info!("🧹 Security Monitor cleaned up");
//     }

//     async fn do_monitoring_work(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         // Get mutable access to monitor
//         let mut monitor_ref = self.monitor.borrow_mut();
//         if let Some(monitor) = monitor_ref.as_mut() {
//             // Process a frame
//             monitor.process_frame().await?;
//         }
//         Ok(())
//     }

//     async fn do_maintenance(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         // Get mutable access to monitor
//         let mut monitor_ref = self.monitor.borrow_mut();
//         if let Some(monitor) = monitor_ref.as_mut() {
//             // Run maintenance
//             monitor.maintenance_check().await?;
//         }
//         Ok(())
//     }

//     fn setup_directories(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         use std::fs;
        
//         let dirs = vec![
//             "screenshots",
//             "logs",
//             "certificates"
//         ];
        
//         for dir in dirs {
//             fs::create_dir_all(dir)?;
//         }
        
//         Ok(())
//     }
// }

// #[async_trait::async_trait]
// impl ProtectionModule for SecurityMonitorProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         _communicator: &ServerCommunicator,
//         _agent_id: u64,
//         _token: &str,
//     ) -> Result<(), Box<dyn Error + Send + Sync>> {
//         // Check if policy is active - SAME AS OTHER MODULES
//         if !policy_engine.is_policy_active("POLICY_OCR_MONITOR") {
//             if self.enabled {
//                 log::info!("🛑 Security Monitor DISABLED by policy");
//                 self.cleanup();
//             }
//             return Ok(());
//         }

//         // Enable if not already enabled - SAME AS OTHER MODULES
//         if !self.enabled {
//             log::info!("✅ Security Monitor ENABLED by policy");
//             self.enabled = true;
//             log::info!("🚀 Starting Security Monitor...");
            
//             // Initialize monitor on first enable
//             self.ensure_monitor_initialized()?;
            
//             // Print banner through monitor
//             let mut monitor_ref = self.monitor.borrow_mut();
//             if let Some(monitor) = monitor_ref.as_mut() {
//                 monitor.print_banner();
//             }
//         }

//         // Initialize monitor if needed
//         self.ensure_monitor_initialized()?;

//         // Check if it's time to execute frame processing
//         if self.last_execution.elapsed() >= self.interval {
//             self.do_monitoring_work().await?;
//             self.last_execution = Instant::now();
//         }

//         // Check if it's time for maintenance
//         if self.last_maintenance.elapsed() >= self.maintenance_interval {
//             self.do_maintenance().await?;
//             self.last_maintenance = Instant::now();
//         }
        
//         Ok(())
//     }
    
//     fn get_name(&self) -> &str {
//         "SecurityMonitor"
//     }
// }



// // src/protection_modules/security_monitor/mod.rs
// pub mod image_processing;
// pub mod ocr;
// pub mod rule_engine;
// pub mod llm_threat_assessor;
// pub mod types;
// pub mod monitor;

// use std::any::Any;
// use std::error::Error;
// use std::sync::Arc;
// use std::thread;
// use tokio::sync::RwLock;
// use std::time::{Duration, Instant};
// use std::sync::mpsc;
// use tokio::task;
// use crate::communication::OcrStatusUpdate;
// use crate::{PolicyEngine, ServerCommunicator, protection_modules::ProtectionModule};
// use crate::protection_modules::security_monitor::types::{RealtimeUpdate, UpdateData, UpdateType};

// pub struct SecurityMonitorProtection {
//     agent_id: u64,
//     token: String,
//     enabled: bool,
//     last_execution: Instant,
//     last_maintenance: Instant,
//     interval: Duration,
//     maintenance_interval: Duration,
//     // Channel to send commands to OCR thread
//     ocr_tx: Option<mpsc::Sender<OcrCommand>>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
//     realtime_tx: Option<mpsc::Sender<RealtimeUpdate>>,
// }

// enum OcrCommand {
//     ProcessFrame,
//     Shutdown,
// }

// // Use this wrapper to make it Send + Sync
// pub struct ThreadSafeSecurityMonitorProtection {
//     inner: Arc<tokio::sync::Mutex<SecurityMonitorProtection>>,
// }

// impl ThreadSafeSecurityMonitorProtection {
//     pub fn new(agent_id: u64, token: String, communicator: Arc<RwLock<ServerCommunicator>>) -> Self {
//         Self {
//             inner: Arc::new(tokio::sync::Mutex::new(SecurityMonitorProtection::new(
//                 agent_id, token, communicator
//             ))),
//         }
//     }

//      pub async fn update_token(&self, new_token: String) {
//         let mut guard = self.inner.lock().await;
//         guard.update_token(new_token);
//     }
// }

// impl SecurityMonitorProtection {
    
//      pub fn update_token(&mut self, new_token: String) {
//         log::info!("🔑 Updating Security Monitor token");
//         self.token = new_token;
//     }

//     pub fn new(agent_id: u64, token: String, communicator: Arc<RwLock<ServerCommunicator>>) -> Self {
//         let (ocr_tx, ocr_rx) = mpsc::channel();
//         let (realtime_tx, realtime_rx) = mpsc::channel(); // NEW: Real-time channel
            
//         // // Spawn real-time sender thread
//         // let realtime_thread_tx = realtime_tx.clone(); // for thread
//         //     let realtime_main_tx = realtime_tx.clone();   // for sending initial status

//          let rt_communicator = communicator.clone();
//          let ocr_communicator = communicator.clone();
//         // let communicator_clone1 = communicator.clone();
//         // let communicator_clone2 = communicator.clone();
//         // let communicator_clone3 = communicator.clone();

//         let agent_id_clone = agent_id;

//         let token_for_realtime = token.clone();
//         let token_for_ocr = token.clone();
//         let token_for_status = token.clone();
        
//          // Clone realtime_tx for the monitor thread
//         let realtime_tx_for_monitor = realtime_tx.clone();

//         thread::spawn(move || {
//             // This thread sends updates to server
//             for update in realtime_rx {
//                 // Send to server via HTTP or WebSocket
//                 let comm = rt_communicator.blocking_read();
//                let fut = comm.send_realtime_update(
//                 agent_id_clone,
//                 &token_for_realtime,
//                 &update,
//             );

//             if let Err(e) = tokio::runtime::Handle::current().block_on(fut) {
//                 log::error!("Failed realtime update: {}", e);
//             }
//             }
//         });
//         //    let ocr_communicator = communicator.clone();
//         // Spawn OCR processing thread (updated)
//         thread::spawn(move || { 
//             let rt = tokio::runtime::Runtime::new().unwrap();
//              let communicator_arc = ocr_communicator; // Rename for clarity
//             let mut monitor = match monitor::SecurityMonitor::new(
//                 agent_id_clone,
//                 token_for_ocr.clone(),
//                 realtime_tx_for_monitor,
//                  //used clone
//             ) {
//                 Ok(m) => m,
//                 Err(e) => {
//                     log::error!("Failed to initialize OCR monitor: {}", e);
//                     return;
//                 }
//             };
            
//             monitor.print_banner();
            
//             // Send initial status
//             // let _ = realtime_main_tx.send(RealtimeUpdate {
//             //     update_type: UpdateType::StatusUpdate,
//             //     timestamp: chrono::Utc::now().to_rfc3339(),
//             //     agent_id: agent_id_clone,
//             //     data: UpdateData::Status(monitor.get_status()),
//             // });
//              let comm = communicator_arc.blocking_read();
//               rt.block_on(async {
//                 // let comm = communicator_clone2.blocking_read();
//                 if let Err(e) = send_initial_ocr_status(&monitor, &*comm, &token_for_status).await {
//                     log::error!("Failed to send initial OCR status: {}", e);
//                 }
//             });
            
//             for cmd in ocr_rx {
//                 match cmd {
//                     OcrCommand::ProcessFrame => {

//                          let comm = communicator_arc.blocking_read();

//                         let result = rt.block_on(async {
//                             // monitor.process_frame( &*comm ,&token_for_status).await
//                             monitor.process_frame(&*comm, &token_for_status).await
//                         });
                        
                         
//                         if let Err(e) = result {
//                             log::error!("OCR processing error: {}", e);
//                         }

//                         // // Send screenshot update
//                         // if let Some(screenshot_data) = monitor.get_last_screenshot_data() {
//                         //     let _ = realtime_main_tx.send(RealtimeUpdate {
//                         //         update_type: UpdateType::ScreenshotCaptured,
//                         //         timestamp: chrono::Utc::now().to_rfc3339(),
//                         //         agent_id: agent_id_clone,
//                         //         data: UpdateData::Screenshot(screenshot_data),
//                         //     });
//                         // }
//                         // let comm_status = communicator_arc.blocking_read();
//                          rt.block_on(async {
//                             let comm = communicator_arc.blocking_read();
//                             if let Err(e) = send_ocr_status_update(&monitor, &comm, &token_for_status).await {
//                                 log::error!("Failed to send OCR status: {}", e);
//                             }
//                         });
//                     }
//                     OcrCommand::Shutdown => break,
//                 }
//             }
//         });
        
//        Self {
//             agent_id,
//             token: token,
//             enabled: false,
//             last_execution: Instant::now(),
//             last_maintenance: Instant::now(),
//             interval: Duration::from_secs(5),
//             maintenance_interval: Duration::from_secs(60),
//             ocr_tx: Some(ocr_tx),
//             realtime_tx: Some(realtime_tx),
//             communicator,
//         }
//     }

     

//     async fn send_ocr_status_to_server(
//     &self,
//     monitor: &monitor::SecurityMonitor,
// ) -> Result<(), Box<dyn Error + Send + Sync>> {
//     let status_update = OcrStatusUpdate {
//         agent_id: self.agent_id,
//         ocr_enabled: true,
//         last_screenshot_time: chrono::Utc::now().to_rfc3339(),
//         threat_score: monitor.last_certificate.as_ref().map_or(0.0, |c| c.threat_score),
//         violations_last_24h: monitor.violation_count,
//         agent_hostname: monitor.device_addr.clone(),
//     };
    
//     let comm = self.communicator.read().await;
//     comm.http()
//         .post(&format!("{}/api/agent/ocr/status", "YOUR_BASE_URL"))
//         .bearer_auth(&self.token)
//         .json(&status_update)
//         .send()
//         .await?;
    
//     Ok(())
// }
    
//     fn send_realtime_update(&self, update: RealtimeUpdate) -> Result<(), Box<dyn Error + Send + Sync>> {
//         if let Some(tx) = &self.realtime_tx {
//             tx.send(update)
//                 .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
//         } else {
//             Ok(())
//         }
//     }

//     fn send_ocr_command(&self, command: OcrCommand) -> Result<(), Box<dyn Error + Send + Sync>> {
//         if let Some(tx) = &self.ocr_tx {
//             tx.send(command)
//                 .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
//         }
//         Ok(())
//     }

//     fn setup_directories(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         use std::fs;
        
//         let dirs = vec![
//             "screenshots",
//             "logs",
//             "certificates"
//         ];
        
//         for dir in dirs {
//             fs::create_dir_all(dir)?;
//         }
        
//         log::info!("📁 Security Monitor directories created");
//         Ok(())
//     }

//     fn cleanup(&mut self) {
//         // Send shutdown command to OCR thread
//         if let Some(tx) = self.ocr_tx.take() {
//             let _ = tx.send(OcrCommand::Shutdown);
//         }
        
//         self.enabled = false;
//         log::info!("🧹 Security Monitor cleaned up");
//     }
// }

//  // Helper functions for sending OCR status
// async fn send_initial_ocr_status(
//     monitor: &monitor::SecurityMonitor,
//     communicator: &ServerCommunicator,
//     token: &str,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     let status_update = OcrStatusUpdate {
//         agent_id: monitor.agent_id,
//         ocr_enabled: true,
//         last_screenshot_time: chrono::Utc::now().to_rfc3339(),
//         threat_score: 0.0, // Initial score
//         violations_last_24h: 0,
//         agent_hostname: "Initializing...".to_string(),
//     };
    
//     communicator.send_ocr_status(monitor.agent_id, token, &status_update).await
// }
  
//     async fn send_ocr_status_update(
//     monitor: &monitor::SecurityMonitor,
//     communicator: &ServerCommunicator,
//     token: &str,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     let status_update = OcrStatusUpdate {
//         agent_id: monitor.agent_id,
//         ocr_enabled: true,
//         last_screenshot_time: chrono::Utc::now().to_rfc3339(),
//         threat_score: monitor.calculate_current_threat_score(),
//         violations_last_24h: monitor.violation_count,
//         agent_hostname: monitor.device_addr.clone(),
//     };
    
//     communicator.send_ocr_status(monitor.agent_id, token, &status_update).await
// }

// #[async_trait::async_trait]
// impl ProtectionModule for ThreadSafeSecurityMonitorProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         _communicator: &ServerCommunicator,
//         _agent_id: u64,
//         _token: &str,
//     ) -> Result<(), Box<dyn Error + Send + Sync>> {
//         let mut inner = self.inner.lock().await;
        
//         // Check if policy is active
//         if !policy_engine.is_policy_active("POLICY_OCR_MONITOR") {
//             if inner.enabled {
//                 log::info!("🛑 Security Monitor DISABLED by policy");
//                 inner.cleanup();
//             }
//             return Ok(());
//         }

//         // Enable if not already enabled
//         if !inner.enabled {
//             log::info!("✅ Security Monitor ENABLED by policy");
//             inner.enabled = true;
//             log::info!("🚀 Starting Security Monitor...");
            
//             // Create necessary directories
//             if let Err(e) = inner.setup_directories() {
//                 log::error!("❌ Failed to setup directories: {}", e);
//                 return Err(e);
//             }
            
//             log::info!("🔍 Security Monitor initialized and ready");
//         }

//         // Check if it's time to execute frame processing
//         if inner.last_execution.elapsed() >= inner.interval {
//             // Send command to OCR thread
//             if let Err(e) = inner.send_ocr_command(OcrCommand::ProcessFrame) {
//                 log::error!("❌ Failed to send OCR command: {}", e);
//                 return Err(e);
//             }
            
//             inner.last_execution = Instant::now();
//             log::debug!("📸 Sent screenshot capture command to OCR thread");
//         }

//         // Check if it's time for maintenance
//         if inner.last_maintenance.elapsed() >= inner.maintenance_interval {
//             // Note: Maintenance is handled inside the OCR thread
//             inner.last_maintenance = Instant::now();
//             log::debug!("🔄 Maintenance check scheduled in OCR thread");
//         }
        
//         Ok(())
//     }
    
//     fn get_name(&self) -> &str {
//         "SecurityMonitor"
//     }
    
//     fn as_any(&self) -> &dyn Any {
//         self
//     }
// }

// impl Drop for SecurityMonitorProtection {   
//     fn drop(&mut self) {
//         // Clean up on drop
//         self.cleanup();
//     }
// }
// src/protection_modules/security_monitor/mod.rs
pub mod image_processing;
pub mod ocr;
pub mod rule_engine;
pub mod llm_threat_assessor;
pub mod types;
pub mod monitor;

use std::any::Any;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::sync::mpsc;

use tokio::sync::RwLock;

use crate::communication::OcrStatusUpdate;
use crate::protection_modules::security_monitor::monitor::SecurityMonitor;
use crate::{PolicyEngine, ServerCommunicator, protection_modules::ProtectionModule};
use crate::protection_modules::security_monitor::types::{RealtimeUpdate, UpdateData, UpdateType};

pub struct SecurityMonitorProtection {
    agent_id: u64,
    // ✅ token is now shared & mutable across threads
    token: Arc<Mutex<String>>,
    enabled: bool,
    last_execution: Instant,
    last_maintenance: Instant,
    interval: Duration,
    maintenance_interval: Duration,
    // Channel to send commands to OCR thread
    ocr_tx: Option<mpsc::Sender<OcrCommand>>,
    communicator: Arc<RwLock<ServerCommunicator>>,
    realtime_tx: Option<mpsc::Sender<RealtimeUpdate>>,
}

enum OcrCommand {
    ProcessFrame,
    RunMaintenance,
    Shutdown,
}

// Thread-safe wrapper so it can be stored as a ProtectionModule
pub struct ThreadSafeSecurityMonitorProtection {
    inner: Arc<tokio::sync::Mutex<SecurityMonitorProtection>>,
}

impl ThreadSafeSecurityMonitorProtection {
    pub fn new(
        agent_id: u64,
        token: String,
        communicator: Arc<RwLock<ServerCommunicator>>,
    ) -> Self {
        // ✅ Wrap token in Arc<Mutex<>> so background threads always see latest
        let token_shared = Arc::new(Mutex::new(token));
        let inner = SecurityMonitorProtection::new(agent_id, token_shared.clone(), communicator);

        Self {
            inner: Arc::new(tokio::sync::Mutex::new(inner)),
        }
    }

    /// Called from AgentCore when the main token changes.
    pub async fn update_token(&self, new_token: String) {
        let mut guard = self.inner.lock().await;
        guard.update_token(new_token);
    }
}

impl SecurityMonitorProtection {
    /// Update the token used by OCR / realtime threads
    pub fn update_token(&mut self, new_token: String) {
        log::info!("🔑 Updating Security Monitor token");
        if let Ok(mut t) = self.token.lock() {
            *t = new_token;
        } else {
            log::error!("Failed to lock token mutex while updating token");
        }
    }

    pub fn new(
        agent_id: u64,
        token: Arc<Mutex<String>>,
        communicator: Arc<RwLock<ServerCommunicator>>,
    ) -> Self {
        let (ocr_tx, ocr_rx) = mpsc::channel();
        let (realtime_tx, realtime_rx) = mpsc::channel();

        let rt_communicator = communicator.clone();
        let ocr_communicator = communicator.clone();

        let agent_id_clone = agent_id;

        // ✅ Cloned token handles for each thread
        let token_for_realtime = token.clone();
        let token_for_ocr = token.clone();
        let token_for_status = token.clone();

        // -------- REALTIME SENDER THREAD ----------
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

            for update in realtime_rx {
                let comm_arc = rt_communicator.clone();
                let token_arc = token_for_realtime.clone();

                rt.block_on(async move {
                    let comm = comm_arc.read().await;

                    // Read latest token
                    let token_value = {
                        let lock = token_arc.lock().unwrap();
                        lock.clone()
                    };

                    if let Err(e) = comm
                        .send_realtime_update(agent_id_clone, &token_value, &update)
                        .await
                    {
                        log::error!("Failed realtime update: {}", e);
                    }
                });
            }

            log::info!("🔌 Realtime thread exiting");
        });

        let realtime_tx_clone_for_struct = realtime_tx.clone();

        // -------- OCR PROCESSING THREAD ----------
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
            let communicator_arc = ocr_communicator;

            // Get initial token value for SecurityMonitor::new
            let initial_token = {
                let lock = token_for_ocr.lock().unwrap();
                lock.clone()
            };

            let mut monitor = match monitor::SecurityMonitor::new(
                agent_id_clone,
                initial_token.clone(),
                realtime_tx.clone(),
                communicator_arc.clone()
            ) {
                Ok(m) => m,
                Err(e) => {
                    log::error!("Failed to initialize OCR monitor: {}", e);
                    return;
                }
            };

            monitor.print_banner();

            // Initial status send
            {
                let comm_arc = communicator_arc.clone();
                let token_arc = token_for_status.clone();
                rt.block_on(async {
                    let comm = comm_arc.read().await;
                    let token_value = {
                        let lock = token_arc.lock().unwrap();
                        lock.clone()
                    };

                    // Get username from communicator credentials
                    let username = comm.get_credentials()
                        .map(|c| c.username.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    if let Err(e) =
                        send_initial_ocr_status(&monitor, &*comm, &token_value, &username).await
                    {
                        log::error!("Failed to send initial OCR status: {}", e);
                    }
                });
            }

            // Main OCR command loop
            for cmd in ocr_rx {
                match cmd {
                    OcrCommand::ProcessFrame => {
                        // 1) Process frame
                        {
                            let comm_arc = communicator_arc.clone();
                            let token_arc = token_for_ocr.clone();

                            rt.block_on(async {
                                let comm = comm_arc.read().await;
                                let token_value = {
                                    let lock = token_arc.lock().unwrap();
                                    lock.clone()
                                };

                                if let Err(e) = monitor.process_frame(&*comm, &token_value).await {
                                    log::error!("OCR processing error: {}", e);
                                }
                            });
                        }

                        // 2) Send updated OCR status
                        {
                            let comm_arc = communicator_arc.clone();
                            let token_arc = token_for_status.clone();

                            rt.block_on(async {
                                let comm = comm_arc.read().await;
                                let token_value = {
                                    let lock = token_arc.lock().unwrap();
                                    lock.clone()
                                };

                                // Get username from communicator credentials
                                let username = comm.get_credentials()
                                    .map(|c| c.username.clone())
                                    .unwrap_or_else(|| "unknown".to_string());

                                if let Err(e) =
                                    send_ocr_status_update(&monitor, &*comm, &token_value, &username).await
                                {
                                    log::error!("Failed to send OCR status: {}", e);
                                }
                            });
                        }
                    }

                    OcrCommand::RunMaintenance => {
                        let comm_arc = communicator_arc.clone();
                        let token_arc = token_for_status.clone();

                        rt.block_on(async {
                            let token_value = {
                                let lock = token_arc.lock().unwrap();
                                lock.clone()
                            };

                            if let Err(e) = monitor.maintenance_check(&comm_arc, &token_value).await {
                                log::error!("❌ Maintenance error: {}", e);
                            }
                        });
                    }

                    OcrCommand::Shutdown => {
                        log::info!("🛑 OCR thread received shutdown command");
                        break;
                    }
                }
            }

            log::info!("🔌 OCR thread exiting");
        });

        Self {
            agent_id,
            token, // shared Arc<Mutex<String>>
            enabled: false,
            last_execution: Instant::now(),
            last_maintenance: Instant::now(),
            interval: Duration::from_secs(5),
            maintenance_interval: Duration::from_secs(60),
            ocr_tx: Some(ocr_tx),
            realtime_tx: Some(realtime_tx_clone_for_struct),
            communicator,
        }
    }

    async fn send_ocr_status_to_server(
        &self,
        monitor: &SecurityMonitor,
        username: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (_, threat_arrow, trend_color) = monitor.get_threat_trend_info();
        
        let status_update = OcrStatusUpdate {
            agent_id: self.agent_id,
            username: username.to_string(),
            ocr_enabled: true,
            last_screenshot_time: chrono::Utc::now().to_rfc3339(),
            threat_score: monitor.calculate_current_threat_score(),
            threat_arrow,
            trend_color,
            violations_last_24h: monitor.violation_count,
            agent_hostname: monitor.device_addr.clone(),
        };

        let comm = self.communicator.read().await;
        let token = {
            let lock = self.token.lock().unwrap();
            lock.clone()
        };

        comm.http()
            .post(&format!("{}/api/agent/ocr/status", "YOUR_BASE_URL"))
            .bearer_auth(&token)
            .json(&status_update)
            .send()
            .await?;

        Ok(())
    }

    fn send_realtime_update(
        &self,
        update: RealtimeUpdate,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(tx) = &self.realtime_tx {
            tx.send(update)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
        } else {
            Ok(())
        }
    }

    fn send_ocr_command(&self, command: OcrCommand) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(tx) = &self.ocr_tx {
            tx.send(command)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        }
        Ok(())
    }

    fn setup_directories(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        use std::fs;

        let dirs = vec!["screenshots", "logs", "certificates"];

        for dir in dirs {
            fs::create_dir_all(dir)?;
        }

        log::info!("📁 Security Monitor directories created");
        Ok(())
    }

    fn cleanup(&mut self) {
        if let Some(tx) = self.ocr_tx.take() {
            let _ = tx.send(OcrCommand::Shutdown);
        }

        self.enabled = false;
        log::info!("🧹 Security Monitor cleaned up");
    }
}

// ===== Helper functions =====
async fn send_initial_ocr_status(
    monitor: &SecurityMonitor,
    communicator: &ServerCommunicator,
    token: &str,
    username: &str,  
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_, threat_arrow, trend_color) = monitor.get_threat_trend_info();
    
    let status_update = OcrStatusUpdate {
        agent_id: monitor.agent_id,
        username: username.to_string(),  // ← Add username
        ocr_enabled: true,
        last_screenshot_time: chrono::Utc::now().to_rfc3339(),
        threat_score: 0.0, // Initial score
        threat_arrow,
        trend_color,
        violations_last_24h: 0,
        agent_hostname: "Initializing...".to_string(),
    };

    communicator
        .send_ocr_status(monitor.agent_id, token, &status_update)
        .await
}

async fn send_ocr_status_update(
    monitor: &SecurityMonitor,
    communicator: &ServerCommunicator,
    token: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_, threat_arrow, trend_color) = monitor.get_threat_trend_info();
    
    let status_update = monitor.get_ocr_status_update().await;

    // OcrStatusUpdate {
    //     agent_id: monitor.agent_id,
    //     username: username.to_string(),  // ← Add username
    //     ocr_enabled: true,
    //     last_screenshot_time: chrono::Utc::now().to_rfc3339(),
    //     threat_score: monitor.calculate_current_threat_score(),
    //     threat_arrow,
    //     trend_color,
    //     violations_last_24h: monitor.violation_count,
    //     agent_hostname: monitor.device_addr.clone(),
    // };

     println!("📤 Sending OCR status for agent {}:", monitor.agent_id);
    println!("   - last_screenshot_time from update: {}", status_update.last_screenshot_time);
    println!("   - has screenshot data: {}", monitor.last_screenshot_data.is_some());
    
  if let Some(data) = &monitor.last_screenshot_data {
        println!("   - screenshot path: {}", data.path);
        // Try to extract timestamp manually to verify
        if let Some(extracted) = SecurityMonitor::extract_timestamp_from_path(&data.path) {
            println!("   - extracted timestamp: {}", extracted);
        } else {
            println!("   - failed to extract timestamp from path");
        }
    } else {
        println!("   ⚠️ No screenshot data available - using current time: {}", 
                 status_update.last_screenshot_time);
    }

    communicator
        .send_ocr_status(monitor.agent_id, token, &status_update)
        .await
}

// ===== ProtectionModule impl =====

#[async_trait::async_trait]
impl ProtectionModule for ThreadSafeSecurityMonitorProtection {
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        _communicator: &ServerCommunicator,
        _agent_id: u64,
        _token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut inner = self.inner.lock().await;

        // Policy check
        if !policy_engine.is_policy_active("POLICY_OCR_MONITOR") {
            if inner.enabled {
                log::info!("🛑 Security Monitor DISABLED by policy");
                inner.cleanup();
            }
            return Ok(());
        }

        if !inner.enabled {
            log::info!("✅ Security Monitor ENABLED by policy");
            inner.enabled = true;
            log::info!("🚀 Starting Security Monitor...");

            if let Err(e) = inner.setup_directories() {
                log::error!("❌ Failed to setup directories: {}", e);
                return Err(e);
            }

            log::info!("🔍 Security Monitor initialized and ready");
        }

        // Periodic OCR trigger
        if inner.last_execution.elapsed() >= inner.interval {
            if let Err(e) = inner.send_ocr_command(OcrCommand::ProcessFrame) {
                log::error!("❌ Failed to send OCR command: {}", e);
                return Err(e);
            }

            inner.last_execution = Instant::now();
            log::debug!("📸 Sent screenshot capture command to OCR thread");
        }

        if inner.last_maintenance.elapsed() >= inner.maintenance_interval {
            inner.last_maintenance = Instant::now();
            log::debug!("🔄 Maintenance check scheduled in OCR thread");

            if let Err(e) = inner.send_ocr_command(OcrCommand::RunMaintenance) {
                log::error!("❌ Failed to send maintenance command: {}", e);
            }
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        "SecurityMonitor"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for SecurityMonitorProtection {
    fn drop(&mut self) {
        self.cleanup();
    }
}