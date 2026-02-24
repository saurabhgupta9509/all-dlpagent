// src/kernel/kernel_event_bridge.rs
//! Kernel → Agent Event Bridge (STEP 6.1)
//! Core Principle: Receive events from kernel, forward to Agent

use std::sync::Arc;
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};

use crate::protection_modules::file_protection::networking::WebSocketServer;
use crate::protection_modules::file_protection::fs_index::FilesystemIndex;
use crate::communication::FileEventDTO;
use tokio::sync::Mutex;

/// Kernel event sent from minifilter to Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    pub node_id: u64,              // ID from filesystem index
    pub policy_id: u64,            // Policy that was matched
    pub operation: KernelOperation, // Operation type
    pub process_name: String,      // Process that triggered it
    pub process_id: u32,           // Process ID
    pub decision: EnforcementDecision, // What happened
    pub timestamp: u64,            // When it happened
}

/// Filesystem operation types (from kernel)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KernelOperation {
    Read,
    Write,
    Delete,
    Rename,
    Create,
    QueryInfo, // Metadata read
    SetInfo,   // Metadata write
}

/// Enforcement decision from kernel
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EnforcementDecision {
    Allowed,      // Policy allowed it
    Blocked,      // Policy blocked it
    Audited,      // Policy audited it (allowed + logged)
    NotProtected, // No policy matched
}

/// Kernel event bridge - connects kernel events to Agent
pub struct KernelEventBridge {
    ws_server: Arc<WebSocketServer>,
    index: Arc<FilesystemIndex>,
    event_queue: Arc<Mutex<Vec<FileEventDTO>>>,
    event_receiver: mpsc::Receiver<KernelEvent>,
}

impl KernelEventBridge {
    /// Create new kernel event bridge
    pub fn new(
        ws_server: Arc<WebSocketServer>,
        index: Arc<FilesystemIndex>,
        event_queue: Arc<Mutex<Vec<FileEventDTO>>>,
    ) -> (Self, mpsc::Sender<KernelEvent>) {
        // Create channel for kernel events
        let (event_sender, event_receiver) = mpsc::channel(100);
        
        let bridge = KernelEventBridge {
            ws_server,
            index,
            event_queue,
            event_receiver,
        };
        
        (bridge, event_sender)
    }
    
    /// Start processing kernel events
    pub async fn start(mut self) {
        println!("🔌 KernelEventBridge: Starting...");
        
        while let Some(event) = self.event_receiver.recv().await {
            self.handle_kernel_event(event).await;
        }
        
        println!("🔌 KernelEventBridge: Stopped");
    }
    
    /// Handle a kernel event
    async fn handle_kernel_event(&self, event: KernelEvent) {
        println!("🔌 KernelEvent: Received from kernel");
        println!("   Node: {}, Policy: {}, Operation: {:?}", 
            event.node_id, event.policy_id, event.operation);
        println!("   Process: {} (PID: {}), Decision: {:?}",
            event.process_name, event.process_id, event.decision);
        
        // Resolve path for backend reporting
        let file_path = self.index.get_display_path(event.node_id)
            .unwrap_or_else(|| format!("ID:{}", event.node_id));
        
        let file_extension = std::path::Path::new(&file_path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_string();

        match event.decision {
            EnforcementDecision::Blocked | EnforcementDecision::Audited => {
                let blocked = matches!(event.decision, EnforcementDecision::Blocked);
                
                // 1. Send WebSocket event
                if blocked {
                    self.ws_server.broadcast_kernel_blocked(
                        &self.operation_to_string(event.operation),
                        event.policy_id,
                        &event.process_name,
                    );
                }
                
                // 2. Queue for backend reporting
                let dto = FileEventDTO {
                    operation: self.operation_to_string(event.operation).to_uppercase(),
                    file_path: file_path.clone(),
                    file_extension,
                    file_size: None, // We don't have size here easily
                    process_name: event.process_name.clone(),
                    process_id: event.process_id,
                    user_id: "system".to_string(), // Placeholder
                    blocked,
                    reason: Some(format!("Policy ID: {}", event.policy_id)),
                    timestamp: Some(chrono::Utc::now().to_rfc3339()),
                };
                
                let mut queue = self.event_queue.lock().await;
                queue.push(dto);
                
                if blocked {
                    println!("   ⛔ BLOCKED: {} tried to {:?} protected node {}", 
                        event.process_name, event.operation, file_path);
                } else {
                    println!("   📋 AUDITED: {} {:?} node {} (policy {})",
                        event.process_name, event.operation, file_path, event.policy_id);
                }
            }
            
            EnforcementDecision::Allowed => {
                println!("   ✅ ALLOWED: {} {:?} node {}",
                    event.process_name, event.operation, file_path);
            }
            
            EnforcementDecision::NotProtected => {
                // Nothing to do
            }
        }
    }
    
    /// Convert kernel operation to string
    fn operation_to_string(&self, operation: KernelOperation) -> String {
        match operation {
            KernelOperation::Read => "read".to_string(),
            KernelOperation::Write => "write".to_string(),
            KernelOperation::Delete => "delete".to_string(),
            KernelOperation::Rename => "rename".to_string(),
            KernelOperation::Create => "create".to_string(),
            KernelOperation::QueryInfo => "query_info".to_string(),
            KernelOperation::SetInfo => "set_info".to_string(),
        }
    }
}

/// Mock kernel event generator for testing
pub struct MockKernelEventGenerator {
    event_sender: mpsc::Sender<KernelEvent>,
    next_event_id: u64,
}

impl MockKernelEventGenerator {
    /// Create new mock generator
    pub fn new(event_sender: mpsc::Sender<KernelEvent>) -> Self {
        MockKernelEventGenerator {
            event_sender,
            next_event_id: 1,
        }
    }
    
    /// Generate a test event
    pub async fn generate_test_event(&mut self, node_id: u64, policy_id: u64, process: &str) {
        let event = KernelEvent {
            node_id,
            policy_id,
            operation: KernelOperation::Read,
            process_name: process.to_string(),
            process_id: 1234,
            decision: EnforcementDecision::Blocked,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        if let Err(e) = self.event_sender.send(event).await {
            eprintln!("❌ Failed to send mock kernel event: {}", e);
        } else {
            println!("🔌 MockKernelEvent: Sent test event for node {}", node_id);
            self.next_event_id += 1;
        }
    }
}