// src/kernel/mod.rs
//! Kernel Integration Module (STEP 6)
//! Core Principle: Real-time policy enforcement via kernel minifilter

mod kernel_event_bridge;

pub use kernel_event_bridge::{
    KernelEventBridge, 
    KernelEvent, 
    KernelOperation, 
    EnforcementDecision,
    MockKernelEventGenerator
};

use crate::protection_modules::file_protection::networking::WebSocketServer;

/// Initialize STEP 6 kernel integration
pub fn init_step6(
    ws_server: std::sync::Arc<WebSocketServer>,
    index: std::sync::Arc<crate::protection_modules::file_protection::fs_index::FilesystemIndex>,
    event_queue: std::sync::Arc<tokio::sync::Mutex<Vec<crate::communication::FileEventDTO>>>,
) -> (KernelEventBridge, tokio::sync::mpsc::Sender<KernelEvent>) 
{
    println!("🔧 Initializing STEP 6: Kernel Enforcement");
    println!("   • Kernel → Agent event bridge");
    println!("   • Real-time policy enforcement");
    println!("   • WebSocket event streaming");
    println!("   • CRITICAL: READ = BLOCK ALL rule");
    
    // Create kernel event bridge
    let (bridge, event_sender) = KernelEventBridge::new(ws_server, index, event_queue);
    
    println!("✅ STEP 6: Kernel integration ready");
    println!("   Kernel events will be forwarded to WebSocket");
    
    (bridge, event_sender)
}