// src/networking/mod.rs
//! Networking Layer (STEP 5)
//! Core Principle: Expose Agent APIs over network for Spring Boot Admin
//! 🔐 SECURITY: No NT paths in network responses, IDs only

mod agent_server;
mod websocket_server;

pub use agent_server::{AgentServer, ServerState, SearchQuery, ApplyPolicyRequest, PolicyOperations};
pub use websocket_server::{WebSocketServer, AgentEvent};

use std::net::SocketAddr;
use std::sync::Arc;

use crate::protection_modules::file_protection::comms::QueryApiServer;
use crate::protection_modules::file_protection::policy::PolicyEngine;

/// Initialize STEP 5 networking
pub async fn init_step5(
    query_api: std::sync::Arc<QueryApiServer>,
    policy_engine: std::sync::Arc<PolicyEngine>,
    bind_address: SocketAddr,
) -> Result<ServerHandle, String> {
    println!("🌐 Initializing STEP 5: Networking Layer");
    println!("   • HTTP APIs for Spring Boot Admin");
    println!("   • WebSocket for real-time events");
    println!("   • Binding to: {}", bind_address);
    println!("   • Security: NT paths NEVER exposed");
    println!("   • Auth: Optional X-AGENT-TOKEN header");
    
    // Create WebSocket server
    let ws_server = WebSocketServer::new();
    
    // Create and start HTTP server with WebSocket support
    let server = AgentServer::new(
        query_api, 
        policy_engine, 
        ws_server.clone(),
        bind_address
    );
    
    // Create shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    
    // Spawn server task with graceful shutdown
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.start(shutdown_rx).await {
            eprintln!("❌ HTTP server error: {}", e);
        }
    });
    
    println!("✅ STEP 5: Networking layer initialized");
    println!("   HTTP endpoints ready on {}", bind_address);
    println!("   WebSocket endpoint ready on ws://{}/api/v1/ws", bind_address);
    println!("   Spring Boot Admin can connect now");

    Ok(ServerHandle {
        server_handle,
        shutdown_tx,
        ws_server,
    })
}

/// Server handle for graceful shutdown
pub struct ServerHandle {
    server_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    ws_server: Arc<WebSocketServer>,
}

impl ServerHandle {
    /// Gracefully shutdown the server
    pub async fn shutdown(self) -> Result<(), String> {
        println!("🛑 Shutting down STEP 5 networking...");
        
        // Send shutdown signal
        let _ = self.shutdown_tx.send(());
        
        // Broadcast shutdown event
        self.ws_server.broadcast_event(AgentEvent::AgentDisconnected);
        
        // Wait for server to finish
        self.server_handle.await
            .map_err(|e| format!("Failed to shutdown server: {}", e))
    }
    
    /// Get WebSocket server for event emission
    pub fn ws_server(&self) -> Arc<WebSocketServer> {
        self.ws_server.clone()
    }

    /// Helper to emit filesystem changed events
    pub fn emit_filesystem_changed(&self, node_id: u64, change_type: &str) {
        self.ws_server.broadcast_event(AgentEvent::FilesystemChanged {
            node_id,
            change_type: change_type.to_string(),
        });
    }

     pub fn emit_kernel_blocked(&self, operation: &str, policy_id: u64, process: &str) {
        self.ws_server.broadcast_kernel_blocked(operation, policy_id, process);
    }
    
}