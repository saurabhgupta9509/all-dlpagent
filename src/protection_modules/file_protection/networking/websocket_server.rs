// src/networking/websocket_server.rs
//! WebSocket Server (STEP 5.3 - Optional)
//! Core Principle: Push events from Agent to Admin Server in real-time

use axum::{ extract::{ ws::{ WebSocket, WebSocketUpgrade }, State }, response::IntoResponse };
use futures::{ sink::SinkExt, stream::StreamExt };
use serde_json::json;
use std::sync::Arc;
use tokio::sync::broadcast;

/// WebSocket events
#[derive(Debug, Clone, serde::Serialize)]
pub enum AgentEvent {
    FilesystemChanged {
        node_id: u64,
        change_type: String,
    },
    PolicyApplied {
        policy_id: u64,
        node_id: u64,
        scope: String,
        action: String,
    },
    PolicyRemoved {
        policy_id: u64,
        node_id: u64,
    },
    KernelBlocked {
        operation: String, 
        policy_id: u64,      // ✅ Use policy_id, not path
        process: String,
        timestamp: u64,
    },
    AgentConnected,
    AgentDisconnected,
    Error {
        message: String,
        code: String,
    },
}

/// WebSocket server for real-time updates
pub struct WebSocketServer {
    event_tx: broadcast::Sender<AgentEvent>,
}

impl WebSocketServer {
    /// Create new WebSocket server
    pub fn new() -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(100);

        Arc::new(WebSocketServer {
            event_tx,
        })
    }

    /// Get event sender for broadcasting events
    pub fn event_sender(&self) -> broadcast::Sender<AgentEvent> {
        self.event_tx.clone()
    }

    /// Broadcast an event to all connected clients
    pub fn broadcast_event(&self, event: AgentEvent) {
        let _ = self.event_tx.send(event);
    }

     /// Get a simple description
    pub fn describe(&self) -> String {
        "WebSocket Server (Event system ready)".to_string()
    }

    /// Internal handler for WebSocket connections
    pub async fn handle_websocket_internal(&self, socket: axum::extract::ws::WebSocket) {
        println!("🔌 WebSocket: Client connected");
        
        // Send connection event
        self.broadcast_event(AgentEvent::AgentConnected);
        
        let (mut sender, mut receiver) = socket.split();
        
        // Subscribe to events
        let mut event_rx = self.event_tx.subscribe();
        
        // Send welcome message
        let welcome = json!({
            "type": "welcome",
            "message": "Connected to DLP Agent WebSocket",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "note": "Events are pushed from Agent. Admin should not send commands here.",
        });
        
        if let Ok(message) = serde_json::to_string(&welcome) {
            let _ = sender.send(axum::extract::ws::Message::Text(message)).await;
        }
        
        // Handle WebSocket communication
        let mut handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Receive events from broadcast channel
                    Ok(event) = event_rx.recv() => {
                        if let Ok(message) = serde_json::to_string(&event) {
                            if sender.send(axum::extract::ws::Message::Text(message)).await.is_err() {
                                break;
                            }
                        }
                    }
                    
                    // Receive messages from client (should be minimal)
                    Some(Ok(msg)) = receiver.next() => {
                        match msg {
                            axum::extract::ws::Message::Text(text) => {
                                println!("🔌 WebSocket: Received from client: {}", text);
                                // Admin can send ping/pong, but no commands
                                if text == "ping" {
                                    let pong = json!({
                                        "type": "pong",
                                        "timestamp": std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                    });
                                    if let Ok(message) = serde_json::to_string(&pong) {
                                        let _ = sender.send(axum::extract::ws::Message::Text(message)).await;
                                    }
                                }
                            }
                            axum::extract::ws::Message::Close(_) => {
                                println!("🔌 WebSocket: Client disconnected");
                                break;
                            }
                            _ => {}
                        }
                    }
                    
                    // Exit if receiver is done
                    else => {
                        break;
                    }
                }
            }
        });
        
        // Wait for handle to complete
        let _ = handle.await;
        
        println!("🔌 WebSocket: Connection closed");
        self.broadcast_event(AgentEvent::AgentDisconnected);
    }

  /// Broadcast policy applied event (safe - no NT paths)
    pub fn broadcast_policy_applied(&self, policy_id: u64, node_id: u64, scope: &str, action: &str) {
        self.broadcast_event(AgentEvent::PolicyApplied {
            policy_id,
            node_id,
            scope: scope.to_string(),
            action: action.to_string(),
        });
    }

      /// Broadcast kernel blocked event (safe - no NT paths)
    pub fn broadcast_kernel_blocked(&self, operation: &str, policy_id: u64, process: &str) {
        self.broadcast_event(AgentEvent::KernelBlocked {
            operation: operation.to_string(),
            policy_id,
            process: process.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
    }

    
    /// WebSocket handler
    pub async fn handle_websocket(
        ws: WebSocketUpgrade,
        State(server): State<Arc<WebSocketServer>>
    ) -> impl IntoResponse {
        println!("🔌 WebSocket: New connection request");

        ws.on_upgrade(|socket| async move {
            handle_socket(socket, server).await;
        })
    }

    
    
  
}

/// Handle individual WebSocket connection
async fn handle_socket(socket: WebSocket, server: Arc<WebSocketServer>) {
    println!("🔌 WebSocket: Client connected");

    // Send connection event
    server.broadcast_event(AgentEvent::AgentConnected);

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to events
    let mut event_rx = server.event_tx.subscribe();

    // Send welcome message
    let welcome =
        json!({
        "type": "welcome",
        "message": "Connected to DLP Agent WebSocket",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "note": "Events are pushed from Agent. Admin should not send commands here.",
    });

    if let Ok(message) = serde_json::to_string(&welcome) {
        let _ = sender.send(axum::extract::ws::Message::Text(message)).await;
    }

    // Handle WebSocket communication
    let mut handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Receive events from broadcast channel
                Ok(event) = event_rx.recv() => {
                    if let Ok(message) = serde_json::to_string(&event) {
                        if sender.send(axum::extract::ws::Message::Text(message)).await.is_err() {
                            break;
                        }
                    }
                }
                
                // Receive messages from client (should be minimal)
                Some(Ok(msg)) = receiver.next() => {
                    match msg {
                        axum::extract::ws::Message::Text(text) => {
                            println!("🔌 WebSocket: Received from client: {}", text);
                            // Admin can send ping/pong, but no commands
                            if text == "ping" {
                                let pong = json!({
                                    "type": "pong",
                                    "timestamp": std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                });
                                if let Ok(message) = serde_json::to_string(&pong) {
                                    let _ = sender.send(axum::extract::ws::Message::Text(message)).await;
                                }
                            }
                        }
                        axum::extract::ws::Message::Close(_) => {
                            println!("🔌 WebSocket: Client disconnected");
                            break;
                        }
                        _ => {}
                    }
                }
                
                // Exit if receiver is done
                else => {
                    break;
                }
            }
        }
    });

    // Wait for handle to complete
    let _ = handle.await;

    println!("🔌 WebSocket: Connection closed");
    server.broadcast_event(AgentEvent::AgentDisconnected);
}

  