//! Agent HTTP Server (STEP 5.1)
//! Core Principle: Expose existing APIs over HTTP, NO new logic, NO NT paths in responses
// src/networking/agent_server.rs
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json, Router,
    routing::{get, post, delete},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::protection_modules::file_protection::{comms::{AdminRequest, AgentResponse, QueryApiServer}, networking::{AgentEvent, WebSocketServer}, policy::{HealthStatus, PolicyEngine, PolicyIntent, PolicyPreviewService, ProtectionAction, ProtectionOperations, ProtectionScope}};

/// Server state shared across all handlers
#[derive(Clone)]
pub struct ServerState {
    query_api: Arc<QueryApiServer>,
    policy_engine: Arc<PolicyEngine>,
      ws_server: Arc<WebSocketServer>, // Add WebSocket server
}

/// Standardized error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

/// Standardized API response
#[derive(Debug, Serialize)]
pub struct StandardApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ErrorResponse>,
}

impl<T> StandardApiResponse<T> {
    fn success(data: T) -> Self {
        StandardApiResponse {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: ErrorResponse) -> Self {
        StandardApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}


/// Query parameters for search - FIXED: parent_id is required
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub parent_id: u64,  // Required - no Option
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Policy application request
#[derive(Debug, Deserialize, Serialize)]
pub struct ApplyPolicyRequest {
     pub node_id: u64,
    pub scope: String,          // "file", "folder", "folder_recursive"
    pub action: String,         // "block", "allow", "audit"
    pub operations: PolicyOperations,
    pub created_by: String,
    pub comment: Option<String>,
    pub confirmed: bool,        // ✅ Add confirmation flag
     #[serde(default)]  // Optional field with default
    pub timestamp: Option<u64>,
}

/// Policy operations for HTTP API
#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyOperations {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub rename: bool,
    pub create: bool,

}

/// Agent HTTP Server
pub struct AgentServer {
    state: Arc<ServerState>,
    bind_address: SocketAddr,
}

impl AgentServer {
    /// Create new HTTP server
    pub fn new(
        query_api: Arc<QueryApiServer>,
        policy_engine: Arc<PolicyEngine>,
        ws_server: Arc<WebSocketServer>, // Add WebSocket server
        bind_address: SocketAddr,
    ) -> Self {
        AgentServer {
            state: Arc::new(ServerState {
                query_api,
                policy_engine,
                  ws_server,
            }),
            bind_address,
        }
    }
    
    /// Start the HTTP server
    pub async fn start(self ,shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
        println!("🌐 Agent HTTP Server starting on {}", self.bind_address);
        println!("   Endpoints exposed for Spring Boot Admin");
        
        // Build router with all endpoints
        let app = Router::new()
            // Explorer APIs (read-only)
            .route("/api/v1/drives", get(get_drives))
            .route("/api/v1/nodes/:id", get(get_node))
            .route("/api/v1/nodes/:id/children", get(get_node_children))
            .route("/api/v1/nodes/:id/expand", post(expand_node))
            .route("/api/v1/nodes/:id/collapse", post(collapse_node))
            .route("/api/v1/search/local", get(search_local))
            .route("/api/v1/stats", get(get_stats))

            // Policy APIs
            .route("/api/v1/policies/apply", post(apply_policy))
            .route("/api/v1/policies/:policy_id", delete(remove_policy))
            .route("/api/v1/policies", get(list_policies))
            .route("/api/v1/policies/node/:node_id", get(get_node_policies))
            
            // STEP 7 Policy Assurance Layer endpoints
            .route("/api/v1/policies/preview", post(policy_preview_handler))
            .route("/api/v1/policies/dry-run", post(policy_dry_run_handler))
            .route("/api/v1/policies/:id/status", get(policy_status_handler))
            .route("/api/v1/policies/validate", post(policy_validate_handler))

             // WebSocket endpoint
            .route("/api/v1/ws", get(handle_websocket_route))

            // Health
            .route("/api/v1/ping", get(ping))
            
             // Add authentication middleware (optional)
            .layer(axum::middleware::from_fn(optional_auth_middleware))

            // Add state
            .with_state(self.state.clone());
        
        // Start server
        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", self.bind_address, e))?;
        
        println!("✅ Agent HTTP Server listening on {}", self.bind_address);
        println!("   Ready for Spring Boot Admin connections");
        
        axum::serve(listener, app)
        .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
                println!("🛑 Received shutdown signal, stopping HTTP server...");
            })
            .await
            .map_err(|e| format!("HTTP server error: {}", e))
    }
}

/// POST /api/v1/policies/dry-run - Policy Dry-Run (STEP 7.2)
async fn policy_dry_run_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ApplyPolicyRequest>,
) -> impl IntoResponse {
    println!("🧪 POST /api/v1/policies/dry-run");
    println!("   Node ID: {}, Action: {}", request.node_id, request.action);
    
    // Convert HTTP request to PolicyIntent (syntax validation only)
    let scope = match request.scope.as_str() {
        "file" => ProtectionScope::File,
        "folder" => ProtectionScope::Folder,
        "folder_recursive" => ProtectionScope::FolderRecursive,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_SCOPE".to_string(),
                message: format!("Invalid scope: {}", request.scope),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let action = match request.action.as_str() {
        "block" => ProtectionAction::Block,
        "allow" => ProtectionAction::Allow,
        "audit" => ProtectionAction::Audit,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_ACTION".to_string(),
                message: format!("Invalid action: {}", request.action),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    // Create intent
    let operations = ProtectionOperations {
        read: request.operations.read,
        write: request.operations.write,
        delete: request.operations.delete,
        rename: request.operations.rename,
        create: request.operations.create,
    };
    
    let intent = PolicyIntent::new(
        request.node_id,
        scope,
        action,
        operations,
        &request.created_by,
        request.comment.as_deref(),
    );
    
    // Run dry-run through PolicyEngine
    match state.policy_engine.dry_run_policy(&intent) {
        Ok(evaluation) => {
            println!("   ✅ Dry-run completed successfully");
            
            let results: Vec<serde_json::Value> = evaluation.results.iter().map(|r| {
                serde_json::json!({
                    "operation": r.operation,
                    "will_block": r.will_block,
                    "reason": r.reason,
                })
            }).collect();
            
            let response = serde_json::json!({
                "node_id": evaluation.node_id,
                "policy_preview": evaluation.policy_preview,
                "results": results,
                "summary": evaluation.summary,
                "mode": "simulation",
                "note": "Dry-run simulation only - kernel untouched",
            });
            
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        Err(e) => {
            println!("   ❌ Dry-run failed: {}", e);
            let error = ErrorResponse {
                code: "DRY_RUN_FAILED".to_string(),
                message: e,
            };
            (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)))
        }
    }
}

/// GET /api/v1/policies/:id/status - Policy Status (STEP 7.3)
async fn policy_status_handler(
    State(state): State<Arc<ServerState>>,
    Path(policy_id): Path<u64>,
) -> impl IntoResponse {
    println!("📊 GET /api/v1/policies/{}/status", policy_id);
    
    // ✅ DELEGATE TO POLICY ENGINE
    match state.policy_engine.get_policy_health(policy_id) {
        Some((health_status, message)) => {
            let kernel_connected = state.policy_engine.is_kernel_connected();
            
            let response = serde_json::json!({
                "policy_id": policy_id,
                "enforcement_mode": if kernel_connected { "REAL" } else { "SIMULATED" },
                "kernel_connected": kernel_connected,
                "health_status": match health_status {
                    HealthStatus::Healthy => "HEALTHY",
                    HealthStatus::Warning => "WARNING",
                    HealthStatus::Degraded => "DEGRADED",
                    HealthStatus::Failed => "FAILED",
                    HealthStatus::Unknown => "UNKNOWN",
                },
                "health_message": message,
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        None => {
            let error = ErrorResponse {
                code: "POLICY_NOT_FOUND".to_string(),
                message: format!("Policy ID {} not found", policy_id),
            };
            (StatusCode::NOT_FOUND, Json(StandardApiResponse::error(error)))
        }
    }
}

/// POST /api/v1/policies/validate - Policy Safety Validation (STEP 7.4)
async fn policy_validate_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ApplyPolicyRequest>,
) -> impl IntoResponse {
    println!("🛡️ POST /api/v1/policies/validate");
    
    // Convert HTTP to PolicyIntent (SYNTAX ONLY)
    let scope = match request.scope.as_str() {
        "file" => ProtectionScope::File,
        "folder" => ProtectionScope::Folder,
        "folder_recursive" => ProtectionScope::FolderRecursive,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_SCOPE".to_string(),
                message: format!("Invalid scope: {}", request.scope),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let action = match request.action.as_str() {
        "block" => ProtectionAction::Block,
        "allow" => ProtectionAction::Allow,
        "audit" => ProtectionAction::Audit,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_ACTION".to_string(),
                message: format!("Invalid action: {}", request.action),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let operations = ProtectionOperations {
        read: request.operations.read,
        write: request.operations.write,
        delete: request.operations.delete,
        rename: request.operations.rename,
        create: request.operations.create,
    };
    
    let intent = PolicyIntent::new(
        request.node_id,
        scope,
        action,
        operations,
        &request.created_by,
        request.comment.as_deref(),
    );
    
    // ✅ DELEGATE TO POLICY ENGINE
    let validation = state.policy_engine.validate_policy_safety(&intent);
    
    let response = serde_json::json!({
        "is_valid": validation.is_valid,
        "warnings": validation.warnings,
        "errors": validation.errors,
        "requires_confirmation": validation.requires_confirmation,
        "confirmation_message": validation.confirmation_message,
    });
    (StatusCode::OK, Json(StandardApiResponse::success(response)))
}

// ========================================
// Explorer API Handlers - NOW ASYNC
// ========================================

/// GET /api/v1/drives
async fn get_drives(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    println!("🌐 GET /api/v1/drives");
    
    match state.query_api.handle_request(AdminRequest::GetDrives).await {
        AgentResponse::Drives { drives } => {
            println!("   ✅ Returning {} drives", drives.len());
            (StatusCode::OK, Json(StandardApiResponse::success(drives)))
        }
        AgentResponse::Error { code, message, .. } => {
            println!("   ❌ Error: {} - {}", code, message);
            let error = ErrorResponse {
                code,
                message,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
            let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// GET /api/v1/nodes/:id
async fn get_node(
    State(state): State<Arc<ServerState>>,
    Path(node_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 GET /api/v1/nodes/{}", node_id);
    
    match state.query_api.handle_request(AdminRequest::GetNode { node_id }).await {
        AgentResponse::Node { node } => {
            println!("   ✅ Returning node info");
            (StatusCode::OK, Json(StandardApiResponse::success(node)))
        }
        AgentResponse::Error { code, message, .. } => {
            println!("   ❌ Error: {} - {}", code, message);
            let status = if code == "NODE_NOT_FOUND" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let error = ErrorResponse { code, message };
            (status, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
            let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// GET /api/v1/nodes/:id/children
async fn get_node_children(
    State(state): State<Arc<ServerState>>,
    Path(node_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 GET /api/v1/nodes/{}/children", node_id);
    
    match state.query_api.handle_request(AdminRequest::ListChildren { node_id }).await {
        AgentResponse::Children { parent_id, parent_name, children, total_children } => {
            println!("   ✅ Returning {} children", children.len());
            let response = serde_json::json!({
                "parent_id": parent_id,
                "parent_name": parent_name,
                "children": children,
                "total_children": total_children,
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        AgentResponse::Error { code, message, .. } => {
            println!("   ❌ Error: {} - {}", code, message);
             let status = if code == "NODE_NOT_FOUND" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let error = ErrorResponse { code, message };
            (status, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
             let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// POST /api/v1/nodes/:id/expand - NOW RETURNS CHILDREN
async fn expand_node(
    State(state): State<Arc<ServerState>>,
    Path(node_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 POST /api/v1/nodes/{}/expand", node_id);
    
    match state.query_api.handle_request(AdminRequest::ExpandNode { node_id }).await {
        AgentResponse::Expanded { node_id, node_name, children, total_children } => {
            println!("   ✅ Expanded '{}', {} children loaded", node_name, children.len());
            let response = serde_json::json!({
                "node_id": node_id,
                "node_name": node_name,
                "children": children,  // Now returns actual children
                "total_children": total_children,
                "message": format!("Expanded '{}' with {} children", node_name, children.len()),
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        AgentResponse::Error { code, message, details } => {
            println!("   ❌ Error: {} - {}", code, message);
            let status = if code == "NODE_NOT_FOUND" {
                StatusCode::NOT_FOUND
            } else if code == "ALREADY_EXPANDED" {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let error = ErrorResponse { code, message };
            (status, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
             let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// POST /api/v1/nodes/:id/collapse
async fn collapse_node(
    State(state): State<Arc<ServerState>>,
    Path(node_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 POST /api/v1/nodes/{}/collapse", node_id);
    
    match state.query_api.handle_request(AdminRequest::CollapseNode { node_id }).await {
        AgentResponse::Collapsed { node_id, node_name, removed_children } => {
            println!("   ✅ Collapsed '{}', removed {} children", node_name, removed_children);
            let response = serde_json::json!({
                "node_id": node_id,
                "node_name": node_name,
                "removed_children": removed_children,
                "message": format!("Collapsed '{}', removed {} children", node_name, removed_children),
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        AgentResponse::Error { code, message, details } => {
            println!("   ❌ Error: {} - {}", code, message);
            let status = if code == "NODE_NOT_FOUND" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let error = ErrorResponse { code, message };
            (status, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
            let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// GET /api/v1/search/local - FIXED: parent_id is required
async fn search_local(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
    println!("🌐 GET /api/v1/search/local?parent_id={}&query={}", params.parent_id, params.query);
    println!("   ⚠️  Search is LOCAL ONLY (expanded nodes)");
    
    match state.query_api.handle_request(
        AdminRequest::SearchLocal { 
            parent_id: params.parent_id, 
            query: params.query.clone(), 
            limit: params.limit,
        }
    ).await {
        AgentResponse::SearchLocalResults { parent_id, query, results, total_matches, scope } => {
            println!("   ✅ Found {} matches (Scope: {})", total_matches, scope);
            let response = serde_json::json!({
                "parent_id": parent_id,
                "query": query,
                "results": results,
                "total_matches": total_matches,
                "scope": scope,
                "note": "Search is local to expanded nodes only. Expand more folders for broader search.",
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        AgentResponse::Error { code, message, details } => {
            println!("   ❌ Error: {} - {}", code, message);
            let error = ErrorResponse { code, message };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
            let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

/// GET /api/v1/stats
async fn get_stats(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    println!("🌐 GET /api/v1/stats");
    
    match state.query_api.handle_request(AdminRequest::GetStats).await {
        AgentResponse::Stats { stats } => {
            println!("   ✅ Returning system stats");
            (StatusCode::OK, Json(StandardApiResponse::success(stats)))
        }
        AgentResponse::Error { code, message, details } => {
            println!("   ❌ Error: {} - {}", code, message);
            let error = ErrorResponse { code, message };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
        _ => {
            println!("   ❌ Unexpected response type");
            let error = ErrorResponse {
                code: "INTERNAL_ERROR".to_string(),
                message: "Unexpected response from agent".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
        }
    }
}

// ========================================
// Policy API Handlers
// ========================================

/// POST /api/v1/policies/apply
async fn apply_policy(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ApplyPolicyRequest>,
) -> impl IntoResponse {
    println!("🌐 POST /api/v1/policies/apply");
    println!("   Node ID: {}, Scope: {}, Action: {}", 
        request.node_id, request.scope, request.action);
    
    // HTTP-level validation
    let operations = &request.operations;
    if !operations.read && !operations.write && !operations.delete && 
       !operations.rename && !operations.create 
    //    && !operations.copy && !operations.execute 
       {
        let error = ErrorResponse {
            code: "INVALID_REQUEST".to_string(),
            message: "At least one operation must be selected".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
    }
    
    // if (request.scope == "folder" || request.scope == "folder_recursive") && operations.execute {
    //     let error = ErrorResponse {
    //         code: "INVALID_REQUEST".to_string(),
    //         message: "Folders cannot have execute protection".to_string(),
    //     };
    //     return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
    // }
    
    if request.created_by.trim().is_empty() {
        let error = ErrorResponse {
            code: "INVALID_REQUEST".to_string(),
            message: "Creator name cannot be empty".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
    }
    
    // Convert HTTP request to PolicyIntent
    let scope = match request.scope.as_str() {
        "file" => ProtectionScope::File,
        "folder" => ProtectionScope::Folder,
        "folder_recursive" => ProtectionScope::FolderRecursive,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_SCOPE".to_string(),
                message: format!("Invalid scope: {}", request.scope),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let action = match request.action.as_str() {
        "block" => ProtectionAction::Block,
        "allow" => ProtectionAction::Allow,
        "audit" => ProtectionAction::Audit,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_ACTION".to_string(),
                message: format!("Invalid action: {}", request.action),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let operations = ProtectionOperations {
        read: request.operations.read,
        write: request.operations.write,
        delete: request.operations.delete,
        rename: request.operations.rename,
        create: request.operations.create,
       
    };
    
    let intent = PolicyIntent::new(
        request.node_id,
        scope,
        action,
        operations,
        &request.created_by,
        request.comment.as_deref(),
    );
    

    // match state.policy_engine.apply_protection(intent.clone()) {
    //     Ok(policy_id) => {
    //         println!("   ✅ Policy applied successfully (ID: {})", policy_id);
            
    //         let scope_str = match intent.scope {
    //             ProtectionScope::File => "file",
    //             ProtectionScope::Folder => "folder",
    //             ProtectionScope::FolderRecursive => "folder_recursive",
    //         };
            
    //         let action_str = match intent.action {
    //             ProtectionAction::Block => "block",
    //             ProtectionAction::Allow => "allow",
    //             ProtectionAction::Audit => "audit",
    //         };
            
    //         state.ws_server.broadcast_policy_applied(
    //             policy_id,
    //             intent.node_id,
    //             scope_str,
    //             action_str,
    //         );
            
    //         let response = serde_json::json!({
    //             "policy_id": policy_id,
    //             "message": "Policy applied successfully",
    //             "note": "NT path resolved internally and sent to kernel",
    //         });
    //         (StatusCode::CREATED, Json(StandardApiResponse::success(response)))
    //     }
    //     Err(e) => {
    //         println!("   ❌ Failed to apply policy: {}", e);
    //         let error = ErrorResponse {
    //             code: "POLICY_APPLICATION_FAILED".to_string(),
    //             message: e,
    //         };
    //         (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)))
    //     }
    // }

    let engine = state.policy_engine.clone();
    let intent_clone = intent.clone();
    let confirmed = request.confirmed;
    let result = tokio::task::spawn_blocking(move || {
            engine.apply_protection_with_assurance(intent_clone, confirmed)
        })
        .await;
match result {
    Ok(Ok(policy_id)) => {
        println!("   ✅ Policy applied successfully (ID: {})", policy_id);

        let response = serde_json::json!({
            "policy_id": policy_id,
            "message": "Policy applied successfully",
        });

        (StatusCode::CREATED, Json(StandardApiResponse::success(response)))
    }
    Ok(Err(e)) => {
        let error = ErrorResponse {
            code: "POLICY_APPLICATION_FAILED".to_string(),
            message: e,
        };
        (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)))
    }
    Err(_) => {
        let error = ErrorResponse {
            code: "INTERNAL_ERROR".to_string(),
            message: "Kernel task panicked".to_string(),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(error)))
    }
}

}

/// DELETE /api/v1/policies/:policy_id
async fn remove_policy(
    State(state): State<Arc<ServerState>>,
    Path(policy_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 DELETE /api/v1/policies/{}", policy_id);
    
    // Get node_id BEFORE removing policy
    let node_id = state.policy_engine.get_policy_by_id(policy_id)
        .map(|policy| policy.intent.node_id);
    
    match state.policy_engine.remove_protection(policy_id) {
        Ok(_) => {
            println!("   ✅ Policy removed successfully");
            
            // Emit WebSocket event if we found the node_id
            if let Some(node_id) = node_id {
                state.ws_server.broadcast_event(AgentEvent::PolicyRemoved {
                    policy_id,
                    node_id,
                });
            } else {
                println!("   ⚠️  Could not find node_id for policy {}", policy_id);
            }
            
            let response = serde_json::json!({
                "policy_id": policy_id,
                "message": "Policy removed successfully",
                "note": "Removed from kernel and policy store",
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        Err(e) => {
            println!("   ❌ Failed to remove policy: {}", e);
            if e.contains("not found") {
                (StatusCode::NOT_FOUND, Json(StandardApiResponse::error(ErrorResponse {
                    code: "POLICY_NOT_FOUND".to_string(),
                    message: e,
                })))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(StandardApiResponse::error(ErrorResponse {
                    code: "INTERNAL_ERROR".to_string(),
                    message: e,
                })))
            }
        }
    }
}

/// GET /api/v1/policies
async fn list_policies(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    println!("🌐 GET /api/v1/policies");
    
    let policies = state.policy_engine.get_active_policies();
    println!("   ✅ Returning {} active policies", policies.len());
    
    let safe_policies: Vec<serde_json::Value> = policies.into_iter().map(|policy| {
        let policy_id = policy.kernel_policy_ids.first()
            .copied()
            .unwrap_or(policy.intent.node_id);
        
        serde_json::json!({
            "policy_id": policy_id,
            "node_id": policy.intent.node_id,
            "scope": match policy.intent.scope {
                ProtectionScope::File => "file",
                ProtectionScope::Folder => "folder",
                ProtectionScope::FolderRecursive => "folder_recursive",
            },
            "action": match policy.intent.action {
                ProtectionAction::Block => "block",
                ProtectionAction::Allow => "allow",
                ProtectionAction::Audit => "audit",
            },
            "is_active": policy.is_active,
            "created_by": policy.intent.created_by,
            "created_at": policy.created_at,
            "comment": policy.intent.comment,
            "note": "NT paths are stored internally only, never exposed",
        })
    }).collect();
    
    (StatusCode::OK, Json(StandardApiResponse::success(safe_policies)))
}



/// GET /api/v1/policies/node/:node_id
async fn get_node_policies(
    State(state): State<Arc<ServerState>>,
    Path(node_id): Path<u64>,
) -> impl IntoResponse {
    println!("🌐 GET /api/v1/policies/node/{}", node_id);
    
    let policies = state.policy_engine.get_policies_for_node(node_id);
    println!("   ✅ Returning {} policies for node {}", policies.len(), node_id);
    
    let safe_policies: Vec<serde_json::Value> = policies.into_iter().map(|policy| {
        let policy_id = policy.kernel_policy_ids.first()
            .copied()
            .unwrap_or(policy.intent.node_id);
            
        serde_json::json!({
            "policy_id": policy_id,
            "scope": match policy.intent.scope {
                ProtectionScope::File => "file",
                ProtectionScope::Folder => "folder",
                ProtectionScope::FolderRecursive => "folder_recursive",
            },
            "action": match policy.intent.action {
                ProtectionAction::Block => "block",
                ProtectionAction::Allow => "allow",
                ProtectionAction::Audit => "audit",
            },
            "is_active": policy.is_active,
            "created_by": policy.intent.created_by,
            "created_at": policy.created_at,
            "comment": policy.intent.comment,
        })
    }).collect();
    
    (StatusCode::OK, Json(StandardApiResponse::success(safe_policies)))
}

/// POST /api/v1/policies/preview - ONLY ONE VERSION REMAINS
async fn policy_preview_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<ApplyPolicyRequest>,
) -> impl IntoResponse {
    println!("🔍 POST /api/v1/policies/preview");
    
    // Convert HTTP to PolicyIntent (SYNTAX ONLY)
    let scope = match request.scope.as_str() {
        "file" => ProtectionScope::File,
        "folder" => ProtectionScope::Folder,
        "folder_recursive" => ProtectionScope::FolderRecursive,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_SCOPE".to_string(),
                message: format!("Invalid scope: {}", request.scope),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let action = match request.action.as_str() {
        "block" => ProtectionAction::Block,
        "allow" => ProtectionAction::Allow,
        "audit" => ProtectionAction::Audit,
        _ => {
            let error = ErrorResponse {
                code: "INVALID_ACTION".to_string(),
                message: format!("Invalid action: {}", request.action),
            };
            return (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)));
        }
    };
    
    let operations = ProtectionOperations {
        read: request.operations.read,
        write: request.operations.write,
        delete: request.operations.delete,
        rename: request.operations.rename,
        create: request.operations.create,
    };
    
    let intent = PolicyIntent::new(
        request.node_id,
        scope,
        action,
        operations,
        &request.created_by,
        request.comment.as_deref(),
    );
    
    // ✅ DELEGATE TO POLICY ENGINE
    match state.policy_engine.preview_policy(&intent) {
        Ok(preview) => {
            let response = serde_json::json!({
                "node_id": intent.node_id,
                "preview": preview.human_readable,
                "is_block_all": preview.is_block_all,
                "quick_summary": PolicyPreviewService::get_quick_summary(&intent),
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        Err(e) => {
            let error = ErrorResponse {
                code: "PREVIEW_FAILED".to_string(),
                message: e,
            };
            (StatusCode::BAD_REQUEST, Json(StandardApiResponse::error(error)))
        }
    }
}

async fn handle_websocket_route(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    println!("🔌 WebSocket: New connection request");
    
    ws.on_upgrade(|socket| async move {
        // Delegate to WebSocketServer
        state.ws_server.handle_websocket_internal(socket).await;
    })
}

/// Optional authentication middleware
async fn optional_auth_middleware(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    // Check for authentication token in development mode
    let auth_header = request.headers()
        .get("X-AGENT-TOKEN")
        .and_then(|h| h.to_str().ok());
    
    // In production, you would validate the token here
    // For now, just log if token is present
    if let Some(token) = auth_header {
        println!("🔑 Request with auth token (length: {})", token.len());
    } else {
        println!("⚠️  Request without auth token (running in trusted-local mode)");
    }
    
    next.run(request).await
}

// ========================================
// Health API
// ========================================

/// GET /api/v1/ping
async fn ping(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    println!("🌐 GET /api/v1/ping");
    
    match state.query_api.handle_request(AdminRequest::Ping).await {
        AgentResponse::Pong { timestamp, version } => {
            println!("   ✅ Agent alive (v{})", version);
            let response = serde_json::json!({
                "status": "alive",
                "timestamp": timestamp,
                "version": version,
                "agent": "DLP Agent",
                "message": "Ready for Spring Boot Admin connections",
            });
            (StatusCode::OK, Json(StandardApiResponse::success(response)))
        }
        _ => {
            println!("   ⚠️  Ping responded unexpectedly");
            (StatusCode::OK, Json(StandardApiResponse::success(serde_json::json!({
                "status": "alive",
                "message": "Agent running",
            }))))
        }
    }
}