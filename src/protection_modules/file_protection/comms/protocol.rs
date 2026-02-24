//! Communication Protocol - JSON-safe message definitions
//! Core Principle: Admin only sees IDs, Agent owns filesystem truth
// src/comms/protocol.rs
use serde::{Serialize, Deserialize};

// ========================
// Admin → Agent Requests
// ========================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminRequest {
    /// Get all drives (root children)
    GetDrives,
    
    /// List children of a node
    ListChildren {
        node_id: u64,
    },
    
    /// Get metadata for specific node
    GetNode {
        node_id: u64,
    },
    
    /// Search within a directory (LOCAL ONLY - searches only expanded children)
    /// ⚠️ This does NOT search the entire filesystem, only already-loaded children
    SearchLocal {
        parent_id: u64,
        query: String,
        #[serde(default)]
        limit: Option<usize>,
    },
    
    /// Expand a directory (load children if not already loaded)
    ExpandNode {
        node_id: u64,
    },
    
    /// Collapse a directory (unload children)
    CollapseNode {
        node_id: u64,
    },
    
    /// Get system statistics
    GetStats,
    
    /// Ping/health check
    Ping,
}

// ========================
// Agent → Admin Responses
// ========================

#[derive(Debug, Serialize, Deserialize)]
pub struct DriveInfo {
    pub id: u64,
    pub name: String,
    pub drive_letter: String,
    pub has_children: bool,
    pub is_accessible: bool,
    pub node_type: String,  // "drive"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,  // "drive", "directory", "file"
    pub size: Option<u64>,
    pub modified_time: u64,
    pub created_time: u64,
    pub has_children: bool,
    pub is_expanded: bool,
    pub is_accessible: bool,
    pub full_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsInfo {
    pub total_nodes: usize,
    pub total_drives: usize,
    pub expanded_nodes: usize,
    pub memory_usage_bytes: usize,
    pub scan_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    /// List of drives
    Drives {
        drives: Vec<DriveInfo>,
    },
    
    /// List of child nodes
    Children {
        parent_id: u64,
        parent_name: String,
        children: Vec<NodeInfo>,
        total_children: usize,
    },
    
    /// Single node info
    Node {
        node: NodeInfo,
    },
    
    /// Local search results (only in expanded nodes)
    SearchLocalResults {
        parent_id: u64,
        query: String,
        results: Vec<NodeInfo>,
        total_matches: usize,
        scope: String, // "local" - important to indicate limited scope
    },
    
    /// Expand operation result
    Expanded {
        node_id: u64,
        node_name: String,
       children: Vec<NodeInfo>,
        total_children: usize,
    },
    
    /// Collapse operation result
    Collapsed {
        node_id: u64,
        node_name: String,
        removed_children: usize,
    },
    
    /// System statistics
    Stats {
        stats: StatsInfo,
    },
    
    /// Success acknowledgement
    Success {
        message: String,
    },
    
    /// Error response
    Error {
        code: String,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
    
    /// Health/ping response
    Pong {
        timestamp: u64,
        version: String,
    },
}

// ========================
// Error Codes
// ========================

#[derive(Debug, Clone)]
pub enum ErrorCode {
    NodeNotFound,
    AccessDenied,
    InvalidRequest,
    NotADirectory,
    AlreadyExpanded,
    SystemError,
    NotImplemented,
    SearchUnavailable,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::NodeNotFound => "NODE_NOT_FOUND",
            ErrorCode::AccessDenied => "ACCESS_DENIED",
            ErrorCode::InvalidRequest => "INVALID_REQUEST",
            ErrorCode::NotADirectory => "NOT_A_DIRECTORY",
            ErrorCode::AlreadyExpanded => "ALREADY_EXPANDED",
            ErrorCode::SystemError => "SYSTEM_ERROR",
            ErrorCode::NotImplemented => "NOT_IMPLEMENTED",
            ErrorCode::SearchUnavailable => "SEARCH_UNAVAILABLE",
        }
    }
}

// ========================
// Helper Functions
// ========================

impl AgentResponse {
    pub fn error(code: ErrorCode, message: &str, details: Option<&str>) -> Self {
        AgentResponse::Error {
            code: code.as_str().to_string(),
            message: message.to_string(),
            details: details.map(|s| s.to_string()),
        }
    }
    
    pub fn success(message: &str) -> Self {
        AgentResponse::Success {
            message: message.to_string(),
        }
    }
}