//! Query API Server - Safe, read-only API for Admin Server
//! Core Principle: Admin only sees IDs, Agent owns filesystem truth
use crate::protection_modules::file_protection::{filesystem_scanner::FileSystemScanner, query_interface::{QueryInterface, QueryResponse}};

// src/comms/api_server.rs
use super::protocol::{ AdminRequest, AgentResponse, ErrorCode, DriveInfo, NodeInfo, StatsInfo };
use std::sync::Arc;

/// Query API Server - processes Admin requests
pub struct QueryApiServer {
    scanner: Arc<FileSystemScanner>,
    query: Arc<QueryInterface>,
}

impl QueryApiServer {
    /// Create new API server
    pub fn new(scanner: Arc<FileSystemScanner>, query: Arc<QueryInterface>) -> Self {
        QueryApiServer { scanner, query }
    }

    /// Process Admin request and return Agent response - NOW ASYNC
    pub async fn handle_request(&self, request: AdminRequest) -> AgentResponse {
        match request {
            AdminRequest::GetDrives => self.handle_get_drives().await,
            AdminRequest::ListChildren { node_id } => self.handle_list_children(node_id).await,
            AdminRequest::GetNode { node_id } => self.handle_get_node(node_id).await,
            AdminRequest::SearchLocal { parent_id, query, limit } => {
                self.handle_search_local(parent_id, &query, limit).await
            }
            AdminRequest::ExpandNode { node_id } => self.handle_expand_node(node_id).await,
            AdminRequest::CollapseNode { node_id } => self.handle_collapse_node(node_id).await,
            AdminRequest::GetStats => self.handle_get_stats().await,
            AdminRequest::Ping => self.handle_ping().await,
        }
    }

    /// Handle: Get all drives - FIXED: No nested block_in_place
    async fn handle_get_drives(&self) -> AgentResponse {
        let query_clone = self.query.clone();

        // Run all blocking operations in a single spawn_blocking
        let result = tokio::task::spawn_blocking(move || {
            match query_clone.get_drives() {
                QueryResponse::Drives(drives) => {
                    let drive_infos: Vec<DriveInfo> = drives
                        .into_iter()
                        .map(|drive| {
                            // Get node info for has_children flag - inside same blocking context
                            let has_children = match query_clone.get_node(drive.node_id) {
                                QueryResponse::Node(node) => node.has_children,
                                _ => false,
                            };

                            DriveInfo {
                                id: drive.node_id,
                                name: drive.display_name,
                                drive_letter: drive.drive_letter,
                                has_children,
                                is_accessible: true, // Drives are always accessible if listed
                                node_type: "drive".to_string(),
                            }
                        })
                        .collect();

                    AgentResponse::Drives { drives: drive_infos }
                }
                QueryResponse::Error(e) => {
                    AgentResponse::error(ErrorCode::SystemError, &e, None)
                }
                _ =>
                    AgentResponse::error(
                        ErrorCode::SystemError,
                        "Unexpected response type from get_drives",
                        None
                    ),
            }
        }).await;

        match result {
            Ok(response) => response,
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: List children of a node
    async fn handle_list_children(&self, node_id: u64) -> AgentResponse {
        let query_clone = self.query.clone();

        // Run both operations in a single spawn_blocking
        let result = tokio::task::spawn_blocking(move || {
            // Get parent node info
            let parent_name = match query_clone.get_node(node_id) {
                QueryResponse::Node(node) => node.name.clone(),
                QueryResponse::Error(_) => {
                    return AgentResponse::error(
                        ErrorCode::NodeNotFound,
                        &format!("Node {} not found", node_id),
                        None
                    );
                }
                _ => {
                    return AgentResponse::error(
                        ErrorCode::SystemError,
                        "Invalid response for node lookup",
                        None
                    );
                }
            };

            // List children
            match query_clone.list_children(node_id) {
                QueryResponse::Nodes(nodes) => {
                    let child_infos: Vec<NodeInfo> = nodes
                        .into_iter()
                        .map(|node| {
                            NodeInfo {
                                id: node.id,
                                name: node.name,
                                node_type: node.entry_type.to_lowercase(),
                                size: node.size,
                                modified_time: node.modified_time,
                                created_time: node.created_time,
                                has_children: node.has_children,
                                is_expanded: node.is_expanded,
                                is_accessible: node.is_accessible,
                                full_path: Some(node.display_path.clone()),
                            }
                        })
                        .collect();

                    let child_count = child_infos.len();

                    AgentResponse::Children {
                        parent_id: node_id,
                        parent_name,
                        children: child_infos,
                        total_children: child_count,
                    }
                }
                QueryResponse::Error(e) => AgentResponse::error(ErrorCode::SystemError, &e, None),
                _ =>
                    AgentResponse::error(
                        ErrorCode::SystemError,
                        "Unexpected response type from list_children",
                        None
                    ),
            }
        }).await;

        match result {
            Ok(response) => response,
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Get specific node info
    async fn handle_get_node(&self, node_id: u64) -> AgentResponse {
        let query_clone = self.query.clone();
        let result = tokio::task::spawn_blocking(move || { query_clone.get_node(node_id) }).await;

        match result {
            Ok(QueryResponse::Node(node)) => {
                let node_info = NodeInfo {
                    id: node.id,
                    name: node.name,
                    node_type: node.entry_type.to_lowercase(),
                    size: node.size,
                    modified_time: node.modified_time,
                    created_time: node.created_time,
                    has_children: node.has_children,
                    is_expanded: node.is_expanded,
                    is_accessible: node.is_accessible,
                    full_path: Some(node.display_path.clone()),
                };

                AgentResponse::Node { node: node_info }
            }
            Ok(QueryResponse::Error(e)) => AgentResponse::error(ErrorCode::NodeNotFound, &e, None),
            Ok(_) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    "Unexpected response type from get_node",
                    None
                ),
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Search within expanded nodes only (LOCAL SEARCH)
    async fn handle_search_local(
        &self,
        parent_id: u64,
        query_str: &str,
        limit: Option<usize>
    ) -> AgentResponse {
        let query_clone = self.query.clone();
        let query_string = query_str.to_string();

        let result = tokio::task::spawn_blocking(move || {
            query_clone.search_local(parent_id, &query_string)
        }).await;

        match result {
            Ok(QueryResponse::Nodes(nodes)) => {
                // Apply limit if specified
                let limited_nodes = if let Some(limit) = limit {
                    nodes.into_iter().take(limit).collect::<Vec<_>>()
                } else {
                    nodes
                };

                let results: Vec<NodeInfo> = limited_nodes
                    .into_iter()
                    .map(|node| {
                        NodeInfo {
                            id: node.id,
                            name: node.name,
                            node_type: node.entry_type.to_lowercase(),
                            size: node.size,
                            modified_time: node.modified_time,
                            created_time: node.created_time,
                            has_children: node.has_children,
                            is_expanded: node.is_expanded,
                            is_accessible: node.is_accessible,
                            full_path: Some(node.display_path.clone())
                           
                        }
                    })
                    .collect();

                let total_matches = results.len();

                AgentResponse::SearchLocalResults {
                    parent_id,
                    query: query_str.to_string(),
                    results,
                    total_matches,
                    scope: "local".to_string(),
                }
            }
            Ok(QueryResponse::Error(e)) => AgentResponse::error(ErrorCode::SystemError, &e, None),
            Ok(_) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    "Unexpected response type during search",
                    None
                ),
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Expand a directory (load children) - FIXED: Check for already expanded
    // async fn handle_expand_node(&self, node_id: u64) -> AgentResponse {
    //     let scanner_clone = self.scanner.clone();
    //     let query_clone = self.query.clone();

    //     let result = tokio::task::spawn_blocking(move || {
    //         // Get node info first
    //         let node = match query_clone.get_node(node_id) {
    //             QueryResponse::Node(node) => {
    //                 // Check if it's a directory/drive
    //                 if node.entry_type != "directory" && node.entry_type != "drive" {
    //                     return AgentResponse::error(
    //                         ErrorCode::NotADirectory,
    //                         &format!("Node {} is not a directory", node_id),
    //                         None,
    //                     );
    //                 }

    //                 node
    //             }
    //             QueryResponse::Error(e) => {
    //                 return AgentResponse::error(ErrorCode::NodeNotFound, &e, None);
    //             }
    //             _ => {
    //                 return AgentResponse::error(
    //                     ErrorCode::SystemError,
    //                     "Invalid response for node lookup",
    //                     None,
    //                 );
    //             }
    //         };

    //         // Check if already expanded
    //         if node.is_expanded {
    //             return AgentResponse::error(
    //                 ErrorCode::AlreadyExpanded,
    //                 &format!("Node '{}' is already expanded", node.name),
    //                 None,
    //             );
    //         }

    //         // Expand directory
    //         match scanner_clone.expand_directory(node_id) {
    //             Ok(_new_children) => {
    //                 // Get children after expansion
    //                 match query_clone.list_children(node_id) {
    //                     QueryResponse::Nodes(children) => {
    //                         let child_infos: Vec<NodeInfo> = children.into_iter().map(|node| {
    //                             NodeInfo {
    //                                 id: node.id,
    //                                 name: node.name,
    //                                 node_type: node.entry_type.to_lowercase(),
    //                                 size: node.size,
    //                                 modified_time: node.modified_time,
    //                                 created_time: node.created_time,
    //                                 has_children: node.has_children,
    //                                 is_expanded: node.is_expanded,
    //                                 is_accessible: node.is_accessible,
    //                             }
    //                         }).collect();

    //                         let total_children = child_infos.len();

    //                         AgentResponse::Expanded {
    //                             node_id,
    //                             node_name: node.name.clone(),
    //                             children: child_infos,
    //                             total_children,
    //                         }
    //                     }
    //                     QueryResponse::Error(e) => AgentResponse::error(ErrorCode::SystemError, &e, None),
    //                     _ => AgentResponse::error(
    //                         ErrorCode::SystemError,
    //                         "Failed to get children after expansion",
    //                         None,
    //                     ),
    //                 }
    //             }
    //             Err(e) => AgentResponse::error(ErrorCode::SystemError, &e, None),
    //         }
    //     }).await;

    //     match result {
    //         Ok(response) => response,
    //         Err(e) => AgentResponse::error(
    //             ErrorCode::SystemError,
    //             &format!("Task execution failed: {}", e),
    //             None,
    //         ),
    //     }
    // }

    /// Handle: Expand a node (Drive or Directory)
    async fn handle_expand_node(&self, node_id: u64) -> AgentResponse {
        let scanner = self.scanner.clone();
        let query = self.query.clone();

        let result = tokio::task::spawn_blocking(move || {
            // 1️⃣ Get node info
            let node = match query.get_node(node_id) {
                QueryResponse::Node(node) => node,
                QueryResponse::Error(e) => {
                    return AgentResponse::error(ErrorCode::NodeNotFound, &e, None);
                }
                _ => {
                    return AgentResponse::error(
                        ErrorCode::SystemError,
                        "Invalid response for node lookup",
                        None
                    );
                }
            };

            // Normalize entry type
            let entry_type = node.entry_type.to_lowercase();

            // 2️⃣ Already expanded check
            if node.is_expanded {
                return AgentResponse::error(
                    ErrorCode::AlreadyExpanded,
                    &format!("Node '{}' is already expanded", node.name),
                    None
                );
            }

            // 3️⃣ Expand based on node type
            let expand_result = match entry_type.as_str() {
                "directory" => scanner.expand_directory(node_id),
                "drive" => scanner.expand_drive(node_id),
                _ => {
                    return AgentResponse::error(
                        ErrorCode::NotADirectory,
                        &format!("Node '{}' cannot be expanded", node.name),
                        None
                    );
                }
            };

            // 4️⃣ Handle expansion result
            match expand_result {
                Ok(_) => {
                    match query.list_children(node_id) {
                        QueryResponse::Nodes(children) => {
                            let child_infos: Vec<NodeInfo> = children
                                .into_iter()
                                .map(|child| NodeInfo {
                                    id: child.id,
                                    name: child.name,
                                    node_type: child.entry_type.to_lowercase(),
                                    size: child.size,
                                    modified_time: child.modified_time,
                                    created_time: child.created_time,
                                    has_children: child.has_children,
                                    is_expanded: child.is_expanded,
                                    is_accessible: child.is_accessible,
                                    full_path: Some(child.display_path.clone()), // ✅ FIXED
                                })
                                .collect();

                            // ✅ FIX: compute length BEFORE move
                            let total_children = child_infos.len();

                            AgentResponse::Expanded {
                                node_id,
                                node_name: node.name.clone(),
                                children: child_infos, // moved only once
                                total_children,
                            }
                        }
                        QueryResponse::Error(e) => {
                            AgentResponse::error(ErrorCode::SystemError, &e, None)
                        }
                        _ => {
                            AgentResponse::error(
                                ErrorCode::SystemError,
                                "Failed to list children after expansion",
                                None
                            )
                        }
                    }
                }
                Err(e) => { AgentResponse::error(ErrorCode::SystemError, &e, None) }
            }
        }).await;

        match result {
            Ok(response) => response,
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Collapse a directory (unload children)
    // async fn handle_collapse_node(&self, node_id: u64) -> AgentResponse {
    //     let scanner_clone = self.scanner.clone();
    //     let query_clone = self.query.clone();

    //     let result = tokio::task::spawn_blocking(move || {
    //         // Get node info first
    //         let node = match query_clone.get_node(node_id) {
    //             QueryResponse::Node(node) => {
    //                 // Check if it's a directory/drive
    //                 if node.entry_type != "directory" && node.entry_type != "drive" {
    //                     return AgentResponse::error(
    //                         ErrorCode::NotADirectory,
    //                         &format!("Node {} is not a directory", node_id),
    //                         None,
    //                     );
    //                 }
    //                 node
    //             }
    //             QueryResponse::Error(e) => {
    //                 return AgentResponse::error(ErrorCode::NodeNotFound, &e, None);
    //             }
    //             _ => {
    //                 return AgentResponse::error(
    //                     ErrorCode::SystemError,
    //                     "Invalid response for node lookup",
    //                     None,
    //                 );
    //             }
    //         };

    //         // Collapse directory
    //         match scanner_clone.collapse_directory(node_id) {
    //             Ok(removed_children) => {
    //                 AgentResponse::Collapsed {
    //                     node_id,
    //                     node_name: node.name.clone(),
    //                     removed_children,
    //                 }
    //             }
    //             Err(e) => AgentResponse::error(ErrorCode::SystemError, &e, None),
    //         }
    //     }).await;

    //     match result {
    //         Ok(response) => response,
    //         Err(e) => AgentResponse::error(
    //             ErrorCode::SystemError,
    //             &format!("Task execution failed: {}", e),
    //             None,
    //         ),
    //     }
    // }
    async fn handle_collapse_node(&self, node_id: u64) -> AgentResponse {
        let scanner = self.scanner.clone();
        let query = self.query.clone();

        let result = tokio::task::spawn_blocking(move || {
            let node = match query.get_node(node_id) {
                QueryResponse::Node(node) => node,
                QueryResponse::Error(e) => {
                    return AgentResponse::error(ErrorCode::NodeNotFound, &e, None);
                }
                _ => {
                    return AgentResponse::error(
                        ErrorCode::SystemError,
                        "Invalid response for node lookup",
                        None
                    );
                }
            };

            let entry_type = node.entry_type.to_lowercase();

            let collapse_result = match entry_type.as_str() {
                "directory" => scanner.collapse_directory(node_id),
                "drive" => scanner.collapse_drive(node_id), // 🔥 THIS WAS MISSING
                _ => {
                    return AgentResponse::error(
                        ErrorCode::NotADirectory,
                        &format!("Node '{}' cannot be collapsed", node.name),
                        None
                    );
                }
            };

            match collapse_result {
                Ok(removed_children) => {
                    AgentResponse::Collapsed {
                        node_id,
                        node_name: node.name,
                        removed_children,
                    }
                }
                Err(e) => AgentResponse::error(ErrorCode::SystemError, &e, None),
            }
        }).await;

        match result {
            Ok(response) => response,
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Get system statistics
    async fn handle_get_stats(&self) -> AgentResponse {
        let query_clone = self.query.clone();
        let result = tokio::task::spawn_blocking(move || { query_clone.get_stats() }).await;

        match result {
            Ok(QueryResponse::Stats(stats)) => {
                let stats_info = StatsInfo {
                    total_nodes: stats.total_nodes,
                    total_drives: stats.total_drives,
                    expanded_nodes: stats.expanded_nodes,
                    memory_usage_bytes: stats.memory_usage_bytes,
                    scan_state: stats.scan_state.as_str().to_string(),
                };

                AgentResponse::Stats { stats: stats_info }
            }
            Ok(QueryResponse::Error(e)) => AgentResponse::error(ErrorCode::SystemError, &e, None),
            Ok(_) =>
                AgentResponse::error(ErrorCode::SystemError, "Could not retrieve statistics", None),
            Err(e) =>
                AgentResponse::error(
                    ErrorCode::SystemError,
                    &format!("Task execution failed: {}", e),
                    None
                ),
        }
    }

    /// Handle: Ping/health check
    async fn handle_ping(&self) -> AgentResponse {
        AgentResponse::Pong {
            timestamp: std::time::SystemTime
                ::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
