// // src/protection_modules/web_filter_phase3.rs
// use crate::protection_modules::mitm_proxy::MitmProxy;
// use crate::protection_modules::ca_manager::CaManager;
// use crate::policy_engine::PolicyEngine;
// use crate::communication::ServerCommunicator;
// use crate::protection_modules::ProtectionModule;
// use crate::policy_constants::*;
// use async_trait::async_trait;
// use std::sync::Arc;
// use tokio::sync::RwLock;
// use log::{info, error};

// pub struct WebFilterProtection {
//     mitm_handle: Option<tokio::task::JoinHandle<()>>,
//     ca: Arc<CaManager>,
//     policy: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<ServerCommunicator>,
//     proxy_addr: String,
// }

// impl WebFilterProtection {
//     /// Note: return error type requires Send + Sync so futures spawned with tokio::spawn are Send.
//     pub fn new(
//         persist_dir: &str,
//         policy: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<ServerCommunicator>,
//         proxy_addr: &str,
//     ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
//         let ca = CaManager::new_or_load(persist_dir)?;
//         Ok(Self {
//             mitm_handle: None,
//             ca,
//             policy,
//             communicator,
//             proxy_addr: proxy_addr.to_string(),
//         })
//     }

//     fn start_proxy(&mut self) {
//         // clone Arc handles into the spawned task
//         let ca = self.ca.clone();
//         let policy = self.policy.clone();
//         let communicator = self.communicator.clone();
//         let addr = self.proxy_addr.clone();
//         // keep a local clone for move into async
//         let addr_clone = addr.clone();

//         // spawn a Send + 'static future
//         let handle = tokio::spawn(async move {
//             // MitmProxy::new in your codebase is synchronous (returns Result<MitmProxy, _>),
//             // call it here and then run() which is async.
//             match MitmProxy::new(&addr_clone, ca, policy, communicator) {
//                 Ok(proxy) => {
//                     if let Err(e) = proxy.run().await {
//                         error!("MITM proxy failed: {}", e);
//                     }
//                 }
//                 Err(e) => {
//                     error!("Failed to create MITM proxy: {}", e);
//                 }
//             }
//         });

//         self.mitm_handle = Some(handle);
//     }

//     fn stop_proxy(&mut self) {
//         // graceful shutdown TBD: we can signal via an atomic or channel in future.
//         if let Some(h) = self.mitm_handle.take() {
//             h.abort();
//         }
//     }
// }

// #[async_trait]
// impl ProtectionModule for WebFilterProtection {
//     // Use Send + Sync on the boxed error here as well to keep consistency/safety for spawned futures.
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &crate::communication::ServerCommunicator,
//         _agent_id: u64,
//         _token: &str,
//     ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         // Decide whether to run proxy based on is_web_protection_enabled
//         let enabled = policy_engine.is_policy_active(POLICY_WEB_MONITOR_HISTORY)
//             || policy_engine.is_policy_active(POLICY_WEB_UPLOAD_BLOCK)
//             || policy_engine.is_policy_active(POLICY_WEB_DOWNLOAD_BLOCK);

//         if enabled && self.mitm_handle.is_none() {
//             info!("Starting WebFilter MITM proxy...");
//             self.start_proxy();
//         } else if !enabled && self.mitm_handle.is_some() {
//             info!("Stopping WebFilter MITM proxy...");
//             self.stop_proxy();
//         }
//         Ok(())
//     }

//     fn get_name(&self) -> &str {
//         "WEB"
//     }
// }
