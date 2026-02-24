// // web_filter_protection.rs
// // Phase 1: Web Content Filtering Foundation
// //
// // This module will implement system-wide proxy control, 
// // HTTPS inspection (MitM), and policy-based web filtering.
// //
// // Author: DLP Agent Team

// use crate::policy_engine::PolicyEngine;
// use crate::communication::ServerCommunicator;
// use crate::protection_modules::ProtectionModule;
// use crate::policy_constants::*;
// use log::info;
// use std::error::Error;
// use std::hash::Hash;
// use tokio::sync::Mutex;
// use std::sync::Arc;
// use std::process::Command;
// use std::collections::HashSet;

// #[derive(Default, Debug, Clone)]
// struct WebPolicyData {
//     monitor_enabled: bool,
//     upload_block: bool,
//     download_block: bool,
// }

// /// Web Content Filtering (Proxy Layer)
// pub struct WebFilterProtection {
//     last_policy_hash: u64,
//     proxy_enabled: bool,
//     trusted_cert_installed: bool,
//     monitored_urls: Arc<Mutex<HashSet<String>>>, // store visited URLs (for monitor mode)
// }

// impl WebFilterProtection {
//     pub fn new() -> Result<Self, Box<dyn Error>> {
//         info!("🌐 Initializing Web Content Filtering Module (Proxy Layer)...");
//         Ok(Self {
//             last_policy_hash: 0,
//             proxy_enabled: false,
//             trusted_cert_installed: false,
//             monitored_urls: Arc::new(Mutex::new(HashSet::new())),
//         })
//     }

//     /// Entry point: enforce active policies
//     async fn enforce_web_policy(&mut self, policy_engine: &PolicyEngine) -> Result<(), Box<dyn Error>> {
//         let monitor_active = policy_engine.is_policy_active(POLICY_WEB_MONITOR_HISTORY);
//         let upload_block = policy_engine.is_policy_active(POLICY_WEB_UPLOAD_BLOCK);
//         let download_block = policy_engine.is_policy_active(POLICY_WEB_DOWNLOAD_BLOCK);

//         let mut s = std::hash::DefaultHasher::new();
//         monitor_active.hash(&mut s);
//         upload_block.hash(&mut s);
//         download_block.hash(&mut s);
//         let new_hash = std::hash::Hasher::finish(&s);

//         if new_hash == self.last_policy_hash {
//             return Ok(());
//         }

//         info!("🌍 Detected new web policy configuration...");

//         // Ensure proxy foundation is ready
//         if !self.proxy_enabled {
//             self.enable_system_proxy()?;
//         }

//         // Ensure the local root certificate is trusted
//         if !self.trusted_cert_installed {
//             self.install_root_certificate()?;
//         }

//         // Apply behavior according to active policies
//         if monitor_active {
//             info!("👁️ Web Monitoring enabled (POLICY_WEB_MONITOR_HISTORY)");
//         }

//         if upload_block {
//             info!("🚫 Blocking file uploads (POLICY_WEB_UPLOAD_BLOCK)");
//         }

//         if download_block {
//             info!("🛑 Blocking file downloads (POLICY_WEB_DOWNLOAD_BLOCK)");
//         }

//         self.last_policy_hash = new_hash;
//         Ok(())
//     }

//     /// Enables system-wide proxy routing through local agent port (e.g., 127.0.0.1:8888)
//     fn enable_system_proxy(&mut self) -> Result<(), Box<dyn Error>> {
//         info!("🔧 Enabling Windows system proxy via registry...");
//         let output = Command::new("reg")
//             .args(&[
//                 "add",
//                 r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
//                 "/v",
//                 "ProxyEnable",
//                 "/t",
//                 "REG_DWORD",
//                 "/d",
//                 "1",
//                 "/f",
//             ])
//             .output()?;

//         if !output.status.success() {
//             return Err("Failed to enable system proxy".into());
//         }

//         // Set proxy address
//         let output = Command::new("reg")
//             .args(&[
//                 "add",
//                 r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
//                 "/v",
//                 "ProxyServer",
//                 "/t",
//                 "REG_SZ",
//                 "/d",
//                 "127.0.0.1:8888",
//                 "/f",
//             ])
//             .output()?;

//         if !output.status.success() {
//             return Err("Failed to configure proxy server".into());
//         }

//         self.proxy_enabled = true;
//         info!("✅ System proxy set to 127.0.0.1:8888");
//         Ok(())
//     }

//     /// Installs local Root CA certificate for HTTPS inspection (placeholder for real logic)
//     fn install_root_certificate(&mut self) -> Result<(), Box<dyn Error>> {
//         info!("🔐 Installing DLP Agent Root CA into Windows Trusted Root Store...");
//         // In the real phase 2, this will:
//         //  - Generate a CA certificate (self-signed)
//         //  - Import it using `certutil -addstore root dlp_root_ca.crt`
//         // For now, this is simulated
//         self.trusted_cert_installed = true;
//         Ok(())
//     }

//     /// Simulate HTTPS proxy packet inspection and enforce upload/download blocking
//     async fn inspect_http_traffic(&self, _url: &str, _method: &str) -> bool {
//         // This function will be expanded in phase 2:
//         // - Capture requests via proxy listener
//         // - Detect Content-Disposition headers
//         // - Block file uploads/downloads dynamically
//         true
//     }
// }

// #[async_trait::async_trait]
// impl ProtectionModule for WebFilterProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         _agent_id: u64,
//         _token: &str,
//     ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         // your existing logic...
//         if policy_engine.is_policy_active(POLICY_WEB_MONITOR_HISTORY)
//             || policy_engine.is_policy_active(POLICY_WEB_UPLOAD_BLOCK)
//             || policy_engine.is_policy_active(POLICY_WEB_DOWNLOAD_BLOCK)
//         {
//             self.enforce_web_policy(policy_engine).await;
//         } else {
//             if self.last_policy_hash != 0 {
//                 log::info!("🧹 Web content policy disabled. Cleaning up proxy settings...");
//                 self.last_policy_hash = 0;
//             }
//         }
//         Ok(())
//     }

//     fn get_name(&self) -> &str {
//         "WEB"
//     }
// }
